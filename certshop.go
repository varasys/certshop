package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	infoLog   = log.New(os.Stderr, "", 0)
	debugLog  = log.New(ioutil.Discard, "", 0)
	errorLog  = log.New(os.Stderr, "ERROR: ", log.Lshortfile)
	root      string
	overwrite bool
	runTime   time.Time
)

func main() {
	runTime = time.Now().UTC()
	flag.StringVar(&root, "root", "./", "path to root directory (default=\"./\")")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite existing directories (default=false)")
	debug := flag.Bool("debug", false, "show extra debug information (default=false)")
	flag.Parse()

	if *debug {
		debugLog = log.New(os.Stderr, "", 0)
	}
	if absRoot, err := filepath.Abs(root); err != nil {
		errorLog.Fatalf("Failed to parse root directory %s: %s", root, err)
	} else {
		root = absRoot
	}
	debugLog.Printf("Using root directory: %s", root)
	if err := os.MkdirAll(root, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create root directory %s: %s", root, err)
	}
	if err := os.Chdir(root); err != nil {
		errorLog.Fatalf("Failed to set root directory to %s: %s", root, err)
	}

	var subCommand string
	if len(flag.Args()) < 1 {
		subCommand = "help"
	} else {
		subCommand = flag.Args()[0]
	}
	switch subCommand {
	case "ca":
		manifest := createCA(flag.Args()[1:], "ca", "/CN=ca", 10*(365+5))
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ca in %s\n", filepath.Join(root, manifest.path))
	case "ica":
		manifest := createCA(flag.Args()[1:], "ca/ica", "/CN=ica", 5*(365+5))
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ica in %s\n", filepath.Join(root, manifest.path))
	case "server":
		manifest := createCertificate(flag.Args()[1:], "ca/server", "/CN=server", "127.0.0.1,localhost,::1", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating server in %s\n", filepath.Join(root, manifest.path))
	case "client":
		manifest := createCertificate(flag.Args()[1:], "ca/client", "/CN=client", "127.0.0.1,localhost,::1", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating client in %s\n", filepath.Join(root, manifest.path))
	case "peer":
		manifest := createCertificate(flag.Args()[1:], "ca/peer", "/CN=peer", "127.0.0.1,localhost,::1", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating peer in %s\n", filepath.Join(root, manifest.path))
	case "signature":
		manifest := createCertificate(flag.Args()[1:], "ca/sign", "/CN=sign", "127.0.0.1,localhost,::1", 365+5,
			x509.KeyUsageDigitalSignature, nil)
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating signature cert in %s\n", filepath.Join(root, manifest.path))
	case "csr":
		manifest := createCSR(flag.Args()[1:])
		if manifest.path != "" {
			manifest.save(newFileWriter())
		} else {
			writer := newTgzWriter(os.Stdout)
			defer writer.close()
			manifest.save(writer)
		}
		infoLog.Printf("Finished creating certificate signing request")
	case "export":
		exportCertificate(flag.Args()[1:])
	case "kubernetes":
		createKubernetes(flag.Args()[1:])
	default:
		debugLog.Println("Usage: certshop ca | ica | server | client | signature | export")
	}
}

func createCertificate(args []string, path, defaultDN, defaultSAN string, defaultValidity int, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) *certManifest {
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", defaultDN, "certificate subject")
	san := fs.String("san", defaultSAN, "subject alternative names")
	validity := fs.Int("validity", defaultValidity, "certificate duration in days")

	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = filepath.Clean(fs.Arg(0))
	}
	debugLog.Printf("Creating Certificate %s with Subject: %s\n", path, *dn)
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("Error: directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
		}
	}
	if err := os.MkdirAll(path, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create directory %s: %s", path, err)
	}
	sans := parseSANs(*san)
	manifest := certManifest{
		path:       path,
		PrivateKey: generateKey(),
		Certificate: &x509.Certificate{
			IsCA:           false,
			KeyUsage:       usage,
			ExtKeyUsage:    extUsage,
			NotBefore:      runTime,
			NotAfter:       runTime.Add(time.Duration(*validity*24) * time.Hour),
			SerialNumber:   generateSerial(),
			IPAddresses:    sans.ip,
			EmailAddresses: sans.email,
			DNSNames:       sans.dns,
		},
	}
	if id, err := x509.MarshalPKIXPublicKey(manifest.Public()); err != nil {
		errorLog.Fatalf("Error marshaling public key")
	} else {
		hash := sha1.Sum(id)
		manifest.SubjectKeyId = hash[:]
	}
	manifest.loadCertChain(true)
	manifest.Subject = parseDN(manifest.ca.Subject, *dn)
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	manifest.sign()
	return &manifest
}

func createCA(args []string, path string, defaultDN string, defaultValidity int) *certManifest {
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", defaultDN, "certificate subject")
	maxPathLength := fs.Int("maxPathLength", 0, "max path length")
	validity := fs.Int("validity", defaultValidity, "certificate duration in days")

	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = filepath.Clean(fs.Arg(0))
	}
	debugLog.Printf("Creating Certificate Authority %s with Subject: %s\n", path, *dn)
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("Error: directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
		}
	}
	if err := os.MkdirAll(path, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create directory %s: %s", path, err)
	}
	manifest := certManifest{
		path:       path,
		PrivateKey: generateKey(),
		Certificate: &x509.Certificate{
			IsCA: true,
			BasicConstraintsValid: true,
			MaxPathLen:            *maxPathLength,
			MaxPathLenZero:        *maxPathLength == 0,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			NotBefore:             runTime,
			NotAfter:              runTime.Add(time.Duration(*validity*24) * time.Hour),
			SerialNumber:          generateSerial(),
		},
	}
	if id, err := x509.MarshalPKIXPublicKey(manifest.Public()); err != nil {
		errorLog.Fatalf("Error marshaling public key")
	} else {
		hash := sha1.Sum(id)
		manifest.SubjectKeyId = hash[:]
	}
	if filepath.Dir(path) == "." { // self signed cert
		manifest.ca = &certManifest{
			path:        ".",
			Certificate: manifest.Certificate,
			PrivateKey:  manifest.PrivateKey,
		}
		manifest.Subject = parseDN(pkix.Name{}, *dn)
	} else {
		manifest.loadCertChain(true)
		if manifest.ca.MaxPathLen < 1 || manifest.MaxPathLen > (manifest.ca.MaxPathLen-1) {
			errorLog.Fatalf("Max Path Length of ca exceeded")
		}
		manifest.Subject = parseDN(manifest.ca.Subject, *dn)
	}
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	manifest.sign()
	return &manifest
}

func createCSR(args []string) *csrManifest {
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", "", "certificate subject (required)")
	san := fs.String("san", "", "subject alternative names")
	password := fs.String("password", "", "private key password (default=\"\")")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if *dn == "" {
		errorLog.Fatalf("Error: Distinguished Name required (ie. -dn=\"/CN=ACME\")")
	}
	var path string
	switch len(fs.Args()) {
	case 0:
		path = ""
	case 1:
		path = fs.Args()[0]
	default:
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	}
	sans := *parseSANs(*san)
	key := generateKey()
	manifest := csrManifest{
		path:       path,
		PrivateKey: key,
		password:   *password,
		CertificateRequest: &x509.CertificateRequest{
			Subject:            parseDN(pkix.Name{}, *dn),
			SignatureAlgorithm: x509.ECDSAWithSHA384,
			PublicKeyAlgorithm: x509.ECDSA,
			PublicKey:          key.Public(),
			DNSNames:           sans.dns,
			EmailAddresses:     sans.email,
			IPAddresses:        sans.ip,
		},
	}
	if der, err := x509.CreateCertificateRequest(rand.Reader, manifest.CertificateRequest, manifest.PrivateKey); err != nil {
		errorLog.Fatalf("Failed to sign certificate signing request: %s", err)
	} else {
		manifest.CertificateRequest.Raw = der
	}
	return &manifest
}
