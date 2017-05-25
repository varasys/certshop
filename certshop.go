package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	Version   string
	Build     string
	infoLog   = log.New(os.Stderr, "", 0)
	debugLog  = log.New(ioutil.Discard, "", 0)
	errorLog  = log.New(os.Stderr, "Error: ", 0)
	root      string
	overwrite bool
	runTime   time.Time
)

func main() {
	runTime = time.Now().UTC()
	flag.StringVar(&root, "root", "./", "path to root directory (default=\"./\")")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite existing directories (default=false)")
	version := flag.Bool("version", false, "print version and exit")
	debug := flag.Bool("debug", false, "show extra debug information (default=false)")
	flag.Parse()

	if *version {
		infoLog.Printf("certshop %s\nBuilt: %s\nCopyright (C) 2017 VARASYS Limited", Version, Build)
		os.Exit(0)
	}
	if *debug {
		debugLog = log.New(os.Stderr, "", log.Lshortfile)
		errorLog.SetFlags(log.Lshortfile)
	}
	if absRoot, err := filepath.Abs(root); err != nil {
		errorLog.Fatalf("Failed to parse root path %s: %s", root, err)
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
		flag.PrintDefaults()
	}
}

func createCA(args []string, path, defaultDN string, defaultValidity int) *certManifest {
	debugLog.Printf("Creating Certificate Authority %s\n", path)
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", defaultDN, "certificate subject")
	maxPathLength := fs.Int("maxPathLength", 0, "max path length")
	validity := fs.Int("validity", defaultValidity, "certificate duration in days")
	subjectPass := &password{}
	fs.Var(subjectPass, "subjectPass", "subject private key password")
	issuerPass := &password{}
	fs.Var(issuerPass, "issuerPass", "issuer private key password")
	csrFile := fs.String("csrFile", "", "certificate signing request file")

	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = filepath.Clean(fs.Arg(0))
	}
	if filepath.Dir(path) == "." && *csrFile != "" {
		errorLog.Fatalf("Failed to create certificate authority: certificate signing requests can't be used for root certificate authorities")
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("Directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
		}
	}
	manifest := certManifest{
		path: path,
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
	if *csrFile != "" {
		csr := readCSR(*csrFile)
		manifest.publicKey = csr.PublicKey.(*ecdsa.PublicKey)
		manifest.Subject = csr.Subject
	} else {
		manifest.privateKey = &privateKey{generateKey(), subjectPass}
		manifest.publicKey = manifest.privateKey.Public().(*ecdsa.PublicKey)
	}
	manifest.SubjectKeyId = *hashPublicKey(manifest.publicKey)
	if filepath.Dir(path) == "." { // self signed cert
		manifest.ca = &certManifest{
			path:        ".",
			Certificate: manifest.Certificate,
			privateKey:  manifest.privateKey,
		}
		manifest.Subject = *parseDN(pkix.Name{}, dn)
	} else {
		manifest.loadCACert()
		keyFile := filepath.Dir(path)
		keyFile = filepath.Join(keyFile, filepath.Base(keyFile)+"-key.pem")
		manifest.ca.privateKey = readKey(keyFile, issuerPass)
		if manifest.ca.MaxPathLen < 1 || manifest.MaxPathLen > (manifest.ca.MaxPathLen-1) {
			errorLog.Fatalf("Maximum Path Length of certificate authority exceeded")
		}
		manifest.Subject = *parseDN(manifest.ca.Subject, dn)
	}
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	manifest.sign()
	return &manifest
}

func createCertificate(args []string, path, defaultDN, defaultSAN string, defaultValidity int, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) *certManifest {
	debugLog.Printf("Creating Certificate %s\n", path)
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", defaultDN, "certificate subject")
	validity := fs.Int("validity", defaultValidity, "certificate duration in days")
	subjectPass := &password{}
	fs.Var(subjectPass, "subjectPass", "subject private key password")
	issuerPass := &password{}
	fs.Var(issuerPass, "issuerPass", "issuer private key password")
	csrFile := fs.String("csrFile", "", "certificate signing request file")
	sans := &sanList{}
	fs.Var(sans, "san", "comma seperated list of subject alternative names")

	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = filepath.Clean(fs.Arg(0))
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("Directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
		}
	}
	manifest := certManifest{
		path: path,
		Certificate: &x509.Certificate{
			IsCA:         false,
			KeyUsage:     usage,
			ExtKeyUsage:  extUsage,
			NotBefore:    runTime,
			NotAfter:     runTime.Add(time.Duration(*validity*24) * time.Hour),
			SerialNumber: generateSerial(),
		},
	}
	manifest.loadCACert()
	if *csrFile != "" {
		csr := readCSR(*csrFile)
		manifest.publicKey = csr.PublicKey.(*ecdsa.PublicKey)
		manifest.Subject = csr.Subject
		manifest.IPAddresses = csr.IPAddresses
		manifest.EmailAddresses = csr.EmailAddresses
		manifest.DNSNames = csr.DNSNames
	} else {
		if sans.sans == nil {
			_ = sans.Set(defaultSAN)
		}
		manifest.privateKey = &privateKey{generateKey(), subjectPass}
		manifest.publicKey = manifest.privateKey.Public().(*ecdsa.PublicKey)
		manifest.Subject = *parseDN(manifest.ca.Subject, dn)
		manifest.IPAddresses = sans.ip
		manifest.EmailAddresses = sans.email
		manifest.DNSNames = sans.dns
	}
	manifest.SubjectKeyId = *hashPublicKey(manifest.publicKey)
	keyFile := filepath.Dir(path)
	keyFile = filepath.Join(keyFile, filepath.Base(keyFile)+"-key.pem")
	manifest.ca.privateKey = readKey(keyFile, issuerPass)
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	manifest.sign()
	return &manifest
}

func createCSR(args []string) *csrManifest {
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", "", "certificate subject (required)")
	keyFile := fs.String("keyFile", "", "private key file (optional)")
	keyPass := &password{}
	fs.Var(keyPass, "keyPass", "private key password")
	sans := &sanList{}
	fs.Var(sans, "sans", "comma seperated list of subject alternative names")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}
	if *dn == "" {
		errorLog.Fatalf("Distinguished Name required (ie. -dn=\"/CN=ACME\")")
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
	var key *privateKey
	if *keyFile == "" {
		key = &privateKey{generateKey(), keyPass}
	} else {
		key = readKey(*keyFile, keyPass)
	}
	manifest := csrManifest{
		path:       path,
		privateKey: key,
		CertificateRequest: &x509.CertificateRequest{
			Subject:            *parseDN(pkix.Name{}, dn),
			SignatureAlgorithm: x509.ECDSAWithSHA384,
			PublicKeyAlgorithm: x509.ECDSA,
			PublicKey:          key.PrivateKey.Public(),
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

func hashPublicKey(key *ecdsa.PublicKey) *[]byte {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		errorLog.Fatalf("Failed to marshal public key")
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		errorLog.Fatalf("Failed to unmarshal public key asn.1 bitstring")
	}
	hash := sha1.Sum(publicKeyInfo.PublicKey.RightAlign())
	slice := hash[:]
	return &slice
}
