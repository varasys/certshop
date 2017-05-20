package main

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	infoLog   = log.New(os.Stderr, "", 0)
	errorLog  = log.New(os.Stderr, "ERROR: ", log.Lshortfile)
	root      string
	overwrite bool
)

func main() {
	flag.StringVar(&root, "root", "./", "path to root directory (default=\"./\")")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite existing directories (default=false)")
	flag.Parse()

	if absRoot, err := filepath.Abs(root); err != nil {
		errorLog.Fatalf("Failed to parse root directory %s: %s", root, err)
	} else {
		root = absRoot
	}
	infoLog.Printf("Using root directory: %s", root)
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
		createCA(flag.Args()[1:], "ca", "/CN=ca", 10*365+5)
	case "ica":
		createCA(flag.Args()[1:], "ca/ica", "/CN=ica", 5*365+5)
	case "server":
		createCertificate(flag.Args()[1:], "ca/server", "/CN=server", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	case "client":
		createCertificate(flag.Args()[1:], "ca/client", "/CN=client", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	case "peer":
		createCertificate(flag.Args()[1:], "ca/peer", "/CN=peer", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	case "signature":
		createCertificate(flag.Args()[1:], "ca/sign", "/CN=sign", 365+5,
			x509.KeyUsageDigitalSignature, nil)
	case "export":
		exportCertificate(flag.Args()[1:])
	case "kubernetes":
		createKubernetes(flag.Args()[1:])
	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
	}
}

func createCertificate(args []string, path string, defaultDN string, defaultValidity int, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) {

}

func createCA(args []string, path string, defaultDN string, defaultValidity int) {
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
	infoLog.Printf("Creating Certificate Authority %s with Subject: %s\n", path, *dn)
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			errorLog.Fatalf("Error: directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
		}
	}
	if err := os.MkdirAll(path, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create directory %s: %s", path, err)
	}
	notBefore := time.Now().UTC()
	manifest := certManifest{
		path: path,
		key:  generateKey(),
		cert: &x509.Certificate{
			IsCA: true,
			BasicConstraintsValid: true,
			MaxPathLen:            *maxPathLength,
			MaxPathLenZero:        *maxPathLength == 0,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(time.Duration(*validity*24) * time.Hour),
			SerialNumber:          generateSerial(),
		},
	}
	if id, err := x509.MarshalPKIXPublicKey(manifest.key.Public()); err != nil {
		errorLog.Fatalf("Error marshaling public key")
	} else {
		hash := sha1.Sum(id)
		manifest.cert.SubjectKeyId = hash[:]
	}
	if filepath.Dir(path) == "." { // self signed cert
		manifest.ca = &certManifest{
			path: ".",
			cert: manifest.cert,
			key:  manifest.key,
		}
		manifest.cert.Subject = parseDN(pkix.Name{}, *dn)
	} else {
		manifest.loadCertChain(true)
		if manifest.ca.cert.MaxPathLen < 1 || manifest.cert.MaxPathLen > (manifest.ca.cert.MaxPathLen-1) {
			errorLog.Fatalf("Max Path Length of ca exceeded")
		}
		manifest.cert.Subject = parseDN(manifest.ca.cert.Subject, *dn)
	}
	manifest.cert.AuthorityKeyId = manifest.ca.cert.SubjectKeyId

	// manifest.parseSAN(sans)
	manifest.sign()
	manifest.save()
}
