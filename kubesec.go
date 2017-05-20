package main

import (
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
		subCommand = flag.Args()[1]
	}
	switch subCommand {
	case "ca":
		createCA(flag.Args()[2:], "ca", "/CN=ca", time.Hour*24*(10*365+5))
	case "ica":
		createCA(flag.Args()[2:], "ca/ica", "/CN=ica", time.Hour*24*(5*365+5))
	case "server":
		createCertificate(flag.Args()[2:], "ca/server", "/CN=server", time.Hour*24*(365+5),
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	case "client":
		createCertificate(flag.Args()[2:], "ca/client", "/CN=client", time.Hour*24*(365+5),
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	case "peer":
		createCertificate(flag.Args()[2:], "ca/peer", "/CN=peer", time.Hour*24*(365+5),
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	case "signature":
		createCertificate(flag.Args()[2:], "ca/sign", "/CN=sign", time.Hour*24*(365+5),
			x509.KeyUsageDigitalSignature, nil)
	case "export":
		exportCertificate(flag.Args()[2:])
	case "kubernetes":
		createKubernetes(flag.Args()[2:])
	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
	}
}

func createCertificate(args []string, path string, defaultDN string, defaultValidity time.Duration, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) {

}

func createCA(args []string, path string, defaultDN string, defaultValidity time.Duration) {
	fs := flag.NewFlagSet("command", flag.PanicOnError)
	dn := fs.String("dn", defaultDN, "certificate subject")
	maxPathLength := fs.Int("maxPathLength", 0, "max path length")
	validity := fs.Duration("validity", defaultValidity, "certificate duration")

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
			MaxPathLenZero:        !(*maxPathLength > 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(*validity),
			SerialNumber:          generateSerial(),
		},
	}
	if filepath.Dir(path) == "." {
		manifest.signingCert = manifest.cert
		manifest.signingKey = manifest.key
		manifest.cert.Subject = parseDN(pkix.Name{}, *dn)
	} else {
		file := filepath.Dir(path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.signingCert = readCert(file + ".pem")
		manifest.signingKey = readKey(file + "-key.pem")
		manifest.cert.Subject = parseDN(manifest.signingCert.Subject, *dn)
	}

	// manifest.parseSAN(sans)
	manifest.sign()
	manifest.save()
}
