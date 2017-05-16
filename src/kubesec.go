package kubesec

import (
	"crypto/x509"
	"flag"
	"log"
	"math/big"
	"os"
)

var (
	infoLog  = log.New(os.Stderr, "", 0)
	errorLog = log.New(os.Stderr, "ERROR: ", log.Lshortfile)

	serialNumberLimit             = new(big.Int).Lsh(big.NewInt(1), 128)
	privatePerms      os.FileMode = 0600
	publicPerms       os.FileMode = 0644
	root              string
	overwrite         boolean
)

func kubesec() {
	flag.StringVar(&root, "root", "./", "path to root directory (default=./)")
	create := flag.Bool("create", false, "create root directory if it doesn't exist (default=false)")
	flag.Parse()

	if *create {
		err := os.MkdirAll(root, publicPerms)
		if err != nil {
			errorLog.Fatalf("Failed to create rood dir %s: %s", root, err)
		}
	}

	var command string
	if len(flag.Args()) < 1 {
		command = "help"
	} else {
		command = flag.Args()[1]
	}
	switch command {
	case "ca":
		createCA(flag.Args()[2:], "ca", "/CN=certstore-ca", 10*365+5)
	case "ica":
		createCA(flag.Args()[2:], "ca/ica", "/CN=certstore-ica", 5*365+5)
	case "server":
		createCertificate(flag.Args()[2:], "ca/server", "/CN=server", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	case "client":
		createCertificate(flag.Args()[2:], "ca/client", "/CN=client", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	case "peer":
		createCertificate(flag.Args()[2:], "ca/peer", "/CN=peer", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	case "signature":
		createCertificate(flag.Args()[2:], "ca/sign", "/CN=sign", 365+5,
			x509.KeyUsageDigitalSignature, nil)
	case "export":
		exportCertificate(flag.Args()[2:])
	case "kubernetes":
		createKubernetes(flag.Args()[2:])
	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
	}
}
