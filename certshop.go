package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// Version is populated using "-ldflags -X `git describe --tags`" build option
	// build using the Makefile to inject this value
	Version string
	// Build is populated using "-ldflags -X `date +%FT%T%z`" build option
	// build using the Makefile to inject this value
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
	fs := parseMainFlags(os.Args[1:], ".", false, false)
	if fs.version {
		infoLog.Printf("certshop %s\nBuilt: %s\nCopyright (C) 2017 Varasys Limited", Version, Build)
		os.Exit(0)
	}
	if fs.debug {
		debugLog = log.New(os.Stderr, "", log.Lshortfile)
		errorLog.SetFlags(log.Lshortfile)
	}
	debugLog.Printf("Using root directory: %s", fs.root)
	if err := os.MkdirAll(fs.root, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create root directory %s: %s", fs.root, err)
	}
	if err := os.Chdir(fs.root); err != nil {
		errorLog.Fatalf("Failed to set root directory to %s: %s", fs.root, err)
	}
	switch fs.command {
	case "ca":
		flags := parseCertFlags(fs.args, true, "", "", 0, 10*(365+5))
		manifest := createCA(flags)
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ca in %s\n", filepath.Join(root, flags.path))
	case "ica":
		flags := parseCertFlags(fs.args, true, "", "", 0, 5*(365+5))
		manifest := createCA(flags)
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ica in %s\n", filepath.Join(root, flags.path))
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
		flags := parseCSRFlags(fs.args, "", "")
		manifest := createCSR(&flags)
		writer := newTgzWriter(os.Stdout)
		defer writer.close()
		manifest.save(writer)
		infoLog.Printf("Finished creating certificate signing request")
	case "export":
		exportCertificate(flag.Args()[1:])
	case "kubernetes":
		createKubernetes(flag.Args()[1:])
	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
		fs.PrintDefaults()
	}
}

func createCA(flags *certFlags) certManifest {
	debugLog.Printf("Creating Certificate Authority %s\n", flags.path)
	if filepath.Dir(flags.path) == "." && flags.csr {
		errorLog.Fatalf("Failed to create certificate authority: certificate signing requests can't be used for root certificate authorities")
	}
	if !overwrite {
		if _, err := os.Stat(flags.path); err == nil {
			errorLog.Fatalf("Directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, flags.path))
		}
	}
	manifest := certManifest{
		path: flags.path,
		Certificate: &x509.Certificate{
			KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			NotBefore:    runTime,
			NotAfter:     runTime.Add(time.Duration(flags.validity*24) * time.Hour),
			SerialNumber: generateSerial(),
		},
	}
	if flags.isCA {
		manifest.IsCA = true
		manifest.BasicConstraintsValid = true
		manifest.MaxPathLen = flags.ica
		manifest.MaxPathLenZero = flags.ica == 0
	}
	if flags.csr {
		reader := bufio.NewReader(os.Stdin)
		data := []byte{}
		if n, err := reader.Read(data); n <= 0 || err != io.EOF {
			errorLog.Fatalf("Failed to read csr from stdin: %s", err)
		}
		csr := unMarshalCSR(&data)
		manifest.publicKey = csr.PublicKey.(*ecdsa.PublicKey)
		manifest.Subject = csr.Subject
	} else {
		manifest.privateKey = &privateKey{generateKey(), &flags.subjectpass}
		manifest.publicKey = manifest.privateKey.Public().(*ecdsa.PublicKey)
	}
	manifest.SubjectKeyId = *hashPublicKey(manifest.publicKey)
	if filepath.Dir(flags.path) == "." { // self signed cert
		manifest.ca = &certManifest{
			path:        ".",
			Certificate: manifest.Certificate,
			privateKey:  manifest.privateKey,
		}
		manifest.Subject = flags.dn.parseDN(pkix.Name{})
	} else {
		manifest.loadCACert()
		keyFile := filepath.Dir(flags.path)
		keyFile = filepath.Join(keyFile, filepath.Base(keyFile)+"-key.pem")
		manifest.ca.privateKey = readKey(keyFile, &flags.issuerpass)
		if manifest.ca.MaxPathLen < 1 || manifest.MaxPathLen > (manifest.ca.MaxPathLen-1) {
			errorLog.Fatalf("Maximum Path Length of certificate authority exceeded")
		}
		manifest.Subject = flags.dn.parseDN(manifest.ca.Subject)
	}
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	manifest.sign()
	return manifest
}

func createCertificate(args []string, path, defaultDN, defaultSAN string, defaultValidity int, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) *certManifest {
	// debugLog.Printf("Creating Certificate %s\n", path)
	// fs := flag.NewFlagSet("command", flag.PanicOnError)
	// dn := fs.String("dn", defaultDN, "certificate subject")
	// validity := fs.Int("validity", defaultValidity, "certificate duration in days")
	// subjectPass := &password{}
	// fs.Var(subjectPass, "subjectPass", "subject private key password")
	// issuerPass := &password{}
	// fs.Var(issuerPass, "issuerPass", "issuer private key password")
	// csrFile := fs.String("csrFile", "", "certificate signing request file")
	// sans := &sanList{}
	// fs.Var(sans, "san", "comma seperated list of subject alternative names")

	// if err := fs.Parse(args); err != nil {
	// 	errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	// }
	// if len(fs.Args()) > 1 {
	// 	errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	// } else if len(fs.Args()) == 1 {
	// 	path = filepath.Clean(fs.Arg(0))
	// }
	// if !overwrite {
	// 	if _, err := os.Stat(path); err == nil {
	// 		errorLog.Fatalf("Directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, path))
	// 	}
	// }
	// manifest := certManifest{
	// 	path: path,
	// 	Certificate: &x509.Certificate{
	// 		IsCA:         false,
	// 		KeyUsage:     usage,
	// 		ExtKeyUsage:  extUsage,
	// 		NotBefore:    runTime,
	// 		NotAfter:     runTime.Add(time.Duration(*validity*24) * time.Hour),
	// 		SerialNumber: generateSerial(),
	// 	},
	// }
	// manifest.loadCACert()
	// if *csrFile != "" {
	// 	csr := readCSR(*csrFile)
	// 	manifest.publicKey = csr.PublicKey.(*ecdsa.PublicKey)
	// 	manifest.Subject = csr.Subject
	// 	manifest.IPAddresses = csr.IPAddresses
	// 	manifest.EmailAddresses = csr.EmailAddresses
	// 	manifest.DNSNames = csr.DNSNames
	// } else {
	// 	if sans.raw == nil {
	// 		_ = sans.Set(defaultSAN)
	// 	}
	// 	manifest.privateKey = &privateKey{generateKey(), subjectPass}
	// 	manifest.publicKey = manifest.privateKey.Public().(*ecdsa.PublicKey)
	// 	manifest.Subject = dn.parseDN(manifest.ca.Subject)
	// 	manifest.IPAddresses = sans.ip
	// 	manifest.EmailAddresses = sans.email
	// 	manifest.DNSNames = sans.dns
	// }
	// manifest.SubjectKeyId = *hashPublicKey(manifest.publicKey)
	// keyFile := filepath.Dir(path)
	// keyFile = filepath.Join(keyFile, filepath.Base(keyFile)+"-key.pem")
	// manifest.ca.privateKey = readKey(keyFile, issuerPass)
	// manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	// manifest.sign()
	manifest := certManifest{}
	return &manifest
}

func createCSR(flags *csrFlags) csrManifest {
	key := &privateKey{generateKey(), &flags.keyPass}
	manifest := csrManifest{
		path:       flags.path,
		privateKey: key,
		CertificateRequest: &x509.CertificateRequest{
			Subject:            flags.dn.parseDN(pkix.Name{}),
			SignatureAlgorithm: x509.ECDSAWithSHA384,
			PublicKeyAlgorithm: x509.ECDSA,
			PublicKey:          key.PrivateKey.Public(),
			DNSNames:           flags.sans.dns,
			EmailAddresses:     flags.sans.email,
			IPAddresses:        flags.sans.ip,
		},
	}
	if der, err := x509.CreateCertificateRequest(rand.Reader, manifest.CertificateRequest, manifest.PrivateKey); err != nil {
		errorLog.Fatalf("Failed to sign certificate signing request: %s", err)
	} else { // else is required so value of der is available
		manifest.CertificateRequest.Raw = der
	}
	return manifest
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

type mainFlags struct {
	*flag.FlagSet
	root      string
	overwrite bool
	version   bool
	debug     bool
	command   string
	args      []string
}

func parseMainFlags(args []string, root string, overwrite, debug bool) mainFlags {
	fs := mainFlags{FlagSet: flag.NewFlagSet("main", flag.PanicOnError)}
	fs.StringVar(&fs.root, "root", root, "certificate tree root directory")
	fs.BoolVar(&fs.overwrite, "overwrite", overwrite, "don't abort if output directory already exists")
	fs.BoolVar(&fs.version, "version", false, "show program version")
	fs.BoolVar(&fs.debug, "debug", false, "output extra debugging information")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	if root, err := filepath.Abs(fs.root); err != nil {
		errorLog.Fatalf("Failed to parse root path %s: %s", fs.root, err)
	} else {
		fs.root = root
	}
	if len(fs.Args()) < 1 {
		errorLog.Fatalf("Failed to parse command: %s", strings.Join(args, " "))
	}
	fs.command = fs.Args()[0]
	fs.args = fs.Args()[1:]
	return fs
}

type certFlags struct {
	flag.FlagSet
	dn          distName
	sans        sanList
	ica         int
	validity    int
	subjectpass password
	issuerpass  password
	path        string
	isCA        bool
	csr         bool
}

func parseCertFlags(args []string, isCA bool, dn, san string, ica, validity int) *certFlags {
	fs := certFlags{FlagSet: *flag.NewFlagSet("ca", flag.PanicOnError)}
	fs.isCA = isCA
	fs.Var(&fs.dn, "dn", "subject distunguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	if isCA {
		fs.IntVar(&fs.ica, "ica", ica, "maximum number of subordinate intermediate certificate authorities allowed")
	}
	fs.BoolVar(&fs.csr, "csr", false, "create certificate from certificate signing request provided via stdin")
	fs.IntVar(&fs.validity, "validity", validity, "validity of the certificate in days")
	fs.Var(&fs.subjectpass, "subjectpass", "password for the subject private key")
	fs.Var(&fs.issuerpass, "issuerpass", "password for the issuer private key")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	} else if len(fs.Args()) != 1 {
		errorLog.Fatalf("Failed to parse certificate path: %s", strings.Join(fs.Args(), " "))
	}
	fs.path = filepath.Clean(fs.Args()[0])
	if fs.dn.string == nil {
		if dn != "" {
			fs.dn.Set(dn) // TODO why isn't compiler complaining about not checking err?
		} else {
			_ = fs.dn.Set("/CN=" + filepath.Base(fs.path))
		}

	}
	if fs.sans.string == nil {
		fs.sans = newSanList(san)
	}
	return &fs
}

type csrFlags struct {
	flag.FlagSet
	dn      distName
	sans    sanList
	keyPass password
	path    string
}

func parseCSRFlags(args []string, dn, san string) csrFlags {
	fs := csrFlags{FlagSet: *flag.NewFlagSet("csr", flag.PanicOnError)}
	fs.Var(&fs.dn, "dn", "subject distinguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	fs.Var(&fs.keyPass, "keyPass", "aes-256 encrypt private key with password")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	if fs.dn.string == nil {
		fs.dn.string = &dn
	}
	if fs.sans.string == nil {
		fs.sans = newSanList(san)
	}
	cn := fs.dn.parseDN(pkix.Name{}).CommonName
	if cn == "" {
		errorLog.Fatalf("Failed to parse common name from -dn flag: %s", *fs.dn.string)
	}
	switch len(fs.Args()) {
	case 0:
		fs.path = cn
	case 1:
		fs.path = fs.Args()[0]
	default:
		errorLog.Fatalf("Failed to parse command line options: unknown options %s", strings.Join(fs.Args(), " "))
	}
	return fs
}
