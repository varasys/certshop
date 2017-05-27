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
	fs := parseMainFlags(os.Args[1:], ".")
	if fs.version {
		infoLog.Printf("certshop %s\nBuilt: %s\nCopyright (c) 2017 VARASYS Limited", Version, Build)
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
		flags := parseCertFlags(fs.args, "ca", "", "", 0, 10*(365+5))
		manifest := createCertificate(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ca in %s\n", filepath.Join(root, flags.path))
		describeCert(manifest.Certificate, nil)
	case "ica":
		flags := parseCertFlags(fs.args, "ica", "", "", 0, 5*(365+5))
		manifest := createCertificate(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating ca in %s\n", filepath.Join(root, flags.path))
	case "server":
		flags := parseCertFlags(fs.args, "server", "", "", 0, 10*(365+5))
		flags.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		flags.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		manifest := createCertificate(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating server in %s\n", filepath.Join(root, manifest.path))
	case "client":
		flags := parseCertFlags(fs.args, "client", "", "", 0, 10*(365+5))
		flags.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		flags.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		manifest := createCertificate(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating client in %s\n", filepath.Join(root, manifest.path))
	case "peer":
		flags := parseCertFlags(fs.args, "peer", "", "", 0, 10*(365+5))
		flags.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		flags.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		manifest := createCertificate(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating peer in %s\n", filepath.Join(root, manifest.path))
	case "signature":
		flags := parseCertFlags(fs.args, "signature", "", "", 0, 10*(365+5))
		flags.keyUsage = x509.KeyUsageDigitalSignature
		manifest := createCertificate(flags)
		manifest.sign()
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
		exportCertificate(parseExportFlags(fs.args))
	case "describe":
		infoLog.Printf("starting describe thingy")
		flags := parseDescribeFlags(fs.args)
		writer := newDescribeWriter(true, true)
		writer.writeHeader(0, "Starting Describe")
		writer.processFlags(&flags)
	case "kubernetes":
		createKubernetes(flag.Args()[1:])
	// case "openvpn":

	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
		fs.PrintDefaults()
	}
}

func createCertificate(flags *certFlags) certManifest {
	debugLog.Printf("Creating certificate %s\n", flags.path)
	if !overwrite {
		if _, err := os.Stat(flags.path); err == nil {
			errorLog.Fatalf("Directory %s exists, use -overwrite flag to overwrite.", filepath.Join(root, flags.path))
		}
	}
	manifest := certManifest{
		path: flags.path,
		Certificate: &x509.Certificate{
			KeyUsage:       flags.keyUsage,
			ExtKeyUsage:    flags.extKeyUsage,
			NotBefore:      runTime,
			NotAfter:       runTime.Add(time.Duration(flags.validity*24) * time.Hour),
			SerialNumber:   generateSerial(),
			IPAddresses:    flags.sans.ip,
			DNSNames:       flags.sans.dns,
			EmailAddresses: flags.sans.email,
		},
	}
	if flags.isCA {
		manifest.IsCA = true
		manifest.BasicConstraintsValid = true
		manifest.MaxPathLen = flags.maxICA
		manifest.MaxPathLenZero = flags.maxICA == 0
	}
	if flags.csr.string != nil {
		der := flags.csr.Get().([]byte)
		csr := unMarshalCSR(der)
		manifest.publicKey = csr.PublicKey.(*ecdsa.PublicKey)
		manifest.Subject = csr.Subject
		manifest.IPAddresses = csr.IPAddresses
		manifest.DNSNames = csr.DNSNames
		manifest.EmailAddresses = csr.EmailAddresses
	} else {
		manifest.privateKey = &privateKey{generateKey(), &flags.subjectpass}
		manifest.publicKey = manifest.privateKey.Public().(*ecdsa.PublicKey)
		manifest.Subject = flags.dn.parseDN(pkix.Name{})
	}
	manifest.SubjectKeyId = hashPublicKey(manifest.publicKey)
	if flags.isSelfSigned {
		manifest.ca = &certManifest{
			path:        ".",
			Certificate: manifest.Certificate,
			privateKey:  manifest.privateKey,
		}
	} else {
		manifest.loadCACert()
		keyFile := filepath.Dir(flags.path)
		keyFile = filepath.Join(keyFile, filepath.Base(keyFile)+"-key.pem")
		manifest.ca.privateKey = readKey(keyFile, &flags.issuerpass)
		if flags.isCA && (manifest.ca.MaxPathLen < 1 || manifest.MaxPathLen > (manifest.ca.MaxPathLen-1)) {
			errorLog.Fatalf("Maximum Path Length of certificate authority exceeded")
		}
		manifest.Subject = flags.dn.parseDN(manifest.ca.Subject)
	}
	manifest.AuthorityKeyId = manifest.ca.SubjectKeyId
	if flags.local || flags.localhost {
		concatIP(manifest.IPAddresses, "127.0.0.1", "::1")
		concatDNS(manifest.DNSNames, "localhost")
	}
	if flags.localhost {
		if host, err := os.Hostname(); err != nil {
			errorLog.Fatalf("Failed to determine localhost: set the common name using the -dn flag")
		} else {
			if manifest.Subject.CommonName == "" {
				manifest.Subject.CommonName = host
			} else {
				concatDNS(manifest.DNSNames, host)
			}
		}
	}
	return manifest
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

func hashPublicKey(key *ecdsa.PublicKey) []byte {
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
	return slice
}

type mainFlags struct {
	*flag.FlagSet
	root    string
	version bool
	debug   bool
	command string
	args    []string
}

func parseMainFlags(args []string, root string) mainFlags {
	fs := mainFlags{FlagSet: flag.NewFlagSet("main", flag.PanicOnError)}
	fs.StringVar(&fs.root, "root", root, "certificate tree root directory")
	fs.BoolVar(&overwrite, "overwrite", false, "don't abort if output directory already exists")
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
	dn           distName
	sans         sanList
	maxICA       int
	validity     int
	subjectpass  password
	issuerpass   password
	path         string
	csr          csrPath
	isCA         bool
	isSelfSigned bool
	local        bool
	localhost    bool
	extKeyUsage  []x509.ExtKeyUsage
	keyUsage     x509.KeyUsage
}

func parseCertFlags(args []string, command, dn, san string, maxICA, validity int) *certFlags {
	fs := certFlags{FlagSet: *flag.NewFlagSet("ca", flag.PanicOnError)}
	fs.Var(&fs.dn, "dn", "subject distunguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	fs.IntVar(&fs.maxICA, "maxICA", maxICA, "maximum number of subordinate intermediate certificate authorities allowed")
	fs.IntVar(&fs.validity, "validity", validity, "validity of the certificate in days")
	fs.Var(&fs.subjectpass, "subjectpass", "password for the subject private key")
	fs.Var(&fs.issuerpass, "issuerpass", "password for the issuer private key")
	fs.Var(&fs.csr, "csr", "create certificate from certificate signing request (file path or leave blank to use stdin)")
	fs.BoolVar(&fs.local, "local", false, "include 127.0.0.1, ::1, and localhost subject alternative names")
	fs.BoolVar(&fs.localhost, "localhost", false, "same as -local but also include local hostname subject alternative name")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	switch len(fs.Args()) {
	case 0:
		// do nothing
	case 1:
		fs.path = filepath.Clean(fs.Args()[0])
	default:
		errorLog.Fatalf("Failed to parse certificate path: %s", strings.Join(fs.Args(), " "))
	}
	fs.isSelfSigned = filepath.Dir(fs.path) == "."
	fs.isCA = fs.isSelfSigned || command == "ca" || command == "ica"

	// error checking
	if fs.csr.string != nil && fs.isSelfSigned {
		errorLog.Fatalf("Cannot self sign a certificate made from a csr (since there is no private key)")
	}
	if fs.isCA {
		fs.keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		fs.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}

	if fs.dn.string == nil {
		if dn != "" {
			_ = fs.dn.Set(dn)
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
	dn        distName
	sans      sanList
	keyPass   password
	path      string
	local     bool
	localhost bool
}

func parseCSRFlags(args []string, dn, san string) csrFlags {
	fs := csrFlags{FlagSet: *flag.NewFlagSet("csr", flag.PanicOnError)}
	fs.Var(&fs.dn, "dn", "subject distinguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	fs.Var(&fs.keyPass, "keyPass", "aes-256 encrypt private key with password")
	fs.BoolVar(&fs.local, "local", false, "include 127.0.0.1, ::1, and localhost subject alternative names")
	fs.BoolVar(&fs.localhost, "localhost", false, "same as -local but also include local hostname subject alternative name")
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
