package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
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
	certTypes = map[string]certType{
		"ca": certType{
			command:         "ca",
			defaultValidity: 10 * (365 + 5),
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			defaultMaxICA:   0,
		},
		"ica": certType{
			command:         "ica",
			defaultValidity: 5 * (365 + 5),
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			defaultMaxICA:   0,
		},
		"server": certType{
			command:         "server",
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			defaultMaxICA:   0,
		},
		"client": certType{
			command:         "client",
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			defaultMaxICA:   0,
		},
		"peer": certType{
			command:         "peer",
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			defaultMaxICA:   0,
		},
	}
)

func main() {
	runTime = time.Now().UTC()
	fs := parseMainFlags(os.Args[1:], ".")
	if fs.version {
		infoLog.Printf("certshop %s\nBuilt: %s\nCopyright (c) 2017 VARASYS Limited", Version, Build)
		os.Exit(0)
	}
	setDebug(fs.debug)
	setRootDir(fs.root)
	switch fs.command {
	case "ca", "ica", "server", "client", "peer", "signature":
		flags := parseCertFlags(fs.args, certTypes[fs.command])
		manifest := createCertManifest(flags)
		manifest.sign()
		manifest.save(newFileWriter())
		infoLog.Printf("Finished creating %s: %s\n", fs.command, flags.path)
	case "csr":
		flags := parseCSRFlags(fs.args, "", "")
		manifest := createCSRManifest(flags)
		writer := newTgzWriter(os.Stdout)
		defer writer.close()
		manifest.save(writer)
		infoLog.Printf("Finished creating certificate signing request")
	case "export":
		exportCertificate(parseExportFlags(fs.args))
	case "describe":
		flags := parseDescribeFlags(fs.args)
		writer := newDescribeWriter(os.Stdout)
		writer.describe(flags)
		if err := writer.Flush(); err != nil {
			errorLog.Fatalf("Failed to flush output: %s", err)
		}
	case "kubernetes":
		createKubernetes(flag.Args()[1:])
	// case "openvpn":

	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
		fs.PrintDefaults()
	}
}

func createCertManifest(flags *certFlags) certManifest {
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
	manifest.SubjectKeyId = hashKeyID(manifest.publicKey)
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

func createCSRManifest(flags csrFlags) csrManifest {
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

func hashKeyID(key *ecdsa.PublicKey) []byte {
	hash := sha1.Sum(marshalKeyBitString(key).RightAlign())
	return hash[:]
}

func hashCertFingerprint(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}

func marshalKeyBitString(key *ecdsa.PublicKey) asn1.BitString {
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
	return publicKeyInfo.PublicKey
}

type mainFlags struct {
	flag.FlagSet
	root    string
	version bool
	debug   bool
	command string
	args    []string
}

func parseMainFlags(args []string, defaultRoot string) mainFlags {
	fs := mainFlags{FlagSet: *flag.NewFlagSet("main", flag.ExitOnError)}
	fs.StringVar(&fs.root, "root", defaultRoot, "certificate tree root directory")
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
	extKeyUsage  []x509.ExtKeyUsage
	keyUsage     x509.KeyUsage
	isCA         bool
	isSelfSigned bool
	local        bool
	localhost    bool
	export       bool
	describe     bool
}

func parseCertFlags(args []string, certType certType) *certFlags {
	fs := certFlags{FlagSet: *flag.NewFlagSet("ca", flag.ExitOnError)}
	fs.Var(&fs.dn, "dn", "subject distunguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	fs.IntVar(&fs.maxICA, "maxICA", certType.defaultMaxICA, "maximum number of subordinate intermediate certificate authorities allowed")
	fs.IntVar(&fs.validity, "validity", certType.defaultValidity, "validity of the certificate in days")
	fs.Var(&fs.subjectpass, "subjectpass", "password for the subject private key")
	fs.Var(&fs.issuerpass, "issuerpass", "password for the issuer private key")
	fs.Var(&fs.csr, "csr", "create certificate from certificate signing request (file path or leave blank to use stdin)")
	fs.BoolVar(&fs.local, "local", false, "include 127.0.0.1, ::1, and localhost in subject alternative names")
	fs.BoolVar(&fs.localhost, "localhost", false, "same as -local but also include \"${hostname}\" in subject alternative names")
	fs.BoolVar(&fs.export, "export", false, "export .tgz file to stdout with certificates")
	fs.BoolVar(&fs.describe, "describe", true, "output descriptions of what is created to stderr (and stdout if -export=false)")
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
	fs.isCA = fs.isSelfSigned || certType.command == "ca" || certType.command == "ica"
	if fs.csr.string != nil && fs.isSelfSigned {
		errorLog.Fatalf("Cannot self sign a certificate made from a csr (since there is no private key)")
	}
	if fs.isCA {
		fs.keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		fs.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	if fs.dn.string == nil {
		if certType.defaultDN != "" {
			_ = fs.dn.Set(certType.defaultDN)
		} else {
			_ = fs.dn.Set("/CN=" + filepath.Base(fs.path))
		}
	}
	if fs.sans.string == nil {
		fs.sans = newSanList(certType.defaultSAN)
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
	export    bool
	describe  bool
}

func parseCSRFlags(args []string, dn, san string) csrFlags {
	fs := csrFlags{FlagSet: *flag.NewFlagSet("csr", flag.ExitOnError)}
	fs.Var(&fs.dn, "dn", "subject distinguished name")
	fs.Var(&fs.sans, "san", "comma separated list of subject alternative names (ipv4, ipv6, dns or email)")
	fs.Var(&fs.keyPass, "keyPass", "aes-256 encrypt private key with password")
	fs.BoolVar(&fs.local, "local", false, "include 127.0.0.1, ::1, and localhost subject alternative names")
	fs.BoolVar(&fs.localhost, "localhost", false, "same as -local but also include local hostname subject alternative name")
	fs.BoolVar(&fs.export, "export", true, "export .tgz file to stdout with certificates")
	fs.BoolVar(&fs.describe, "describe", true, "output descriptions of what is created to stderr (and stdout if -export=false)")
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

type certType struct {
	command         string
	defaultValidity int
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	defaultMaxICA   int
	defaultDN       string
	defaultSAN      string
}

func setDebug(debug bool) {
	if debug {
		debugLog = log.New(os.Stderr, "", log.Lshortfile)
		errorLog.SetFlags(log.Lshortfile)
	}
}

func setRootDir(root string) {
	debugLog.Printf("Using root directory: %s", root)
	if err := os.MkdirAll(root, os.FileMode(0755)); err != nil {
		errorLog.Fatalf("Failed to create root directory %s: %s", root, err)
	}
	if err := os.Chdir(root); err != nil {
		errorLog.Fatalf("Failed to set root directory to %s: %s", root, err)
	}
}
