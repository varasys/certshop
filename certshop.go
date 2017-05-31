package main

import (
	"crypto/ecdsa"
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
	// Version is populated using `-ldflags -X `git describe --tags`` build option
	// build using the Makefile to inject this value
	Version string
	// Build is populated using `-ldflags -X `date +%FT%T%z`` build option
	// build using the Makefile to inject this value
	Build string
	// InfoLog logs informational messages to stderr
	InfoLog = log.New(os.Stderr, ``, 0)
	// DebugLog logs additional debugging information to stderr when the -debug
	// flag is used
	DebugLog = log.New(ioutil.Discard, ``, 0)
	// ErrorLog logs error messages (which are typically fatal)
	// The philosophy of this program is to fail fast on an error and not try
	// to do any recovery (so the user knows something is wrong and can
	// explicitely fix it)
	ErrorLog = log.New(os.Stderr, `Error: `, 0)
	// Root is the working directory (defaults to "./")
	Root string
	// Overwrite specifies not to abort if the output directory already exists
	Overwrite bool
	// RunTime stores the time the program started running (used to determine
	// certificate NotBefore and NotAfter values)
	RunTime time.Time
	// NilString is a string used to determine whether user input to a flag
	// was provided. This is done by setting the default flag value to
	// NilString.
	NilString = `\x00` // default for string flags (used to detect if user supplied value)
	// CertTypes defines some default values for different certificate types
	CertTypes = map[string]CertType{
		`ca`: CertType{
			command:         `ca`,
			defaultValidity: 10 * (365 + 5),
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			localSAN:        false,
		},
		`ica`: CertType{
			command:         `ica`,
			defaultValidity: 5 * (365 + 5),
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			localSAN:        false,
		},
		`server`: CertType{
			command:         `server`,
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			localSAN:        true,
		},
		`client`: CertType{
			command:         `client`,
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			localSAN:        true,
		},
		`peer`: CertType{
			command:         `peer`,
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			localSAN:        true,
		},
		`signature`: CertType{
			command:         `signature`,
			defaultValidity: 365 + 5,
			keyUsage:        x509.KeyUsageDigitalSignature,
			localSAN:        false,
		},
	}
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			ErrorLog.Fatalf(`%s`, err)
		}
	}()
	RunTime = time.Now().UTC()
	fs := ParseGlobalFlags()
	for fs.Command != NilString {
		command := fs.Command
		fs.Command = NilString
		switch command {
		case `ca`, `ica`, `server`, `client`, `peer`, `signature`:
			manifest := ParseCertFlags(fs.Args, CertTypes[fs.Command])
			manifest.Path = "Delete this line"
			// manifest.sign()
			// manifest.save(newFileWriter())
			InfoLog.Printf("Finished creating %s: %s\n", command, manifest.Path)
		case `csr`:
			manifest := ParseCSRFlags(fs.Args)
			manifest.Path = "Delete this line"
			writer := NewTgzWriter(os.Stdout)
			defer writer.Close()
			// manifest.save(writer)
			InfoLog.Printf(`Finished creating certificate signing request`)
		case `version`:
			InfoLog.Printf("certshop %s\nBuilt: %s\nCopyright (c) 2017 VARASYS Limited", Version, Build)
			os.Exit(0)
		case `export`:
			ExportCertificate(ParseExportFlags(fs.Args))
		case `describe`:
			flags := parseDescribeFlags(fs.Args)
			writer := newDescribeWriter(os.Stdout)
			writer.describe(flags)
			if err := writer.Flush(); err != nil {
				ErrorLog.Fatalf("Failed to flush output: %s", err)
			}
		case `kubernetes`:
			createKubernetes(flag.Args()[1:])
		// case `openvpn`:

		default:
			InfoLog.Println(`Usage: certshop ca | ica | server | client | signature | export`)
			fs.PrintDefaults()
		}
	}
}

// HashKeyID hashes a private key for use as a certificate Subject ID
func HashKeyID(key *ecdsa.PublicKey) []byte {
	hash := sha1.Sum(MarshalKeyBitString(key).RightAlign())
	return hash[:]
}

// HashCertFingerprint calculates the sha-256 certificate fingerprint hash
func HashCertFingerprint(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}

// MarshalKeyBitString extracts the asn1.BitString from the public key
func MarshalKeyBitString(key *ecdsa.PublicKey) asn1.BitString {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		ErrorLog.Fatalf(`Failed to marshal public key`)
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		ErrorLog.Fatalf(`Failed to unmarshal public key asn.1 bitstring`)
	}
	return publicKeyInfo.PublicKey
}

// GlobalFlags holds the global command line flags
type GlobalFlags struct {
	flag.FlagSet
	Root    string
	Debug   bool
	Command string
	Args    []string
}

// ParseGlobalFlags parses the global command line flags
func ParseGlobalFlags() GlobalFlags {
	InfoLog.Println(`Parsing global flags`)
	fs := GlobalFlags{FlagSet: *flag.NewFlagSet(`main`, flag.ContinueOnError)}
	fs.StringVar(&fs.Root, `root`, `./`, `certificate tree root directory`)
	fs.BoolVar(&Overwrite, `overwrite`, false, `don't abort if output directory already exists`)
	fs.BoolVar(&fs.Debug, `debug`, false, `output extra debugging information`)
	if err := fs.Parse(os.Args[1:]); err != nil {
		ErrorLog.Fatalf(`Failed to parse command line options: %s`, err)
	}
	SetDebug(fs.Debug)
	if root, err := filepath.Abs(fs.Root); err != nil {
		ErrorLog.Fatalf("Failed to parse root path %s: %s", fs.Root, err)
	} else {
		fs.Root = root
		SetRootDir(fs.Root)
	}
	fs.Args = fs.FlagSet.Args()
	if len(fs.Args) > 0 {
		fs.Command = fs.Args[0]
	} else {
		fs.Command = `help`
	}
	return fs
}

// SetDebug sets the debug logger output to stderr
func SetDebug(debug bool) {
	if debug {
		DebugLog = log.New(os.Stderr, ``, log.Lshortfile)
		ErrorLog.SetFlags(log.Lshortfile)
	}
}

// SetRootDir sets the applications working directory
func SetRootDir(root string) {
	DebugLog.Printf("Using root directory: %s", root)
	if err := os.MkdirAll(root, os.FileMode(0755)); err != nil {
		ErrorLog.Fatalf("Failed to create root directory %s: %s", root, err)
	}
	if err := os.Chdir(root); err != nil {
		ErrorLog.Fatalf("Failed to set root directory to %s: %s", root, err)
	}
}

// CertFlags holds information required to create and sign a certificate.
type CertFlags struct {
	flag.FlagSet
	SubjectCert *x509.Certificate
	IssuingCert *x509.Certificate
	Key         *ecdsa.PrivateKey
	SubjectPass string
	IssuerPass  string
	Path        string
}

// ParseCertFlags parses command line flags used to create a certificate
func ParseCertFlags(args []string, certType CertType) *CertFlags {
	InfoLog.Println(`Parsing certificate flags`)
	fs := CertFlags{FlagSet: *flag.NewFlagSet(`ca`, flag.ContinueOnError)}
	fs.StringVar(&fs.SubjectPass, `subjectpass`, NilString, `password for the subject private key`)
	fs.StringVar(&fs.IssuerPass, `issuerpass`, NilString, `password for the issuer private key`)
	csr := fs.String(`csr`, NilString, `create certificate from certificate signing request (file path or leave blank to use stdin)`)
	dn := fs.String(`dn`, NilString, `subject distunguished name`)
	cn := fs.String(`cn`, NilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, NilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
	maxICA := fs.Int(`maxICA`, 0, `maximum number of subordinate intermediate certificate authorities allowed`)
	local := fs.Bool(`local`, certType.localSAN, `include "127.0.0.1", "::1", and "localhost" in subject alternative names`)
	localhost := fs.Bool(`localhost`, false, `same as -local but also include local hostname subject alternative name`)
	inheritDN := fs.Bool(`inherit-dn`, true, `inherit ca distinguished name before applying "-dn" argument`)
	validity := fs.Int(`validity`, certType.defaultValidity, `validity of the certificate in days`)
	if err := fs.Parse(args[1:]); err != nil {
		ErrorLog.Fatalf("Failed to parse certificate command line options: %s", err)
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		ErrorLog.Fatalf(`Failed to parse certificate path: %s`, strings.Join(fs.Args(), ` `))
	}
	isSelfSigned := filepath.Dir(fs.Path) == `.`
	isCA := isSelfSigned || certType.command == `ca` || certType.command == `ica`
	if *csr != NilString && isSelfSigned {
		ErrorLog.Fatal(`Cannot self sign a certificate made from a csr (since the private key is not available for signing)`)
	}
	fs.Key = GenerateKey()
	fs.SubjectCert = &x509.Certificate{
		KeyUsage:     certType.keyUsage,
		ExtKeyUsage:  certType.extKeyUsage,
		NotBefore:    RunTime,
		NotAfter:     RunTime.Add(time.Duration(*validity*24) * time.Hour),
		SerialNumber: GenerateSerial(),
		PublicKey:    fs.Key.Public(),
		IsCA:         isCA,
		BasicConstraintsValid: isCA,
		MaxPathLen:            *maxICA,
		MaxPathLenZero:        *maxICA == 0,
	}
	if isCA {
		fs.SubjectCert.KeyUsage = fs.SubjectCert.KeyUsage | x509.KeyUsageCertSign
	}
	if isSelfSigned {
		fs.IssuingCert = fs.SubjectCert
	} else {
		caDir := filepath.Dir(fs.Path)
		fs.IssuingCert = ReadCert(filepath.Join(caDir, filepath.Base(caDir)+`.pem`))
	}
	if *inheritDN {
		fs.SubjectCert.Subject = ParseDN(fs.IssuingCert.Subject, *dn, *cn)
	} else {
		fs.SubjectCert.Subject = ParseDN(pkix.Name{}, *dn, *cn)
	}
	sans := ParseSAN(*san, *cn, *local, *localhost)
	// as per RFC 6125, published in '2011 "the validator must check SAN
	// first, and if SAN exists, then CN should not be checked" (so it is
	// good practice to duplicate the CN into the SAN list)
	fs.SubjectCert.IPAddresses = sans.ip
	fs.SubjectCert.DNSNames = sans.dns
	fs.SubjectCert.EmailAddresses = sans.email
	return &fs
}

// CertType holds default properties for some pre-defined certificate types
type CertType struct {
	command         string
	defaultValidity int
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	localSAN        bool
}

// CSRFlags holds information required to create and sign a certificate
// signing request
type CSRFlags struct {
	flag.FlagSet
	SubjectCSR  *x509.CertificateRequest
	Key         *ecdsa.PrivateKey
	SubjectPass string
	Path        string
}

// ParseCSRFlags parses command line flags used to create a certificate signing
// request
func ParseCSRFlags(args []string) *CSRFlags {
	InfoLog.Println(`Parsing certificate request flags`)
	fs := CSRFlags{FlagSet: *flag.NewFlagSet(`csr`, flag.ContinueOnError)}
	fs.StringVar(&fs.SubjectPass, `subjectpass`, NilString, `password for the subject private key`)
	dn := fs.String(`dn`, NilString, `subject distunguished name`)
	cn := fs.String(`cn`, NilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, NilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
	local := fs.Bool(`local`, false, `include "127.0.0.1", "::1", and "localhost" in subject alternative names`)
	localhost := fs.Bool(`localhost`, false, `same as -local but also include local hostname subject alternative name`)
	if err := fs.Parse(args[1:]); err != nil {
		ErrorLog.Fatalf(`Failed to parse certificate request command line options: %s`, err)
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		ErrorLog.Fatalf(`Failed to parse certificate request path: %s`, strings.Join(fs.Args(), ` `))
	}
	fs.Key = GenerateKey()
	fs.SubjectCSR = &x509.CertificateRequest{
		Subject:   ParseDN(pkix.Name{}, *dn, *cn),
		PublicKey: fs.Key.Public(),
	}
	sans := ParseSAN(*san, *cn, *local, *localhost)
	fs.SubjectCSR.IPAddresses = sans.ip
	fs.SubjectCSR.DNSNames = sans.dns
	fs.SubjectCSR.EmailAddresses = sans.email
	return &fs
}
