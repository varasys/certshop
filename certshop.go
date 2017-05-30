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
	Build     string
	InfoLog   = log.New(os.Stderr, ``, 0)
	DebugLog  = log.New(ioutil.Discard, ``, 0)
	ErrorLog  = log.New(os.Stderr, `Error: `, 0)
	Root      string
	Overwrite bool
	RunTime   time.Time
	nilString = `\x00` // default for string flags (used to detect if user supplied value)
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
	for fs.Command != nilString {
		command := fs.Command
		fs.Command = nilString
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
			writer := newTgzWriter(os.Stdout)
			defer writer.close()
			// manifest.save(writer)
			InfoLog.Printf(`Finished creating certificate signing request`)
		case `version`:
			InfoLog.Printf("certshop %s\nBuilt: %s\nCopyright (c) 2017 VARASYS Limited", Version, Build)
			os.Exit(0)
		case `export`:
			exportCertificate(parseExportFlags(fs.Args))
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

func HashKeyID(key *ecdsa.PublicKey) []byte {
	hash := sha1.Sum(MarshalKeyBitString(key).RightAlign())
	return hash[:]
}

func HashCertFingerprint(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.Raw)
	return hash[:]
}

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

type GlobalFlags struct {
	flag.FlagSet
	Root    string
	Debug   bool
	Command string
	Args    []string
}

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

func SetDebug(debug bool) {
	if debug {
		DebugLog = log.New(os.Stderr, ``, log.Lshortfile)
		ErrorLog.SetFlags(log.Lshortfile)
	}
}

func SetRootDir(root string) {
	DebugLog.Printf("Using root directory: %s", root)
	if err := os.MkdirAll(root, os.FileMode(0755)); err != nil {
		ErrorLog.Fatalf("Failed to create root directory %s: %s", root, err)
	}
	if err := os.Chdir(root); err != nil {
		ErrorLog.Fatalf("Failed to set root directory to %s: %s", root, err)
	}
}

type CertFlags struct {
	flag.FlagSet
	SubjectCert *x509.Certificate
	IssuingCert *x509.Certificate
	Key         *ecdsa.PrivateKey
	SubjectPass string
	IssuerPass  string
	Path        string
}

func ParseCertFlags(args []string, certType CertType) *CertFlags {
	InfoLog.Println(`Parsing certificate flags`)
	fs := CertFlags{FlagSet: *flag.NewFlagSet(`ca`, flag.ContinueOnError)}
	fs.StringVar(&fs.SubjectPass, `subjectpass`, nilString, `password for the subject private key`)
	fs.StringVar(&fs.IssuerPass, `issuerpass`, nilString, `password for the issuer private key`)
	csr := fs.String(`csr`, nilString, `create certificate from certificate signing request (file path or leave blank to use stdin)`)
	dn := fs.String(`dn`, nilString, `subject distunguished name`)
	cn := fs.String(`cn`, nilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, nilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
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
	if *csr != nilString && isSelfSigned {
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

type CertType struct {
	command         string
	defaultValidity int
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	localSAN        bool
}

type CSRFlags struct {
	flag.FlagSet
	SubjectCSR  *x509.CertificateRequest
	Key         *ecdsa.PrivateKey
	SubjectPass string
	Path        string
}

func ParseCSRFlags(args []string) *CSRFlags {
	InfoLog.Println(`Parsing certificate request flags`)
	fs := CSRFlags{FlagSet: *flag.NewFlagSet(`csr`, flag.ContinueOnError)}
	fs.StringVar(&fs.SubjectPass, `subjectpass`, nilString, `password for the subject private key`)
	dn := fs.String(`dn`, nilString, `subject distunguished name`)
	cn := fs.String(`cn`, nilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, nilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
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
