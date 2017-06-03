package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Commands[`ca`] = &Command{
		Description: `create a new private key and self-signed certificate authority`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				defaultValidity: 10 * (365 + 5),
				keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
				localSAN:        false,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating ca certificate: %s\n", manifest.Path)
		},
	}
	Commands[`ica`] = &Command{
		Description: `create a new private key and self-signed intermediate certificate authority`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				command:         `ica`,
				defaultValidity: 5 * (365 + 5),
				keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
				localSAN:        false,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating ica certificate: %s\n", manifest.Path)
		},
	}
	Commands[`server`] = &Command{
		Description: `create a new private key and server certificate`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				command:         `server`,
				defaultValidity: 365 + 5,
				keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				localSAN:        true,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating server certificate: %s\n", manifest.Path)
		},
	}
	Commands[`client`] = &Command{
		Description: `create a new private key and client certificate`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				command:         `client`,
				defaultValidity: 365 + 5,
				keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				localSAN:        true,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating client certificate: %s\n", manifest.Path)
		},
	}
	Commands[`peer`] = &Command{
		Description: `create a new private key and peer (server and client) certificate`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				command:         `peer`,
				defaultValidity: 365 + 5,
				keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				localSAN:        true,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating peer certificate: %s\n", manifest.Path)
		},
	}
	Commands[`signature`] = &Command{
		Description: `create a new private key and digital signature certificate`,
		HelpString:  `TODO`, // populated in ParseCertFlags error handler
		Function: func(fs *GlobalFlags) {
			certType := &CertType{
				command:         `signature`,
				defaultValidity: 365 + 5,
				keyUsage:        x509.KeyUsageDigitalSignature,
				localSAN:        false,
			}
			manifest := CreateCertificate(fs, certType)
			InfoLog.Printf("Finished creating signature certificate: %s\n", manifest.Path)
		},
	}
}

// CertType is used to pass some certificate properties into CreateCertificate
type CertType struct {
	command         string
	defaultValidity int
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	localSAN        bool
}

// CertFlags holds information required to create and sign a certificate.
type CertFlags struct {
	flag.FlagSet
	SubjectCert *x509.Certificate
	IssuingCert *x509.Certificate
	SubjectKey  *ecdsa.PrivateKey
	IssuingKey  *ecdsa.PrivateKey
	SubjectPass string
	Path        string
	Describe    bool
}

// ParseCertFlags parses command line flags used to create a certificate
func ParseCertFlags(global *GlobalFlags, certType *CertType) *CertFlags {
	DebugLog.Println(`Parsing certificate flags`)
	fs := CertFlags{FlagSet: *flag.NewFlagSet(`ca`, flag.ContinueOnError)}
	fs.StringVar(&fs.SubjectPass, `subject-pass`, NilString, `password for the subject private key`)
	fs.BoolVar(&fs.Describe, `describe`, true, `output description of created key and certificate`)
	caPass := fs.String(`issuing-pass`, NilString, `the issuing private key password`)
	csr := fs.String(`csr`, NilString, `create certificate from certificate signing request (file path or leave blank to use stdin)`)
	dn := fs.String(`dn`, NilString, `subject distunguished name`)
	cn := fs.String(`cn`, NilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, NilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
	maxICA := fs.Int(`maxICA`, 0, `maximum number of subordinate intermediate certificate authorities allowed`)
	local := fs.Bool(`local`, certType.localSAN, `include "127.0.0.1", "::1", and "localhost" in subject alternative names`)
	localhost := fs.Bool(`localhost`, false, `same as -local but also include local hostname subject alternative name`)
	inheritDN := fs.Bool(`inherit-dn`, true, `inherit distinguished name from issuing certificate before applying "-dn" argument`)
	validity := fs.Int(`validity`, certType.defaultValidity, `validity of the certificate in days`)
	help := fs.Bool(`help`, false, `show help message and exit`)
	if err := fs.Parse(global.Args[1:]); err != nil || *help {
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		global.Command.HelpString = buf.String()
		if err != nil {
			global.Command.PrintHelp(os.Stderr, fmt.Errorf("Failed to parse certificate command line options: %s", strings.Join(global.Args[1:], " ")))
		} else {
			global.Command.PrintHelp(os.Stdout, nil)
		}
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		ErrorLog.Fatalf(`Failed to parse certificate path: %s`, strings.Join(global.Args[1:], ` `))
	}
	isSelfSigned := filepath.Dir(fs.Path) == `.`
	isCA := isSelfSigned || certType.command == `ca` || certType.command == `ica`
	if *csr != NilString && isSelfSigned {
		ErrorLog.Fatal(`Cannot self sign a certificate made from a csr (since the private key is not available for signing)`)
	}
	fs.SubjectCert = &x509.Certificate{
		KeyUsage:     certType.keyUsage,
		ExtKeyUsage:  certType.extKeyUsage,
		NotBefore:    RunTime,
		NotAfter:     RunTime.Add(time.Duration(*validity*24) * time.Hour),
		SerialNumber: GenerateSerial(),
		IsCA:         isCA,
		BasicConstraintsValid: isCA,
		MaxPathLen:            *maxICA,
		MaxPathLenZero:        *maxICA == 0,
	}
	sans := SANSet{}
	if *csr == NilString {
		fs.SubjectKey = GenerateKey()
		fs.SubjectCert.PublicKey = fs.SubjectKey.Public()
	} else {
		request := ReadCSR(*csr)
		fs.SubjectCert.PublicKey = request.PublicKey
		if *dn == NilString {
			fs.SubjectCert.Subject = request.Subject
		}
		if *san == NilString {
			sans.ip = request.IPAddresses
			sans.dns = request.DNSNames
			sans.email = request.EmailAddresses
		}
	}
	fs.SubjectCert.SubjectKeyId = HashKeyID(fs.SubjectCert.PublicKey.(*ecdsa.PublicKey))
	if isCA {
		fs.SubjectCert.KeyUsage = fs.SubjectCert.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		fs.SubjectCert.ExtKeyUsage = AppendExtKeyUsage(fs.SubjectCert.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}
	if isSelfSigned {
		fs.IssuingCert = fs.SubjectCert
		fs.IssuingKey = fs.SubjectKey
	} else {
		caDir := filepath.Dir(fs.Path)
		fs.IssuingCert = ReadCert(filepath.Join(caDir, filepath.Base(caDir)+`.pem`))
		fs.IssuingKey = ReadKey(filepath.Join(caDir, filepath.Base(caDir)+`-key.pem`), *caPass)
	}
	fs.SubjectCert.AuthorityKeyId = fs.IssuingCert.SubjectKeyId
	if *csr != NilString {
		if *inheritDN {
			fs.SubjectCert.Subject = ParseDN(fs.IssuingCert.Subject, *dn, *cn)
		} else {
			fs.SubjectCert.Subject = ParseDN(pkix.Name{}, *dn, *cn)
		}
	} else {
		if *inheritDN {
			fs.SubjectCert.Subject = ParseDN(fs.IssuingCert.Subject, *dn, *cn)
		} else {
			fs.SubjectCert.Subject = ParseDN(pkix.Name{}, *dn, *cn)
		}
	}
	if fs.SubjectCert.Subject.CommonName == "" {
		fs.SubjectCert.Subject.CommonName = filepath.Base(fs.Path)
	}
	if *san != NilString {
		sans = *ParseSANString(*san)
	}
	if *local || *localhost {
		sans.AppendLocalSAN(*localhost)
	}
	fs.SubjectCert.IPAddresses = sans.ip
	fs.SubjectCert.DNSNames = sans.dns
	fs.SubjectCert.EmailAddresses = sans.email
	return &fs
}

// CreateCertificate creates a certificate given command args and a CertType
func CreateCertificate(global *GlobalFlags, certType *CertType) *CertFlags {
	manifest := ParseCertFlags(global, certType)
	manifest.Sign()
	manifest.Save(NewFileWriter())
	if manifest.Describe {
		writer := NewDescribeWriter(os.Stdout)
		if manifest.SubjectKey != nil {
			Describe(writer, manifest.SubjectKey)
		}
		Describe(writer, manifest.SubjectCert)
	}
	return manifest
}
