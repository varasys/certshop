package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
	"time"
)

var (
	publicKeyAlgorithms = map[x509.PublicKeyAlgorithm]string{
		x509.UnknownPublicKeyAlgorithm: "Unknown",
		x509.RSA:                       "RSA",
		x509.DSA:                       "DSA",
		x509.ECDSA:                     "ECDSA",
	}

	keyUsages = map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageContentCommitment: "Content Commitment",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageCertSign:          "Certificate Signing",
		x509.KeyUsageCRLSign:           "CRL Signing",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
	}

	extKeyUsages = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "Any",
		x509.ExtKeyUsageServerAuth:                 "Server Auth",
		x509.ExtKeyUsageClientAuth:                 "Client Auth",
		x509.ExtKeyUsageCodeSigning:                "Code Signing",
		x509.ExtKeyUsageEmailProtection:            "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
		x509.ExtKeyUsageTimeStamping:               "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MS Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
	}
)

// DescribeFlags structure holds command line flags for the describe command
type DescribeFlags struct {
	flag.FlagSet
	paths    []string
	key      bool
	crt      bool
	csr      bool
	password string
}

// ParseDescribeFlags parses command line options to the describe command
// into a DescribeFlags struct
func ParseDescribeFlags(args []string) *DescribeFlags {
	fs := DescribeFlags{FlagSet: *flag.NewFlagSet("describe", flag.ExitOnError)}
	fs.StringVar(&fs.password, `password`, NilString, "private key password")
	fs.BoolVar(&fs.key, "key", false, "display private keys")
	fs.BoolVar(&fs.crt, "crt", false, "display certificates")
	fs.BoolVar(&fs.csr, "csr", false, "display certificate signing requests")
	if err := fs.Parse(args[1:]); err != nil {
		ErrorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	fs.paths = fs.Args()
	if !fs.key && !fs.crt && !fs.csr {
		fs.key = true
		fs.crt = true
		fs.csr = true
	}
	return &fs
}

// Describe outputs a description based on DescribeFlags parsed from the
// command line
func (writer *DescribeWriter) Describe(flags *DescribeFlags) {
	if len(flags.paths) == 0 {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			ErrorLog.Fatalf("Failed to read from stdin: %s", err)
		}
		writer.Sprintf("\nDescribing from stdin\n")
		writer.ProcessDER(data, flags)
	} else {
		for i := range flags.paths {
			err := filepath.Walk(filepath.Join(Root, flags.paths[i]),
				func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					} else if info.IsDir() {
						writer.Sprintf("\nDescribing directory: %s", path)
					} else {
						writer.Sprintf("\nDescribing file: %s", path)
						if data, err := ioutil.ReadFile(path); err != nil {
							return fmt.Errorf("failed to read file %s: %s", path, err)
						} else {
							writer.ProcessDER(data, flags)
						}
					}
					return nil
				})
			if err != nil {
				writer.Sprintf("Error walking directory tree: %s\n", err)
			}
		}
	}
	writer.Sprintf("\n")
}

// ProcessDER describes a der format certificate, certificate request, or
// private key
func (writer *DescribeWriter) ProcessDER(der []byte, flags *DescribeFlags) {
	for block, rest := pem.Decode(der); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			if flags.crt {
				if err := DescribeBlock(writer, block, x509.ParseCertificate); err != nil {
					ErrorLog.Printf("Failed to parse certificate: %s\n", err)
				}
			}
		case "EC PRIVATE KEY":
			if flags.key {
				if flags.password != NilString {
					if der, err := x509.DecryptPEMBlock(block, []byte(flags.password)); err != nil {
						ErrorLog.Printf("Failed to decrypt private key: %s\n", err)
					} else {
						if key, err := x509.ParseECPrivateKey(der); err != nil {
							ErrorLog.Printf("Failed to parse private key: %s\n", err)
						} else {
							Describe(writer, key)
						}
					}
				} else {
					if err := DescribeBlock(writer, block, x509.ParseECPrivateKey); err != nil {
						ErrorLog.Printf("Failed to parse private key: %s\n", err)
					}
				}
			}
		case "CERTIFICATE REQUEST":
			if flags.csr {
				if err := DescribeBlock(writer, block, x509.ParseCertificateRequest); err != nil {
					ErrorLog.Printf("Failed to parse csr: %s\n", err)
				}
			}
		default:
			writer.Sprintf("Failed to parse file\n")
		}
	}
}

// DescribeBlock describes a pem format block
func DescribeBlock(writer *DescribeWriter, block *pem.Block, parser interface{}) error {
	in := []reflect.Value{reflect.ValueOf(block.Bytes)}
	out := reflect.ValueOf(parser).Call(in)
	if out[1].Interface() != nil {
		return out[1].Interface().(error)
	}
	Describe(writer, out[0].Interface())
	return nil
}

// DescribeWriter is a wrapper around a bufio.Writer. Use NewDescribeWriter to
// set the output from the bufio.Writer
type DescribeWriter struct {
	bufio.Writer
}

// NewDescribeWriter returns a DescribeWriter outputting to the set
// set of writers (typically stderr, stdout, or both)
func NewDescribeWriter(writers ...io.Writer) *DescribeWriter {
	return &DescribeWriter{*bufio.NewWriter(io.MultiWriter(writers...))}
}

// Sprintf is a utility helper to print formatted strings to the writer
func (writer *DescribeWriter) Sprintf(format string, a ...interface{}) {
	if _, err := writer.WriteString(fmt.Sprintf(format, a...)); err != nil {
		ErrorLog.Fatalf("Failed to write to output: %s", err)
	}
}

var (
	certificateTemplate = `
  Subject Certificate Information:
    {{template "subject" .Subject}}
    DNS Names:           {{join .DNSNames ", "}}
    IP Addresses:        {{joinIP .IPAddresses    ", "}}
    Email Addresses:     {{join .EmailAddresses ", "}}
    x.509 Version:       {{.Version}}
    Is CA:               {{.IsCA}}{{if .IsCA}} (Max Path Length = {{.MaxPathLen}}){{end}}
    Not Before:          {{localTime .NotBefore}}
    Not After:           {{localTime .NotAfter}}
    Key Usage:           {{formatKeyUsage .KeyUsage}}
    Extended Key Usage:  {{formatExtKeyUsage .ExtKeyUsage}}
    Key Algorithm:       {{keyAlgorithm .PublicKey}}
    Key ID:              {{encodeHexString .SubjectKeyId}}
    Signature Algorithm: {{.SignatureAlgorithm.String}}
    Serial Number:       {{encodeHexString .SerialNumber.Bytes}}
    SHA256 Fingerprint:  {{hashSHA256Fingerprint .}}
    SHA1 Fingerprint:    {{hashSHA1Fingerprint .}}
    MD5 Fingerprint:     {{hashMD5Fingerprint .}}

  Issuing Certificate Authority Information:
    {{template "subject" .Issuer}}
    Key ID:              {{encodeHexString .AuthorityKeyId}}
`

	csrTemplate = `
  Certificate Signing Request Information:
    {{template "subject" .Subject}}
    DNS Names:           {{join .DNSNames ", "}}
    IP Addresses:        {{joinIP .IPAddresses    ", "}}
    Email Addresses:     {{join .EmailAddresses ", "}}
    Key Algorithm:       {{keyAlgorithm .PublicKey}}
    Key ID:              {{hashKeyID .PublicKey}}
    Signature Algorithm: {{.SignatureAlgorithm.String}}
    SHA256 Fingerprint:  {{hashSHA256Fingerprint .}}
    SHA1 Fingerprint:    {{hashSHA1Fingerprint .}}
    MD5 Fingerprint:     {{hashMD5Fingerprint .}}
`

	subjectTemplate = `Common Name:         {{.CommonName}}{{if .Organization}}
    Organization:        {{join .Organization ", "}}{{end}}{{if .OrganizationalUnit}}
    Organizational Unit: {{join .OrganizationalUnit ", "}}{{end}}{{if .Country}}
    Country:             {{join .Country ", "}}{{end}}{{if .Province}}
    State/Province:      {{join .Province ", "}}{{end}}{{if .Locality}}
    Locality:            {{join .Locality ", "}}{{end}}`

	keyTemplate = `
  Private Key Information
    Key Algorithm:       {{keyAlgorithm .PublicKey}}
    Key ID:              {{hashKeyID .PublicKey}}
`
)

// potential future items (not currently included)
//  OCSP Servers:         {{join .OCSPServer ", "}}
//  Issuing URLs:         {{join .IssuingCertificateURL ", "}}
//  CRL Dist. Points:     {{join .CRLDistributionPoints ", "}}

// Describe will accept either a *x509.Certificate, *x509.CertificateRequest
// or *ecdsa.PrivateKey
func Describe(writer *DescribeWriter, entity interface{}) {
	tmpl := template.New("main").Funcs(templateFunctions)
	switch entity.(type) {
	case *x509.Certificate:
		_ = template.Must(tmpl.Parse(certificateTemplate))
		_ = template.Must(tmpl.New("subject").Funcs(templateFunctions).Parse(subjectTemplate))
	case *x509.CertificateRequest:
		_ = template.Must(tmpl.Parse(csrTemplate))
		_ = template.Must(tmpl.New("subject").Funcs(templateFunctions).Parse(subjectTemplate))
	case *ecdsa.PrivateKey:
		_ = template.Must(tmpl.Parse(keyTemplate))
	}
	if err := tmpl.Execute(writer, entity); err != nil {
		ErrorLog.Printf("Error describing item: %s", err)
	}
	if err := writer.Flush(); err != nil {
		ErrorLog.Printf("Error flushing describe output: %s", err)
	}
}

var templateFunctions = template.FuncMap{
	"encodeHexString": func(data []byte) string {
		return fmt.Sprintf("% X", data)
	},
	"localTime": func(val time.Time) time.Time {
		return val.Local()
	},
	"join": strings.Join,
	"joinIP": func(val []net.IP, sep string) string {
		strs := make([]string, len(val))
		for i := range val {
			strs[i] = val[i].String()
		}
		return strings.Join(strs, sep)
	},
	"publicKeyAlgorithms": func(val x509.PublicKeyAlgorithm) string {
		return publicKeyAlgorithms[val]
	},
	"hashSHA256Fingerprint": func(entity interface{}) string {
		return fmt.Sprintf("% X", HashSHA256Fingerprint(entity))
	}, "hashSHA1Fingerprint": func(entity interface{}) string {
		return fmt.Sprintf("% X", HashSHA1Fingerprint(entity))
	}, "hashMD5Fingerprint": func(entity interface{}) string {
		return fmt.Sprintf("% X", HashMD5Fingerprint(entity))
	},
	"hashKeyID": func(key *ecdsa.PublicKey) string {
		return fmt.Sprintf("% X", HashKeyID(key))
	},
	"keyAlgorithm": func(pubKey interface{}) string {
		switch pubKey.(type) {
		case *ecdsa.PublicKey:
			key := pubKey.(*ecdsa.PublicKey)
			return fmt.Sprintf("ECDSA (%s)", key.Curve.Params().Name)
		case ecdsa.PublicKey:
			key := pubKey.(ecdsa.PublicKey)
			return fmt.Sprintf("ECDSA (%s)", key.Curve.Params().Name)
		case *rsa.PublicKey:
			return "Error: RSA key found, but only ECDSA keys are supported"
		default:
			return "Unknown Key Algorithm"
		}
	},
	"formatKeyUsage": func(usage x509.KeyUsage) string {
		result := []string{}
		for i, str := range keyUsages {
			if usage&i == i {
				result = append(result, str)
			}
		}
		return strings.Join(result, ", ")
	},
	"formatExtKeyUsage": func(usage []x509.ExtKeyUsage) string {
		result := make([]string, len(usage))
		for i := range usage {
			result[i] = extKeyUsages[usage[i]]
		}
		return strings.Join(result, ", ")
	},
}
