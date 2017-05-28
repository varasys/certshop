package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// publicKeyAlgorithms is used to map x509.PublicKeyAlgorithm constants
// to their string representations
var publicKeyAlgorithms = map[x509.PublicKeyAlgorithm]string{
	x509.UnknownPublicKeyAlgorithm: "Unknown",
	x509.RSA:                       "RSA",
	x509.DSA:                       "DSA",
	x509.ECDSA:                     "ECDSA",
}

type describeFlags struct {
	flag.FlagSet
	paths []string
	key   bool
	crt   bool
	csr   bool
}

func parseDescribeFlags(args []string) *describeFlags {
	fs := describeFlags{FlagSet: *flag.NewFlagSet("describe", flag.PanicOnError)}
	fs.BoolVar(&fs.key, "key", false, "display private keys")
	fs.BoolVar(&fs.crt, "crt", false, "display certificates")
	fs.BoolVar(&fs.csr, "csr", false, "display certificate signing requests")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	fs.paths = fs.Args()
	if !fs.key && !fs.crt && !fs.csr {
		fs.key = true
		fs.crt = true
		fs.csr = true
	}
	return &fs
}

func (writer *describeWriter) processFlags(flags *describeFlags) {
	if len(flags.paths) == 0 {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			errorLog.Fatalf("Failed to read from stdin: %s", err)
		}
		writer.writeHeader(0, "Processing from stdin")
		writer.processDER(data, flags.key, flags.crt, flags.csr)
	} else {
		for i := range flags.paths {
			err := filepath.Walk(flags.paths[i],
				func(path string, info os.FileInfo, err error) error {
					if info.IsDir() {
						writer.writeHeader(0, "Processing directory: "+path)
					} else {
						writer.writeHeader(0, "Processing file: "+path)
						if data, err := ioutil.ReadFile(path); err != nil {
							writer.writeError(0, err.Error())
						} else {
							writer.processDER(data, flags.key, flags.crt, flags.csr)
						}
					}
					return nil
				})
			if err != nil {
				errorLog.Fatalf("Failed to process describe flags: %s", err)
			}
		}
	}
}

func (writer *describeWriter) processDER(der []byte, key, crt, csr bool) {
	for block, rest := pem.Decode(der); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			if crt {
				crt, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse certificate: %s", err)
				}
				if err = describeCert(writer, crt); err != nil {
					errorLog.Fatalf("Failed to describe certificate: %s", err)
				}
			}
		case "EC PRIVATE KEY":
			if key {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse key: %s", err)
				}
				fmt.Fprintf(writer, "%+v", key)
				_ = writer.Flush()
			}
		case "CERTIFICATE REQUEST":
			if csr {
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse key: %s", err)
				}
				fmt.Fprintf(writer, "%+v", csr)
				_ = writer.Flush()
			}
		}
	}
}

type describeWriter struct {
	bufio.Writer
}

func newDescribeWriter(stdout bool, stderr bool) describeWriter {
	writers := make([]io.Writer, 0, 2)
	if stdout {
		writers = append(writers, os.Stdout)
	}
	if stderr {
		writers = append(writers, os.Stderr)
	}
	return describeWriter{*bufio.NewWriter(io.MultiWriter(writers...))}
}

func (writer *describeWriter) writeHeader(indent int, header string) {
	fmtString := "%" + string(indent*5) + "s|%s\n"
	if _, err := fmt.Fprintf(writer, fmtString, "", header); err != nil {
		errorLog.Fatalf("Failed to output describe information: %s", err)
	}
	_ = writer.Flush()
}

func (writer *describeWriter) writeError(indent int, err string) {
	fmtString := "%" + string(indent*5) + "s|%s\n"
	if _, err := fmt.Fprintf(writer, fmtString, "", err); err != nil {
		errorLog.Fatalf("Failed to output describe information: %s", err)
	}
	_ = writer.Flush()
}

var subjectTemplate = `  CommonName:          {{.CommonName}}{{if .Organization}}
  Organization:        {{join .Organization ", "}}{{end}}{{if .OrganizationalUnit}}
  Organizational Unit: {{join .OrganizationalUnit ", "}}{{end}}{{if .Country}}
  Country:             {{join .Country ", "}}{{end}}{{if .Province}}
  State/Province:      {{join .Province ", "}}{{end}}{{if .Locality}}
  Locality:            {{join .Locality ", "}}{{end}}`

var certificateTemplate = `Issuing Certificate Authority Information:
{{template "subject" .Issuer}}
  Key ID:              {{encodeHexString .AuthorityKeyId}}

Subject Certificate Information:
  x.509 Version:       {{.Version}}
  Is CA:               {{.IsCA}}{{if .IsCA}} (max path length = {{.MaxPathLen}}){{end}}
{{template "subject" .Subject}}
  DNS Names:           {{join .DNSNames ", "}}
  Email Addresses:     {{join .EmailAddresses ", "}}
  IP Addresses:        {{joinIP .IPAddresses    ", "}}
  Key Algorithm:       {{keyAlgorithm .}}
  Key ID:              {{encodeHexString .SubjectKeyId}}
  Serial Number:       {{encodeHexString .SerialNumber.Bytes}}
  SHA256 Fingerprint:  {{hashCertFingerprint .}}
  Signature Algorithm: {{.SignatureAlgorithm.String}}
  Not Before:          {{localTime .NotBefore}}
  Not After:           {{localTime .NotAfter}}
  
  Key Usage:           {{.KeyUsage}}
  Extended Key Usage:  {{.ExtKeyUsage}}
`

//  OCSP Servers:         {{join .OCSPServer ", "}}
//  Issuing URLs:         {{join .IssuingCertificateURL ", "}}
//  CRL Dist. Points:     {{join .CRLDistributionPoints ", "}}

func describeCert(writer *describeWriter, crt *x509.Certificate) (err error) {
	tmpl := template.New("cert").Funcs(template.FuncMap{
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
		"hashCertFingerprint": func(cert *x509.Certificate) string {
			return fmt.Sprintf("% X", hashCertFingerprint(cert))
		},
		"keyAlgorithm": func(crt *x509.Certificate) string {
			key := crt.PublicKey.(*ecdsa.PublicKey)
			return fmt.Sprintf("%s (%s)", publicKeyAlgorithms[crt.PublicKeyAlgorithm], key.Curve.Params().Name)
		},
	})
	if _, err = tmpl.Parse(certificateTemplate); err != nil {
		return err
	}
	subject := tmpl.New("subject").Funcs(template.FuncMap{
		"join": strings.Join,
	})
	if _, err = subject.Parse(subjectTemplate); err != nil {
		return err
	}
	if err := tmpl.Execute(writer, crt); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return nil
}
