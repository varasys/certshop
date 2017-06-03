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
)

func init() {
	Commands[`csr`] = &Command{
		Description: `create a new private key and certificate signing request`,
		HelpString:  `TODO`,
		Function: func(fs *GlobalFlags) {
			manifest := ParseCSRFlags(fs)
			manifest.Sign()
			manifest.Save(NewFileWriter())
			if manifest.Describe {
				writer := NewDescribeWriter(os.Stderr)
				Describe(writer, manifest.Key)
				Describe(writer, manifest.CertificateRequest)
			}
			InfoLog.Printf("Finished creating certificate signing request: %s", manifest.Path)
		},
	}
}

// CSRFlags holds information required to create and sign a certificate
// signing request
type CSRFlags struct {
	flag.FlagSet
	CertificateRequest *x509.CertificateRequest
	Key                *ecdsa.PrivateKey
	Password           string
	Path               string
	Describe           bool
}

// ParseCSRFlags parses command line flags used to create a certificate signing
// request
func ParseCSRFlags(global *GlobalFlags) *CSRFlags {
	DebugLog.Println(`Parsing certificate request flags`)
	fs := CSRFlags{FlagSet: *flag.NewFlagSet(`csr`, flag.ContinueOnError)}
	fs.StringVar(&fs.Password, `subjectpass`, NilString, `password for the subject private key`)
	fs.BoolVar(&fs.Describe, `describe`, true, `output description of created key and certificate request`)
	dn := fs.String(`dn`, NilString, `subject distunguished name`)
	cn := fs.String(`cn`, NilString, `common name (overrides "CN=" from "-dn" flag)`)
	san := fs.String(`san`, NilString, `comma separated list of subject alternative names (ipv4, ipv6, dns or email)`)
	local := fs.Bool(`local`, false, `include "127.0.0.1", "::1", and "localhost" in subject alternative names`)
	localhost := fs.Bool(`localhost`, false, `same as -local but also include local hostname subject alternative name`)
	help := fs.Bool(`help`, false, `show help message and exit`)
	if err := fs.Parse(global.Args[1:]); err != nil || *help {
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		global.Command.HelpString = buf.String()
		if err != nil {
			global.Command.PrintHelp(os.Stderr, fmt.Errorf("Failed to parse certificate request command line options: %s", strings.Join(global.Args[1:], " ")))
		} else {
			global.Command.PrintHelp(os.Stdout, nil)
		}
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		fs.PrintDefaults()
		ErrorLog.Fatalf("Failed to parse certificate request path: %s", strings.Join(fs.Args(), ` `))
	}
	fs.Key = GenerateKey()
	fs.CertificateRequest = &x509.CertificateRequest{
		Subject:   ParseDN(pkix.Name{}, *dn, *cn),
		PublicKey: fs.Key.Public(),
	}
	sans := ParseSAN(*san, *cn, *local, *localhost)
	fs.CertificateRequest.IPAddresses = sans.ip
	fs.CertificateRequest.DNSNames = sans.dns
	fs.CertificateRequest.EmailAddresses = sans.email
	return &fs
}
