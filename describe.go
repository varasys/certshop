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
	"os"
	"path/filepath"
)

type describeFlags struct {
	flag.FlagSet
	paths []string
	key   bool
	crt   bool
	csr   bool
}

func parseDescribeFlags(args []string) describeFlags {
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
	return fs
}

func (writer *describeWriter) processFlags(flags *describeFlags) {
	if len(flags.paths) == 0 {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			errorLog.Fatalf("Failed to read from stdin: %s", err)
		}
		writer.writeHeader(0, "Processing from stdin")
		writer.processDER(&data, flags.key, flags.crt, flags.csr)
	} else {
		for i := range flags.paths {
			_ = filepath.Walk(flags.paths[i],
				func(path string, info os.FileInfo, err error) error {
					if info.IsDir() {
						writer.writeHeader(0, "Processing directory: "+path)
					} else {
						writer.writeHeader(0, "Processing file: "+path)
						if data, err := ioutil.ReadFile(path); err != nil {
							writer.writeError(0, err.Error())
						} else {
							writer.processDER(&data, flags.key, flags.crt, flags.csr)
						}
					}
					return nil
				})
		}
	}
}

func (writer *describeWriter) processDER(der *[]byte, key, crt, csr bool) {
	rest := *der
	var block *pem.Block
	for block, rest = pem.Decode(rest); block != nil; {
		_ = rest // to prevent compiler complaints about inneffectual assignment
		switch block.Type {
		case "CERTIFICATE":
			if crt {
				crt, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse certificate: %s", err)
				}
				describeCert(crt, writer)
			}
		case "EC PRIVATE KEY":
			if key {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse key: %s", err)
				}
				describeKey(key, writer)
			}
		case "CERTIFICATE REQUEST":
			if csr {
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					errorLog.Fatalf("Failed to parse key: %s", err)
				}
				describeCSR(csr, writer)
			}
		}
	}
}

type describeWriter struct {
	bufio.Writer
}

func newDescribeWriter(stdout bool, stderr bool) describeWriter {
	return describeWriter{*bufio.NewWriter(io.MultiWriter(os.Stdout, os.Stderr))}
	writers := make([]io.Writer, 2)
	if stdout {
		writers = append(writers, os.Stdout)
	}
	if stderr {
		writers = append(writers, os.Stderr)
	}
	return describeWriter{*bufio.NewWriter(io.MultiWriter(writers...))}
}

func (writer *describeWriter) writeHeader(indent int, header string) {
	fmtString := "%" + string(indent*5) + "s|%s"
	if _, err := fmt.Fprintf(writer, fmtString, "", header); err != nil {
		errorLog.Fatalf("Failed to output describe information: %s", err)
	}
}

func (writer *describeWriter) writeError(indent int, err string) {
	fmtString := "%" + string(indent*5) + "s|%s"
	if _, err := fmt.Fprintf(writer, fmtString, "", err); err != nil {
		errorLog.Fatalf("Failed to output describe information: %s", err)
	}
}

func (writer *describeWriter) writeValue(indent int, param, value string) {
	fmtString := "%" + string(indent*5) + "s|%" + string(30-indent*5) + "s|%s\n"
	if _, err := fmt.Fprintf(writer, fmtString, "", param, value); err != nil {
		errorLog.Fatalf("Failed to output describe information: %s", err)
	}
}

func describeCert(crt *x509.Certificate, writer *describeWriter) {
	var outWriter describeWriter
	if writer == nil {
		outWriter = newDescribeWriter(true, true)
	} else {
		outWriter = *writer
	}
	outWriter.writeValue(1, "Version", string(crt.Version))
	outWriter.writeValue(1, "common name", crt.Subject.CommonName)
}

func describeKey(key *ecdsa.PrivateKey, writer *describeWriter) {
	var outWriter describeWriter
	if writer == nil {
		outWriter = newDescribeWriter(true, true)
	} else {
		outWriter = *writer
	}
	outWriter.writeValue(1, "Public Key ID", "blah")
}

func describeCSR(csr *x509.CertificateRequest, writer *describeWriter) {
	var outWriter describeWriter
	if writer == nil {
		outWriter = newDescribeWriter(true, true)
	} else {
		outWriter = *writer
	}
	outWriter.writeValue(1, "Public Key ID", "blah")
}
