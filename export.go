package main

// import (
// 	"archive/tar"
// 	"bytes"
// 	"flag"
// 	"html/template"
// 	"io"
// 	"os/exec"
// 	"path/filepath"
// 	"strings"
// 	"time"
// )

// func exportCertificate(args []string) {
// 	fs := flag.NewFlagSet("export", flag.PanicOnError)
// 	crt := fs.Bool("crt", true, "include the certificate in pem format")
// 	key := fs.Bool("key", true, "include the private key in pem format")
// 	ca := fs.Bool("ca", true, "include the ca bundle in pem format")
// 	format := fs.String("format", "pem", "export format (pem|der|p12)")
// 	inPass := fs.String("inPass", "", "current private key password (only required for p12 format)")
// 	outPass := fs.String("outPass", "", "password for exported private key")

// 	if err := fs.Parse(args); err != nil {
// 		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
// 	}

// 	if len(fs.Args()) != 1 {
// 		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
// 	}
// 	path := filepath.Clean(fs.Arg(0))
// 	name := filepath.Base(path)
// 	infoLog.Printf("Exporting %s", path)

// 	switch *format {
// 	case "pem":

// 	case "der":

// 	case "p12":
// 		infoLog.Print("Running openssl to create p12 file")
// 		cmd := exec.Command("openssl", "pkcs12", "-export", "-in", filepath.Join(path, name+".crt"), "-inkey", filepath.Join(path, name+".key"), "-passout", "stdin")
// 		stdin, err := cmd.StdinPipe()
// 		if err != nil {
// 			errorLog.Fatalf("Failed to open stdin pipe to openssl: %s", err)
// 		}
// 		go func() {
// 			defer func() {
// 				if err = stdin.Close(); err != nil {
// 					errorLog.Fatalf("Failed to close stdin pipe to openssl: %s", err)
// 				}
// 			}()
// 			if _, err = io.WriteString(stdin, *inPass); err != nil {
// 				errorLog.Fatalf("Failed to transfer password to openssl: %s", err)
// 			}
// 		}()
// 		out, err := cmd.Output()
// 		if err != nil {
// 			errorLog.Fatalf("Error running openssl: %s", err)
// 		}
// 	}
// 	infoLog.Printf("Finished Exporting Certificate %s", path)
// }
