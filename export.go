package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func exportCertificate(args []string) {
	fs := flag.NewFlagSet("export", flag.PanicOnError)
	crt := fs.Bool("crt", true, "include the certificate")
	key := fs.Bool("key", true, "include the private key")
	ca := fs.Bool("ca", true, "include the ca certificate")
	format := fs.String("format", "pem", "export format (pem|p12)")

	passIn := &password{}
	fs.Var(passIn, "passIn", "current private key password")
	passOut := &password{}
	fs.Var(passOut, "passOut", "exported private key password (default = inPass)")

	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}

	if len(fs.Args()) != 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	}
	path := filepath.Clean(fs.Arg(0))
	name := filepath.Base(path)
	if passOut.string == nil {
		passOut.string = passIn.string
	}
	infoLog.Printf("Exporting %s", path)
	writer := newTgzWriter(os.Stdout)
	defer func() {
		writer.close()
	}()
	switch *format {
	case "pem":
		if *ca {
			for caPath := path; caPath != "."; caPath = filepath.Dir(caPath) {
				if filepath.Dir(caPath) == "." {
					writer.writeData(marshalCert(readCert(filepath.Join(caPath, caPath+".pem"))), filepath.Join(name, "ca.pem"), os.FileMode(0644), overwrite)
				}
			}
		}
		if *crt {
			data := []byte{}
			for certPath := path; filepath.Base(certPath) != "."; certPath = filepath.Dir(certPath) {
				file := filepath.Join(certPath, filepath.Base(certPath)+".pem")
				der := marshalCert(readCert(file))
				data = append(data, *der...)
			}
			writer.writeData(&data, filepath.Join(name, "cert.pem"), os.FileMode(0644), overwrite)
		}
		if _, err := os.Stat(filepath.Join(path, name+"-key.pem")); *key && err == nil {
			key := readKey(filepath.Join(path, name+"-key.pem"), passIn)
			key.pwd = passOut
			saveKey(writer, key, filepath.Join(name, "key.pem"))
		}
	case "p12":
		infoLog.Print("Running openssl to create p12 file")
		args := []string{
			"pkcs12",
			"-export",
			"-name", filepath.Base(path),
			"-in", filepath.Join(path, name+".pem"),
			"-inkey", filepath.Join(path, name+"-key.pem")}
		if passIn.string != nil {
			args = append(args, "-passin", "pass:"+*passIn.string)
		}
		if passOut.string == nil {
			errorLog.Fatal("-passOut flag required for .p12 format")
		} else {
			args = append(args, "-aes256", "-passout", "pass:"+*passOut.string)
		}
		data := []byte{}
		for certPath := filepath.Dir(path); certPath != "."; certPath = filepath.Dir(certPath) {
			file := filepath.Join(certPath, filepath.Base(certPath)+".pem")
			der := marshalCert(readCert(file))
			data = append(data, *der...)
		}
		if len(data) > 0 {
			tmpFile, err := ioutil.TempFile(os.TempDir(), "certshop")
			if err != nil {
				errorLog.Fatalf("Failed to create temporary ca file: %s", err)
			}
			if _, err = tmpFile.Write(data); err != nil {
				errorLog.Fatalf("Failed to write to temporary ca file: %s", err)
			}
			defer func() {
				if err := os.Remove(tmpFile.Name()); err != nil {
					errorLog.Fatalf("Failed to close temporary ca file: %s", err)
				}
			}()
			args = append(args, "-certfile", tmpFile.Name())
		}
		cmd := exec.Command("openssl", args...)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			errorLog.Fatalf("Error running openssl: %s", err)
		}
	}
	infoLog.Printf("Finished Exporting Certificate %s", path)
}
