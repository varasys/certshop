package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type exportFlags struct {
	flag.FlagSet
	path    string
	crt     bool
	key     bool
	ca      string
	format  string
	passIn  password
	passOut password
}

func parseExportFlags(args []string) exportFlags {
	fs := exportFlags{FlagSet: *flag.NewFlagSet("export", flag.PanicOnError)}
	fs.BoolVar(&fs.crt, "crt", true, "export certificate")
	fs.BoolVar(&fs.key, "key", true, "export certificate")
	fs.StringVar(&fs.ca, "ca", "", "path to ca directory")
	fs.StringVar(&fs.format, "format", "pem", "export format (pem or p12)")
	fs.Var(&fs.passIn, "passIn", "existing private key password")
	fs.Var(&fs.passOut, "passOut", "pasword for exported private key")
	if err := fs.Parse(args); err != nil {
		errorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	switch len(fs.Args()) {
	case 1:
		fs.path = filepath.Clean(fs.Args()[0])
	default:
		errorLog.Fatalf("Failed to parse command line options: %s", strings.Join(fs.Args(), " "))
	}
	if fs.ca != "" {
		fs.ca = filepath.Clean(fs.ca)
	}
	return fs
}

func exportCertificate(flags exportFlags) {
	infoLog.Printf("Exporting %s\n", flags.path)
	writer := newTgzWriter(os.Stdout)
	defer writer.close()
	switch strings.ToLower(flags.format) {
	case "pem":
		exportPEM(writer, flags)
	case "p12":
		exportP12(writer, flags)
	}
	infoLog.Printf("Finished Exporting Certificate %s", flags.path)
}

func exportPEM(writer pkiWriter, flags exportFlags) {
	name := filepath.Base(flags.path)
	if flags.ca != "" {
		caPath := filepath.Join(flags.ca, filepath.Base(flags.ca)+".pem")
		writer.writeData(marshalCert(readCert(caPath)), filepath.Join(name, "ca.pem"), os.FileMode(0644), overwrite)
	}
	if flags.crt {
		data := []byte{}
		for certPath := flags.path; filepath.Base(certPath) != "."; certPath = filepath.Dir(certPath) {
			file := filepath.Join(certPath, filepath.Base(certPath)+".pem")
			der := marshalCert(readCert(file))
			data = append(data, der...)
		}
		writer.writeData(data, filepath.Join(name, "cert.pem"), os.FileMode(0644), overwrite)
	}
	if flags.key {
		if _, err := os.Stat(filepath.Join(flags.path, name+"-key.pem")); err == nil {
			key := readKey(filepath.Join(flags.path, name+"-key.pem"), &flags.passIn)
			key.pwd = &flags.passOut
			saveKey(writer, key, filepath.Join(name, "key.pem"))
		}
	}
}

func exportP12(writer pkiWriter, flags exportFlags) {
	infoLog.Print("Running openssl to create p12 file")
	name := filepath.Base(flags.path)
	args := []string{
		"pkcs12",
		"-export",
		"-name", filepath.Base(flags.path),
		"-inkey", filepath.Join(flags.path, name+"-key.pem")}
	if flags.passIn.string != nil {
		args = append(args, "-passin", "pass:"+*flags.passIn.string)
	}
	if flags.passOut.string == nil {
		errorLog.Fatal("-passOut flag required for .p12 format")
	} else {
		args = append(args, "-aes256", "-passout", "pass:"+*flags.passOut.string)
	}
	data := []byte{}
	for certPath := flags.path; certPath != "."; certPath = filepath.Dir(certPath) {
		data = append(data, marshalCert(readCert(filepath.Join(certPath, filepath.Base(certPath)+".pem")))...)
	}
	if flags.ca != "" {
		data = append(data, marshalCert(readCert(filepath.Join(flags.ca, filepath.Base(flags.ca)+".pem")))...)
	}
	tmpFile, err := ioutil.TempFile(os.TempDir(), "certshop")
	if err != nil {
		errorLog.Fatalf("Failed to create temporary cert file: %s", err)
	}
	if _, err = tmpFile.Write(data); err != nil {
		errorLog.Fatalf("Failed to write to temporary cert file: %s", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			errorLog.Fatalf("Failed to close temporary cert file: %s", err)
		}
	}()
	args = append(args, "-in", tmpFile.Name())
	cmd := exec.Command("openssl", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		errorLog.Fatalf("Error running openssl: %s", err)
	}
}
