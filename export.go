package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExportFlags struct holds information required by the "export" command
type ExportFlags struct {
	flag.FlagSet
	path         string
	exportCrt    bool
	exportKey    bool
	exportCA     string
	exportFormat string
	passIn       string
	passOut      string
}

// ParseExportFlags parses the command line flags for the "export" command
func ParseExportFlags(args []string) ExportFlags {
	fs := ExportFlags{FlagSet: *flag.NewFlagSet("export", flag.ContinueOnError)}
	fs.BoolVar(&fs.exportCrt, "export-crt", false, "export certificate")
	fs.BoolVar(&fs.exportKey, "export-key", false, "export certificate")
	fs.StringVar(&fs.exportCA, "export-ca", NilString, "path to ca certificate")
	fs.StringVar(&fs.exportFormat, "export-format", "tgz", "export format (\"tgz\" or \"p12\")")
	fs.StringVar(&fs.passIn, "pass-in", NilString, "existing private key password (only required if -exportFormat=\"p12\" and the key is encrypted)")
	fs.StringVar(&fs.passOut, "pass-out", NilString, "pasword for exported private key (only required if -exportFormat=\"p12\")")
	exportAll := fs.String("export-all", NilString, "shortcut for \"-export-crt -export-key -export-ca={path}\" where -export-ca={path} is only include if a path is provided")
	if err := fs.Parse(args); err != nil {
		ErrorLog.Fatalf("Failed to parse command line options: %s", err)
	}
	switch len(fs.Args()) {
	case 1:
		fs.path = filepath.Clean(fs.Args()[0])
	default:
		ErrorLog.Fatalf("Failed to parse command line options: %s", strings.Join(fs.Args(), " "))
	}
	if *exportAll != NilString {
		fs.exportCrt = true
		fs.exportKey = true
		if *exportAll != "" {
			fs.exportCA = *exportAll
		}
	}
	return fs
}

// FindFile accepts a path which is either a directory or file. If it is a
// file the path is returned direcly. If it is a directory, the path to the
// file in the directory with the same name as the directory and
// ending with 'suffix' is returned if it exists or an error is returned.
// It is used to pull a certificate or key from a directory given the
// directory name.
func FindFile(path string, suffix string) (string, error) {
	path = filepath.Clean(path)
	if info, err := os.Stat(path); err != nil {
		return "", err
	} else if info.IsDir() {
		path = filepath.Join(path, filepath.Base(path)+suffix)
		if info, err := os.Stat(path); err != nil {
			return "", err
		} else if info.IsDir() {
			return "", fmt.Errorf("%s is a directory and not a file", path)
		}
	}
	return path, nil
}

// ExportCertificate exports certificate with key and optionally a ca certificate
// to a .tgz archive
func ExportCertificate(flags ExportFlags) {
	InfoLog.Printf("Exporting %s\n", flags.path)
	if flags.exportCA != "" {
		if path, err := FindFile(flags.exportCA, ".pem"); err != nil {
			ErrorLog.Fatalf("Failed to find ca certificate: %s", err)
		} else {
			flags.exportCA = path
		}
	}
	writer := NewTgzWriter(os.Stdout)
	defer writer.Close()
	switch strings.ToLower(flags.exportFormat) {
	case "pem":
		ExportPEM(writer, flags)
	case "p12":
		ExportP12(writer, flags)
	}
	InfoLog.Printf("Finished Exporting Certificate %s", flags.path)
}

// ExportPEM exports in .pem format
func ExportPEM(writer PKIWriter, flags ExportFlags) {
	name := filepath.Base(flags.path)
	if flags.exportCA != "" {
		writer.WriteData(MarshalCert(ReadCert(flags.exportCA)), filepath.Join(name, "ca.pem"), os.FileMode(0644))
	}
	if flags.exportCrt {
		data := []byte{}
		for certPath := flags.path; filepath.Base(certPath) != "."; certPath = filepath.Dir(certPath) {
			file := filepath.Join(certPath, filepath.Base(certPath)+".pem")
			data = append(data, MarshalCert(ReadCert(file))...)
		}
		writer.WriteData(data, filepath.Join(name, "cert.pem"), os.FileMode(0644))
	}
	if flags.exportKey {
		if _, err := os.Stat(filepath.Join(flags.path, name+"-key.pem")); err == nil {
			key := ReadKey(filepath.Join(flags.path, name+"-key.pem"), flags.passIn)
			key.pwd = flags.passOut
			SaveKey(writer, key, filepath.Join(name, "key.pem"))
		}
	}
}

// ExportP12 exports in .p12 format
func ExportP12(writer PKIWriter, flags ExportFlags) {
	InfoLog.Print("Running openssl to create p12 file")
	name := filepath.Base(flags.path)
	args := []string{
		"pkcs12",
		"-export",
		"-name", filepath.Base(flags.path),
		"-inkey", filepath.Join(flags.path, name+"-key.pem")}
	if flags.passIn != NilString {
		args = append(args, "-passin", "pass:"+flags.passIn)
	}
	if flags.passOut == NilString {
		ErrorLog.Fatal("-passOut flag required for .p12 format")
	} else {
		args = append(args, "-aes256", "-passout", "pass:"+flags.passOut)
	}
	data := []byte{}
	for certPath := flags.path; certPath != "."; certPath = filepath.Dir(certPath) {
		data = append(data, MarshalCert(ReadCert(filepath.Join(certPath, filepath.Base(certPath)+".pem")))...)
	}
	if flags.exportCA != "" {
		data = append(data, MarshalCert(ReadCert(filepath.Join(flags.exportCA, filepath.Base(flags.exportCA)+".pem")))...)
	}
	tmpFile, err := ioutil.TempFile(os.TempDir(), "certshop")
	if err != nil {
		ErrorLog.Fatalf("Failed to create temporary cert file: %s", err)
	}
	if _, err = tmpFile.Write(data); err != nil {
		ErrorLog.Fatalf("Failed to write to temporary cert file: %s", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			ErrorLog.Fatalf("Failed to close temporary cert file: %s", err)
		}
	}()
	args = append(args, "-in", tmpFile.Name())
	cmd := exec.Command("openssl", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		ErrorLog.Fatalf("Error running openssl: %s", err)
	}
}
