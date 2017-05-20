package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func exportCertificate(args []string) {
	fs := flag.NewFlagSet("export", flag.PanicOnError)
	crt := fs.Bool("crt", true, "include the certificate in pem format")
	key := fs.Bool("key", true, "include the private key in pem format")
	ca := fs.Bool("ca", true, "include the ca bundle in pem format")
	p12 := fs.Bool("p12", false, "include certificate and key together in pkcs12 format")
	password := fs.String("password", "", "password for pkcs12 format")
	openvpn := fs.Bool("openvpn", false, "include snippet that can be concatenated to the end of openvpn config files")

	err := fs.Parse(args)
	if err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}

	if len(fs.Args()) != 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	}
	path := fs.Arg(0)
	name := filepath.Base(path)
	infoLog.Printf("Exporting Certificate %s", path)

	gz := gzip.NewWriter(os.Stdout)
	defer func() {
		if err = gz.Close(); err != nil {
			errorLog.Fatalf("Failed to close gzip writer: %s", err)
		}
	}()

	tw := tar.NewWriter(gz)
	defer func() {
		if err = tw.Close(); err != nil {
			errorLog.Fatalf("Failed to close tar file: %s", err)
		}
	}()
	if *p12 {
		if *password == "" {
			errorLog.Fatalf("A password is required to export to pkcs12 format")
		}
		infoLog.Print("Running openssl to create p12 file")
		cmd := exec.Command("openssl", "pkcs12", "-export", "-in", filepath.Join(path, name+".crt"), "-inkey", filepath.Join(path, name+".key"), "-passout", "stdin")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			errorLog.Fatalf("Failed to open stdin pipe to openssl: %s", err)
		}
		go func() {
			defer func() {
				if err = stdin.Close(); err != nil {
					errorLog.Fatalf("Failed to close stdin pipe to openssl: %s", err)
				}
			}()
			if _, err = io.WriteString(stdin, *password); err != nil {
				errorLog.Fatalf("Failed to transfer password to openssl: %s", err)
			}
		}()
		out, err := cmd.Output()
		if err != nil {
			errorLog.Fatalf("Error running openssl: %s", err)
		}
		header := &tar.Header{Name: name + ".p12", Mode: 0600, ModTime: time.Now().UTC(), Size: int64(len(out))}
		if err = tw.WriteHeader(header); err != nil {
			errorLog.Fatalf("Failed to write tar header: %s", err)
		}
		if _, err = tw.Write(out); err != nil {
			errorLog.Fatalf("Failed to write tar file: %s", err)
		}
		infoLog.Print("Finished running openssl")
	}
	if *crt {
		tarAppendFile(tw, filepath.Join(path, name+".crt"), name+".crt", "cert.pem", 0644)
	}
	if *key {
		tarAppendFile(tw, filepath.Join(path, name+".key"), name+".key", "key.pem", 0600)
	}
	if *ca {
		tarAppendFile(tw, filepath.Join(path, "ca.pem"), "ca.pem", "", 0644)
	}
	if *openvpn {
		type config struct {
			Ca, Cert, Key string
		}
		text := "# Append this snippet to the end of the OpenVPN config file\n<ca>\n{{.Ca}}</ca>\n<cert>\n{{.Cert}}</cert>\n<key>\n{{.Key}}</key>\n"
		tmpl, err := template.New("ovpn").Parse(text)
		if err != nil {
			errorLog.Fatalf("Error parsing ovpn config template: %s", err)
		}
		buf := new(bytes.Buffer)
		if err = tmpl.Execute(buf,
			config{Ca: readFile(filepath.Join(path, "ca.pem")),
				Cert: readFile(filepath.Join(path, name+".crt")),
				Key:  readFile(filepath.Join(path, name+".key"))}); err != nil {
			errorLog.Fatalf("Error creating ovpn config: %s", err)
		}
		header := &tar.Header{Name: name + ".ovpn", Mode: 0600, ModTime: time.Now().UTC(), Size: int64(buf.Len())}
		if err = tw.WriteHeader(header); err != nil {
			errorLog.Fatalf("Failed to write tar header: %s", err)
		}
		if _, err = tw.Write(buf.Bytes()); err != nil {
			errorLog.Fatalf("Failed to write tar file: %s", err)
		}
	}
	infoLog.Printf("Finished Exporting Certificate %s", path)
}

func tarAppendFile(tw *tar.Writer, path string, tarPath string, altTarPath string, mode int64) {
	info, err := os.Stat(path)
	if err != nil {
		errorLog.Fatalf("Failed to read file metadata: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		errorLog.Fatalf("Failed to open file: %s", path)
	}
	defer func() {
		if err = file.Close(); err != nil {
			errorLog.Fatalf("Failed to close %s: %s", path, err)
		}
	}()
	if err := tw.WriteHeader(&tar.Header{Name: tarPath, Mode: mode, ModTime: info.ModTime(), Size: info.Size()}); err != nil {
		errorLog.Fatalf("Failed to write tar header: %s", path)
	}
	if _, err := io.Copy(tw, file); err != nil {
		errorLog.Fatalf("Failed to write tar file: %s", path)
	}
	if altTarPath != "" {
		if err := tw.WriteHeader(&tar.Header{Name: altTarPath, Mode: mode, ModTime: info.ModTime(), Linkname: tarPath, Typeflag: tar.TypeLink}); err != nil {
			errorLog.Fatalf("Failed to create hard links in tar file: %s", path)
		}
	}
}

/*func copyFile(source string, dest string, perms os.FileMode) {
	sourceFile, err := os.Open(source)
	if err != nil {
		errorLog.Fatalf("Failed to open %s for reading: %s", source, err)
	}
	defer func() {
		if err = sourceFile.Close(); err != nil {
			errorLog.Fatalf("Failed to close %s: %s", source, err)
		}
	}()
	destFile, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, perms)
	if err != nil {
		errorLog.Fatalf("Failed to open %s for writing: %s", dest, err)
	}
	defer func() {
		if err = destFile.Close(); err != nil {
			errorLog.Fatalf("Failed to close %s: %s", dest, err)
		}
	}()
	if _, err = io.Copy(destFile, sourceFile); err != nil {
		errorLog.Fatalf("Failed to copy %s: %s", source, err)
	}
}*/

func readFile(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read file %s: %s", path, err)
	}
	return string(data)
}
