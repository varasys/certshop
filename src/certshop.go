package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var infoLog = log.New(os.Stderr, "", 0)
var errorLog = log.New(os.Stderr, "ERROR: ", log.Lshortfile)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
var privatePerms os.FileMode = 0600
var publicPerms os.FileMode = 0644

func main() {
	var command string
	if len(os.Args) < 1 {
		command = ""
	} else {
		command = os.Args[1]
	}
	switch command {
	case "ca":
		createCA(os.Args[2:], "ca", "/CN=certstore-ca", 10*365+5)
	case "ica":
		createCA(os.Args[2:], "ca/ica", "/CN=certstore-ica", 5*365+5)
	case "server":
		createCertificate(os.Args[2:], "ca/server", "/CN=server", "localhost,127.0.0.1", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	case "client":
		createCertificate(os.Args[2:], "ca/client", "/CN=client", "", 365+5,
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	case "signature":
		createCertificate(os.Args[2:], "ca/sign", "/CN=sign", "", 365+5,
			x509.KeyUsageDigitalSignature, nil)
	case "export":
		exportCertificate(os.Args[2:])
	default:
		infoLog.Println("Usage: certshop ca | ica | server | client | signature | export")
	}
}

func createCA(args []string, path string, defaultDn string, defaultValidity int) {
	fs := flag.NewFlagSet("ca", flag.PanicOnError)
	dn := fs.String("dn", defaultDn, "certificate subject")
	maxPathLength := fs.Int("maxPathLength", 0, "max path length")
	validity := fs.Int("validity", defaultValidity, "ca validity in days")
	overwrite := fs.Bool("overwrite", false, "overwrite any existing files")

	err := fs.Parse(args)
	if err != nil {
		errorLog.Fatalf("Failed to parse command line arguments: %s", err)
	}

	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = fs.Arg(0)
	}

	infoLog.Printf("Creating Certificate Authority %s with Subject: %s\n", path, *dn)

	if !*overwrite {
		checkExisting(path)
	}

	ca := filepath.Dir(path)
	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey
	if ca != "." {
		caCert = parseCert(ca)
		if !caCert.IsCA {
			errorLog.Fatalf("Certificate %s is not a certificate authority", ca)
		} else if !(caCert.MaxPathLen > 0) {
			errorLog.Fatalf("Certificate Authority %s can't sign other certificate authorities (maxPathLength exceeded)", ca)
		}
		*maxPathLength = caCert.MaxPathLen - 1
		caKey = parseKey(ca)
	}

	key, derKey, err := generatePrivateKey()
	if err != nil {
		errorLog.Fatalf("Error generating private key: %s", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, *validity)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		errorLog.Fatalf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               *parseDn(caCert, *dn),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLen:     *maxPathLength,
		MaxPathLenZero: *maxPathLength == 0,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	if caCert == nil {
		caCert = &template
		caKey = key
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		errorLog.Fatalf("Failed to create CA Certificate: %s", err)
	}
	saveCert(path, derCert)
	saveKey(path, derKey)
	if caCert != &template {
		copyFile(filepath.Join(filepath.Dir(path), "ca.pem"), filepath.Join(path, "ca.pem"), publicPerms)
	} else {
		copyFile(filepath.Join(path, path+".crt"), filepath.Join(path, "ca.pem"), publicPerms)
	}
	infoLog.Printf("Finished Creating Certificate Authority %s with Subject: %s\n", path, *dn)
}

func createCertificate(args []string, path string, defaultDn string, defaultSan string, defaultValidity int, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) {
	fs := flag.NewFlagSet("server", flag.PanicOnError)
	dn := fs.String("dn", defaultDn, "certificate subject")
	san := fs.String("san", defaultSan, "subject alternative names")
	validity := fs.Int("validity", defaultValidity, "certificate validity in days")
	overwrite := fs.Bool("overwrite", false, "overwrite any existing files")

	err := fs.Parse(args)
	if err != nil {
		errorLog.Fatalf("Failed to parse command line argumanets: %s", err)
	}

	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = fs.Arg(0)
	}

	infoLog.Printf("Creating Certificate %s with Subject: %s\n", path, *dn)

	if !*overwrite {
		checkExisting(path)
	}

	ca := filepath.Dir(path)

	caCert := parseCert(ca)
	if !caCert.IsCA {
		errorLog.Fatalf("Certificate %s is not a certificate authority", filepath.Dir(path))
	}
	caKey := parseKey(ca)

	key, derKey, err := generatePrivateKey()
	if err != nil {
		errorLog.Fatalf("Error generating private key: %s", err)
	}

	notBefore := time.Now().UTC().Add(-10 * time.Minute) // -10 min to mitigate clock skew
	notAfter := notBefore.AddDate(0, 0, *validity).Add(10 * time.Minute)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		errorLog.Fatalf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        *parseDn(caCert, *dn),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		IsCA:           false,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		EmailAddresses: []string{},
	}

	parseSubjectAlternativeNames(*san, &template)

	derCert, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		errorLog.Fatalf("Failed to create Server Certificate %s: %s", path, err)
	}

	saveCert(path, derCert)
	saveKey(path, derKey)
	copyFile(filepath.Join(filepath.Dir(path), "ca.pem"), filepath.Join(path, "ca.pem"), publicPerms)
	infoLog.Printf("Finished Creating Certificate %s with Subject: %s\n", path, *dn)
}

func parseSubjectAlternativeNames(san string, template *x509.Certificate) {
	infoLog.Printf("Parsing Subject Alternative Names: %s\n", san)
	if san != "" {
		template.IPAddresses = []net.IP{}
		template.DNSNames = []string{}
		for _, h := range strings.Split(san, ",") {
			infoLog.Printf("Parsing %s\n", h)
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else if email := parseEmailAddress(h); email != nil {
				template.EmailAddresses = append(template.EmailAddresses, email.Address)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}
	}
}

// implemented as a seperate function because net.mail.ParseAddress
// panics on malformed addresses
func parseEmailAddress(address string) (email *mail.Address) {
	defer func() {
		if recover() != nil {
			email = nil
		}
	}()
	var err error
	email, err = mail.ParseAddress(address)
	if err == nil && email != nil {
		return email
	}
	return nil
}

func generatePrivateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, derKey, nil
}

func checkExisting(path string) {
	fullPath := filepath.Join(path, filepath.Base(path))
	const errMsg = "Skipping creation of %s because file %s already exists.\nUse the \"-overwrite\" option to overwrite the existing file."
	if _, err := os.Stat(fullPath + ".crt"); err == nil {
		errorLog.Fatalf(errMsg, path, "./"+fullPath+".crt")
	}
	if _, err := os.Stat(fullPath + ".crt"); err == nil {
		errorLog.Fatalf(errMsg, path, "./"+fullPath+".key")
	}
	if _, err := os.Stat(filepath.Join(path, "ca.pem")); err == nil {
		errorLog.Fatalf("Skipping creation of %s because file %s already exists.\nUse the \"-overwrite\" option to overwrite the existing file.", path, filepath.Join(path, "ca.pem"))
	}
}

func createDirectory(directory string) {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		var publicPerms os.FileMode = 0755
		if err := os.MkdirAll(directory, publicPerms); err != nil {
			errorLog.Fatalf("Error creating directory ./%s: %s", directory, err.Error())
		}
	}
}

func saveCert(directory string, derCert []byte) {
	createDirectory(directory)

	fileName := filepath.Join(directory, filepath.Base(directory)+".crt")

	infoLog.Printf("Saving %s\n", fileName)

	certFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, publicPerms)
	if err != nil {
		errorLog.Fatalf("Failed to open %s for writing: %s", fileName, err)
	}
	defer func() {
		if err := certFile.Close(); err != nil {
			errorLog.Fatalf("Failed to save %s: %s", fileName, err)
		}
	}()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derCert}); err != nil {
		errorLog.Fatalf("Failed to marshall %s: %s", fileName, err)
	}
	if filepath.Dir(directory) != "." {
		caFile, err := os.Open(filepath.Join(filepath.Dir(directory), filepath.Base(filepath.Dir(directory))) + ".crt")
		if err != nil {
			errorLog.Fatalf("Failed to open ca certificate: %s", err)
		}
		defer func() {
			if err = caFile.Close(); err != nil {
				errorLog.Fatalf("Failed to close %s: %s", filepath.Join(filepath.Dir(directory), filepath.Base(filepath.Dir(directory)))+".crt", err)
			}
		}()
		_, err = io.Copy(certFile, caFile)
		if err != nil {
			errorLog.Fatalf("Failed to concat ca certificates: %s", err)
		}
		err = certFile.Sync()
		if err != nil {
			errorLog.Fatalf("Failed to sync certificate file: %s", err)
		}
	}
}

func saveKey(directory string, derKey []byte) {

	fileName := filepath.Join(directory, filepath.Base(directory)+".key")

	infoLog.Printf("Saving %s\n", fileName)

	keyFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, privatePerms)
	if err != nil {
		errorLog.Fatalf("Failed to open %s for writing: %s", fileName, err)
	}
	defer func() {
		if err := keyFile.Close(); err != nil {
			errorLog.Fatalf("Failed to close %s: %s", fileName, err)
		}
	}()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey}); err != nil {
		errorLog.Fatalf("Failed to marshall %s: %s", fileName, err)
	}
}

func parseCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(filepath.Join(path, filepath.Base(path)+".crt"))
	if err != nil {
		errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(path, filepath.Base(path)+".crt"), err)
	}
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "CERTIFICATE" {
		errorLog.Fatalf("Failed to decode certificate %s: %s", filepath.Join(path, filepath.Base(path)+".crt"), err)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse certificate %s: %s", filepath.Join(path, filepath.Base(path)+".crt"), err)
	}
	return crt
}

func parseKey(path string) *ecdsa.PrivateKey {
	der, err := ioutil.ReadFile(filepath.Join(path, filepath.Base(path)+".key"))
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(path, filepath.Base(path)+".key"), err)
	}
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		errorLog.Fatalf("Failed to decode private key for %s: %s", filepath.Join(path, filepath.Base(path)+".key"), err)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse private key for %s: %s", filepath.Join(path, filepath.Base(path)+".key"), err)
	}
	return key
}

func parseDn(ca *x509.Certificate, dn string) *pkix.Name {
	infoLog.Printf("Parsing distinguished name: %s\n", dn)
	var caName pkix.Name
	if ca != nil {
		caName = ca.Subject
	} else {
		caName = pkix.Name{}
	}
	newName := &pkix.Name{}
	for _, element := range strings.Split(strings.Trim(dn, "/"), "/") {
		value := strings.Split(element, "=")
		if len(value) != 2 {
			errorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		switch strings.ToUpper(value[0]) {
		case "CN": // commonName
			newName.CommonName = value[1]
		case "C": // countryName
			if value[1] == "" {
				caName.Country = []string{}
			} else {
				newName.Country = append(newName.Country, value[1])
			}
		case "L": // localityName
			if value[1] == "" {
				caName.Locality = []string{}
			} else {
				newName.Locality = append(newName.Locality, value[1])
			}
		case "ST": // stateOrProvinceName
			if value[1] == "" {
				caName.Province = []string{}
			} else {
				newName.Province = append(newName.Province, value[1])
			}
		case "O": // organizationName
			if value[1] == "" {
				caName.Organization = []string{}
			} else {
				newName.Organization = append(newName.Organization, value[1])
			}
		case "OU": // organizationalUnitName
			if value[1] == "" {
				caName.OrganizationalUnit = []string{}
			} else {
				newName.OrganizationalUnit = append(newName.OrganizationalUnit, value[1])
			}
		default:
			errorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
		}
	}
	if ca != nil {
		newName.Country = append(caName.Country, newName.Country...)
		newName.Locality = append(caName.Locality, newName.Locality...)
		newName.Province = append(caName.Province, newName.Province...)
		newName.Organization = append(caName.Organization, newName.Organization...)
		newName.OrganizationalUnit = append(caName.OrganizationalUnit, newName.OrganizationalUnit...)
	}
	return newName
}

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

func copyFile(source string, dest string, perms os.FileMode) {
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
}

func readFile(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read file %s: %s", path, err)
	}
	return string(data)
}
