package kubesec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
		checkExisting(filepath.Join(root, path))
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

func createCertificate(args []string, path string, defaultDn string, defaultValidity int, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage) {
	fs := flag.NewFlagSet("server", flag.PanicOnError)
	dn := fs.String("dn", defaultDn, "certificate subject")
	san := fs.String("san", "", "subject alternative names")
	validity := fs.Int("validity", defaultValidity, "certificate validity in days")
	overwrite := fs.Bool("overwrite", false, "overwrite any existing files")
	nolocalhost := fs.Bool("no-localhost", false, "do not include localhost Subject Alternative Names by default")

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
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:       []string{"localhost"},
	}

	if *nolocalhost {
		template.IPAddresses = []net.IP{}
		template.DNSNames = []string{}
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
	if _, err := os.Stat(fullPath + ".pem"); err == nil {
		errorLog.Fatalf(errMsg, path, fullPath+".pem")
	}
	if _, err := os.Stat(fullPath + "-key.pem"); err == nil {
		errorLog.Fatalf(errMsg, path, fullPath+"-key.pem")
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

	fileName := filepath.Join(directory, filepath.Base(directory)+".pem")

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
		caFile, err := os.Open(filepath.Join(filepath.Dir(directory), filepath.Base(filepath.Dir(directory))) + ".pem")
		if err != nil {
			errorLog.Fatalf("Failed to open ca certificate: %s", err)
		}
		defer func() {
			if err = caFile.Close(); err != nil {
				errorLog.Fatalf("Failed to close %s: %s", filepath.Join(filepath.Dir(directory), filepath.Base(filepath.Dir(directory)))+".pem", err)
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

	fileName := filepath.Join(directory, filepath.Base(directory)+"-key.pem")

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
