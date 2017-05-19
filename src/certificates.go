package kubesec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type certManifest struct {
	path string // path of new certificate directory relative to root

	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	signingCert *x509.Certificate
	signingKey  *ecdsa.PrivateKey
}

func generateSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		errorLog.Fatalf("Failed to generate serial number: %s", err)
	}
	return serial
}

func generateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		errorLog.Fatalf("Failed to generate private key: %s", err)
	}
	return key
}

func parseDN(issuer pkix.Name, dn string) pkix.Name {
	infoLog.Printf("Parsing Distinguished Name: %s\n", dn)
	issuer.CommonName = ""
	for _, element := range strings.Split(strings.Trim(dn, "/"), "/") {
		value := strings.Split(element, "=")
		if len(value) != 2 {
			errorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		switch strings.ToUpper(value[0]) {
		case "CN": // commonName
			issuer.CommonName = value[1]
		case "C": // countryName
			if value[1] != "" {
				issuer.Country = value[1:1]
			} else {
				issuer.Country = nil
			}
		case "L": // localityName
			if value[1] != "" {
				issuer.Locality = value[1:1]
			} else {
				issuer.Locality = nil
			}
		case "ST": // stateOrProvinceName
			if value[1] != "" {
				issuer.Province = value[1:1]
			} else {
				issuer.Province = nil
			}
		case "O": // organizationName
			if value[1] != "" {
				issuer.Organization = value[1:1]
			} else {
				issuer.Organization = nil
			}
		case "OU": // organizationalUnitName
			if value[1] != "" {
				issuer.OrganizationalUnit = value[1:1]
			} else {
				issuer.OrganizationalUnit = nil
			}
		default:
			errorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
		}
	}
	if issuer.CommonName == "" {
		errorLog.Fatalf("Failed to parse common name from %s", dn)
	}
	return issuer
}

func (manifest *certManifest) parseSAN(sans string) {
	infoLog.Printf("Parsing Subject Alternative Names: %s\n", sans)
	for _, h := range strings.Split(sans, ",") {
		if ip := net.ParseIP(h); ip != nil {
			manifest.cert.IPAddresses = append(manifest.cert.IPAddresses, ip)
		} else if email := parseEmailAddress(h); email != nil {
			manifest.cert.EmailAddresses = append(manifest.cert.EmailAddresses, email.Address)
		} else {
			manifest.cert.DNSNames = append(manifest.cert.DNSNames, h)
		}
	}
}

func parseEmailAddress(address string) (email *mail.Address) {
	// implemented as a seperate function because net.mail.ParseAddress
	// panics on malformed addresses (appears to be a bug)
	defer func() {
		if recover() != nil {
			email = nil
		}
	}()
	email, err := mail.ParseAddress(address)
	if err != nil || email == nil {
		email = nil
	}
	return
}

func (manifest *certManifest) sign() {
	//manifest.cert.SignatureAlgorithm = x509.ECDSAWithSHA384
	derCert, err := x509.CreateCertificate(rand.Reader, manifest.cert, manifest.signingCert, manifest.key.PublicKey, manifest.signingKey)
	if err != nil {
		errorLog.Fatalf("Failed to sign certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		errorLog.Fatalf("Failed to load signed certificate: %s", err)
	}
	manifest.cert = cert
}

func (manifest *certManifest) save() {
	baseName := filepath.Base(manifest.path)
	manifest.saveCert(filepath.Join(manifest.path, baseName+".pem"))
	manifest.saveKey(filepath.Join(manifest.path, baseName+"-key.pem"))
	manifest.saveCA(filepath.Join(manifest.path, "ca.pem"))
}

func (manifest *certManifest) saveCert(path string) {
	infoLog.Printf("Saving %s\n", filepath.Join(root, path))
	file, err := os.OpenFile(path, fileCreateFlags, publicPerms)
	if err != nil {
		errorLog.Fatalf("Failed to open file %s for writing: %s", filepath.Join(root, path), err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			errorLog.Fatalf("Failed to close file %s after writing: %s", filepath.Join(root, path), err)
		}
	}()
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: manifest.cert.Raw}); err != nil {
		errorLog.Fatalf("Failed to pem encode %s: %s", filepath.Join(root, path), err)
	}
	if _, err := file.Write(concatCAs(filepath.Dir(manifest.path)).Bytes()); err != nil {
		errorLog.Fatalf("Failed to concat CAs %s: %s", filepath.Join(root, path), err)
	}
}

func (manifest *certManifest) saveKey(path string) {
	infoLog.Printf("Saving %s\n", filepath.Join(root, path))
	file, err := os.OpenFile(path, fileCreateFlags, privatePerms)
	if err != nil {
		errorLog.Fatalf("Failed to open file %s for writing: %s", filepath.Join(root, path), err)
	}
	defer func() {
		if err = file.Close(); err != nil {
			errorLog.Fatalf("Failed to close file %s after writing: %s", path, err)
		}
	}()
	der, err := x509.MarshalECPrivateKey(manifest.key)
	if err != nil {
		errorLog.Fatalf("Failed to der encode private key %s: %s", path, err)
	}
	if err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		errorLog.Fatalf("Failed to pem encode private key %s: %s", path, err)
	}
}

func (manifest *certManifest) saveCA(path string) {
	var data []byte
	var err error
	switch {
	case manifest.path == "ca": // do nothing; it is a self signed cert named "ca", so ca.pem already exists
		return
	case filepath.Dir(manifest.path) == ".": // this is a root ca, so just copy the certificate to ca.pem
		data, err = ioutil.ReadFile(filepath.Join(root, manifest.path, filepath.Base(manifest.path)+".pem"))
		if err != nil {
			errorLog.Fatalf("Error reading %s: %s", filepath.Join(root, manifest.path, filepath.Base(manifest.path)+".pem"), err)
		}
	case filepath.Base(manifest.path) == "ca": // required to avoid case where certificate and it's ca have the same file name (unless it is self signed)
		errorLog.Fatalf("Error creating %s: certs that are not self-signed can't be named \"ca\".", path)
	default: // concat all certs in manifest.path
		data = concatCAs(manifest.path).Bytes()
	}
	if err = ioutil.WriteFile(path, data, publicPerms); err != nil {
		errorLog.Fatalf("Error writing %s: %s", path, err)
	}
}

func readCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
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

func readKey(path string) *ecdsa.PrivateKey {
	der, err := ioutil.ReadFile(path + "-key.pem")
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

func concatCAs(path string) *bytes.Buffer {
	var buf *bytes.Buffer
	for file := filepath.Dir(path); file != "."; file = filepath.Dir(file) {
		der, err := ioutil.ReadFile(path)
		if err != nil {
			errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(root, path, filepath.Base(path)+".crt"), err)
		}
		block, _ := pem.Decode(der)
		if block == nil || block.Type != "CERTIFICATE" {
			errorLog.Fatalf("Failed to decode certificate %s: %s", filepath.Join(root, path, filepath.Base(path)+".crt"), err)
		}
		if pem.Encode(buf, block) != nil {
			errorLog.Fatalf("Failed to encode certificate %s: %s", filepath.Join(root, path, filepath.Base(path)+".crt"), err)
		}
	}
	return buf
}
