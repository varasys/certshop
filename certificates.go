package main

import (
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

type certManifest struct {
	path string

	ca *certManifest
	*x509.Certificate
	*privateKey
	publicKey *ecdsa.PublicKey
}

type csrManifest struct {
	path string

	*x509.CertificateRequest
	*privateKey
}

type sanList struct {
	sans  *string
	ip    []net.IP
	email []string
	dns   []string
}

type privateKey struct {
	*ecdsa.PrivateKey
	pwd *password
}

type password struct {
	*string
}

func (pwd *password) Get() interface{} {
	return pwd.String
}

func (pwd *password) String() string {
	if pwd.string != nil {
		return *pwd.string
	}
	return ""
}

func (pwd *password) Set(val string) error {
	pwd.string = &val
	return nil
}

func (sans *sanList) Get() interface{} {
	return sans
}

func (sans *sanList) String() string {
	if sans.sans != nil {
		return *sans.sans
	}
	return ""
}

func (sans *sanList) Set(val string) error {
	debugLog.Printf("Parsing Subject Alternative Names: %s\n", val)
	sans.sans = &val
	for _, h := range strings.Split(val, ",") {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			sans.ip = append(sans.ip, ip)
		} else if email := parseEmailAddress(h); email != nil {
			sans.email = append(sans.email, email.Address)
		} else {
			sans.dns = append(sans.dns, h)
		}
	}
	return nil
}

func generateSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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

func parseDN(issuer pkix.Name, dn *string) *pkix.Name {
	debugLog.Printf("Parsing Distinguished Name: %s\n", *dn)
	issuer.CommonName = ""
	for _, element := range strings.Split(strings.Trim(*dn, "/"), "/") {
		pair := strings.Split(element, "=")
		if len(pair) != 2 {
			errorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		pair[0] = strings.ToUpper(pair[0])
		if pair[0] == "CN" {
			issuer.CommonName = pair[1]
		} else {
			value := []string{}
			if pair[1] != "" {
				value = append(value, pair[1])
			}
			switch pair[0] {
			case "C": // countryName
				issuer.Country = value
			case "L": // localityName
				issuer.Locality = value
			case "ST": // stateOrProvinceName
				issuer.Province = value
			case "O": // organizationName
				issuer.Organization = value
			case "OU": // organizationalUnitName
				issuer.OrganizationalUnit = value
			default:
				errorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
			}
		}
	}
	if issuer.CommonName == "" {
		errorLog.Fatalf("Failed to parse common name from %s", *dn)
	}
	return &issuer
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
	manifest.PublicKeyAlgorithm = x509.ECDSA
	manifest.SignatureAlgorithm = x509.ECDSAWithSHA384
	der, err := x509.CreateCertificate(rand.Reader, manifest.Certificate, manifest.ca.Certificate, manifest.publicKey, manifest.ca.PrivateKey)
	if err != nil {
		errorLog.Fatalf("Failed to sign certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		errorLog.Fatalf("Failed to load signed certificate: %s", err)
	}
	manifest.Certificate = cert
}

func (manifest *certManifest) save(dest pkiWriter) {
	baseName := filepath.Join(manifest.path, filepath.Base(manifest.path))
	if manifest.privateKey != nil {
		saveKey(dest, manifest.privateKey, baseName+"-key.pem")
	}
	saveCert(dest, manifest, baseName+".pem")
}

func saveKey(dest pkiWriter, key *privateKey, path string) {
	debugLog.Printf("Saving private key: %s\n", path)
	dest.writeData(key.marshalKey(), path, os.FileMode(0600), overwrite)
}

func saveCert(dest pkiWriter, manifest *certManifest, path string) {
	debugLog.Printf("Saving certificate: %s\n", path)
	dest.writeData(marshalCert(manifest.Certificate), path, os.FileMode(0644), overwrite)
}

func (manifest *csrManifest) save(dest pkiWriter) {
	var baseName string
	if manifest.path == "" {
		baseName = "csr"
	} else {
		baseName = filepath.Join(manifest.path, filepath.Base(manifest.path))
	}
	saveKey(dest, manifest.privateKey, baseName+"-key.pem")
	saveCSR(dest, &(manifest.CertificateRequest.Raw), baseName+"-csr.pem")
}

func saveCSR(dest pkiWriter, der *[]byte, path string) {
	debugLog.Printf("Saving certificate signing request: %s\n", path)
	dest.writeData(marshalCSR(der), path, os.FileMode(0644), overwrite)
}

func readCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalCert(&der)
}

func readKey(path string, pwd *password) *privateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalKey(&der, pwd)
}

func readCSR(path string) *x509.CertificateRequest {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read certificate signing request file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalCSR(&der)
}

func marshalCert(cert *x509.Certificate) *[]byte {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &data
}

func unMarshalCert(der *[]byte) *x509.Certificate {
	block, _ := pem.Decode(*der)
	if block == nil || block.Type != "CERTIFICATE" {
		errorLog.Fatal("Failed to decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse certificate: %s", err)
	}
	return crt
}

func marshalCSR(csr *[]byte) *[]byte {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: *csr})
	return &data
}

func unMarshalCSR(der *[]byte) *x509.CertificateRequest {
	block, _ := pem.Decode(*der)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		errorLog.Fatal("Failed to decode certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		errorLog.Fatal("Failed to parse certificate request")
	}
	return csr
}

func (key *privateKey) marshalKey() *[]byte {
	der, err := x509.MarshalECPrivateKey(key.PrivateKey)
	if err != nil {
		errorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if key.pwd.string == nil {
		data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return &data
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte(*key.pwd.string), x509.PEMCipherAES256)
	if err != nil {
		errorLog.Fatalf("Failed to encrypt private key: %s", err)
	}
	data := pem.EncodeToMemory(block)
	return &data
}

func unMarshalKey(der *[]byte, pwd *password) *privateKey {
	block, _ := pem.Decode(*der)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		errorLog.Fatal("Failed to decode private key")
	}
	isEncrypted := x509.IsEncryptedPEMBlock(block)
	if isEncrypted && pwd.string == nil {
		errorLog.Fatalln("Failed to decrypt private key: key is encrypted but no password was provided")
	} else if !isEncrypted && pwd.string != nil {
		errorLog.Fatalln("Failed to decode private key: key is not encrypted but a password was provided")
	}
	if pwd.string == nil {
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			errorLog.Fatalf("Failed to parse private key: %s", err)
		}
		return &privateKey{PrivateKey: key}
	}
	block, _ = pem.Decode(*der)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		errorLog.Fatal("Failed to decode private key")
	}
	dec, err := x509.DecryptPEMBlock(block, []byte(*pwd.string))
	if err != nil {
		errorLog.Fatalf("Failed to decrypt private key: %s", err)
	}
	key, err := x509.ParseECPrivateKey(dec)
	if err != nil {
		errorLog.Fatalf("Failed to parse decrypted private key: %s", err)
	}
	return &privateKey{PrivateKey: key, pwd: pwd}
}

func (manifest *certManifest) loadCACert() {
	if filepath.Dir(manifest.path) != "." {
		file := filepath.Dir(manifest.path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.ca = &certManifest{
			path:        filepath.Dir(manifest.path),
			Certificate: readCert(file + ".pem"),
		}
	} else {
		manifest.ca = manifest
	}
}

func (manifest *certManifest) loadCertChain() {
	if filepath.Dir(manifest.path) != "." {
		manifest.loadCACert()
		manifest.ca.loadCertChain()
	}
}
