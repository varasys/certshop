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
	path string // path of new certificate directory relative to root

	ca *certManifest
	*x509.Certificate
	*privateKey
}

type csrManifest struct {
	path string

	*x509.CertificateRequest
	*privateKey
}

type sanList struct {
	ip    []net.IP
	email []string
	dns   []string
}

type privateKey struct {
	*ecdsa.PrivateKey
	password string
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

func parseSANs(sans *string) *sanList {
	debugLog.Printf("Parsing Subject Alternative Names: %s\n", *sans)
	result := sanList{}
	for _, h := range strings.Split(*sans, ",") {
		if ip := net.ParseIP(h); ip != nil {
			result.ip = append(result.ip, ip)
		} else if email := parseEmailAddress(h); email != nil {
			result.email = append(result.email, email.Address)
		} else {
			result.dns = append(result.dns, h)
		}
	}
	return &result
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
	der, err := x509.CreateCertificate(rand.Reader, manifest.Certificate, manifest.ca.Certificate, manifest.Public(), manifest.ca.PrivateKey)
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
	saveKey(dest, manifest.privateKey, baseName+"-key.pem")
	saveCert(dest, manifest, baseName+".pem")
}

func saveKey(dest pkiWriter, key *privateKey, path string) {
	debugLog.Printf("Saving private key: %s\n", path)
	dest.writeData(key.marshalKey(), path, os.FileMode(0600), overwrite)
}

func saveCert(dest pkiWriter, manifest *certManifest, path string) {
	debugLog.Printf("Saving certificate: %s\n", path)
	data := []byte{}
	for manifest != nil && manifest.path != "." {
		data = append(data, *marshalCert(manifest.Certificate)...)
		manifest = manifest.ca
	}
	dest.writeData(&data, path, os.FileMode(0644), overwrite)
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

func readKey(path string, password string) *privateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalKey(&der, password)
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

func unMarshalCSR(csr *[]byte) *[]byte {
	block, _ := pem.Decode(*csr)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		errorLog.Fatal("Failed to decode certificate request")
	}
	return &(block.Bytes)
}

func (key *privateKey) marshalKey() *[]byte {
	der, err := x509.MarshalECPrivateKey(key.PrivateKey)
	if err != nil {
		errorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if key.password == "" {
		data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return &data
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte(key.password), x509.PEMCipherAES256)
	if err != nil {
		errorLog.Fatalf("Failed to encrypt private key: %s", err)
	}
	data := pem.EncodeToMemory(block)
	return &data
}

func unMarshalKey(der *[]byte, password string) *privateKey {
	if password == "" {
		block, _ := pem.Decode(*der)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			errorLog.Fatal("Failed to decode private key")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			if x509.IsEncryptedPEMBlock(block) {
				errorLog.Fatal("Failed to parse private key: key is encrypted but no password provided")
			}
			errorLog.Fatalf("Failed to parse private key: %s", err)
		}
		return &privateKey{PrivateKey: key}
	}
	block, _ := pem.Decode(*der)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		errorLog.Fatal("Failed to decode private key")
	}
	dec, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		errorLog.Fatalf("Failed to decrypt private key: %s", err)
	}
	key, err := x509.ParseECPrivateKey(dec)
	if err != nil {
		errorLog.Fatalf("Failed to parse decrypted private key: %s", err)
	}
	return &privateKey{PrivateKey: key}
}

func (manifest *certManifest) loadCertChain() {
	if filepath.Dir(manifest.path) != "." {
		file := filepath.Dir(manifest.path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.ca = &certManifest{
			path:        filepath.Dir(manifest.path),
			Certificate: readCert(file + ".pem"),
		}
		manifest.ca.loadCertChain()
	}
}
