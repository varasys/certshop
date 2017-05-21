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
	*ecdsa.PrivateKey
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

func parseDN(issuer pkix.Name, dn string) pkix.Name {
	debugLog.Printf("Parsing Distinguished Name: %s\n", dn)
	issuer.CommonName = ""
	for _, element := range strings.Split(strings.Trim(dn, "/"), "/") {
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
		errorLog.Fatalf("Failed to parse common name from %s", dn)
	}
	return issuer
}

func (manifest *certManifest) parseSAN(sans string) {
	debugLog.Printf("Parsing Subject Alternative Names: %s\n", sans)
	for _, h := range strings.Split(sans, ",") {
		if ip := net.ParseIP(h); ip != nil {
			manifest.IPAddresses = append(manifest.IPAddresses, ip)
		} else if email := parseEmailAddress(h); email != nil {
			manifest.EmailAddresses = append(manifest.EmailAddresses, email.Address)
		} else {
			manifest.DNSNames = append(manifest.DNSNames, h)
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

func (manifest *certManifest) save() {
	baseName := filepath.Join(manifest.path, filepath.Base(manifest.path))
	manifest.saveKey(baseName + "-key.pem")
	manifest.saveCert(baseName + ".pem")
}

func (manifest *certManifest) saveCert(path string) {
	debugLog.Printf("Saving certificate: %s\n", filepath.Join(root, path))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, os.FileMode(0644))
	if err != nil {
		errorLog.Fatalf("Failed to open %s for writing: %s", filepath.Join(root, path), err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			errorLog.Fatalf("Failed to close %s: %s", filepath.Join(root, path), err)
		}
	}()
	for manifest != nil && manifest.path != "." {
		if _, err := file.Write(marshalCert(manifest.Certificate)); err != nil {
			errorLog.Fatalf("Failed to concat certificate %s: %s", filepath.Join(root, manifest.path), err)
		}
		manifest = manifest.ca
	}
}

func (manifest *certManifest) saveKey(path string) {
	debugLog.Printf("Saving private key: %s\n", filepath.Join(root, path))
	if err := ioutil.WriteFile(path, marshalKey(manifest.PrivateKey), os.FileMode(0600)); err != nil {
		errorLog.Fatalf("Failed to save private key %s: %s", path, err)
	}
}

func readCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalCert(der)
}

func readKey(path string) *ecdsa.PrivateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalKey(der)
}

func marshalCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func unMarshalCert(der []byte) *x509.Certificate {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "CERTIFICATE" {
		errorLog.Fatal("Failed to decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse certificate: %s", err)
	}
	return crt
}

func marshalKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		errorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func unMarshalKey(der []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		errorLog.Fatal("Failed to decode private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse private key: %s", err)
	}
	return key
}

func (manifest *certManifest) loadCertChain(includeKey bool) {
	if filepath.Dir(manifest.path) != "." {
		file := filepath.Dir(manifest.path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.ca = &certManifest{
			path:        filepath.Dir(manifest.path),
			Certificate: readCert(file + ".pem"),
		}
		if includeKey {
			manifest.ca.PrivateKey = readKey(file + "-key.pem")
		}
		manifest.ca.loadCertChain(false)
	}
}
