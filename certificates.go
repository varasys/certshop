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
	derCert, err := x509.CreateCertificate(rand.Reader, manifest.cert, manifest.signingCert, manifest.key.Public(), manifest.signingKey)
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
	baseName := filepath.Join(manifest.path, filepath.Base(manifest.path))
	manifest.saveKey(baseName + "-key.pem")
	manifest.saveCert(baseName + ".pem")
}

func (manifest *certManifest) saveCert(path string) {
	infoLog.Printf("Saving certificate: %s\n", filepath.Join(root, path))
	if err := ioutil.WriteFile(path, marshalCert(manifest.cert), os.FileMode(0644)); err != nil {
		errorLog.Fatalf("Failed to save certificate %s: %s", path, err)
	}
}

func (manifest *certManifest) saveKey(path string) {
	infoLog.Printf("Saving private key: %s\n", filepath.Join(root, path))
	if err := ioutil.WriteFile(path, marshalKey(manifest.key), os.FileMode(0600)); err != nil {
		errorLog.Fatalf("Failed to save private key %s: %s", path, err)
	}
}

func readCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(path, filepath.Base(path)+".crt"), err)
	}
	return unMarshalCert(der)
}

func readKey(path string) *ecdsa.PrivateKey {
	der, err := ioutil.ReadFile(path + "-key.pem")
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(path, filepath.Base(path)+".key"), err)
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
