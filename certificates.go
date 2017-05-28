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

var (
	pemKeyHeader  = "EC PRIVATE KEY"
	pemCertHeader = "CERTIFICATE"
	pemCSRHeader  = "CERTIFICATE REQUEST"
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
	*string
	ip    []net.IP
	email []string
	dns   []string
}

type distName struct {
	*string
}

type privateKey struct {
	*ecdsa.PrivateKey
	pwd *password
}

type password struct {
	*string
}

type csrPath struct {
	*string
}

func (dn *distName) Get() interface{} {
	return dn.string
}

func (dn *distName) String() string {
	if dn.string != nil {
		return *dn.string
	}
	return ""
}

func (dn *distName) Set(val string) error {
	dn.string = &val
	return nil
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

func (path *csrPath) Get() interface{} {
	if path.string == nil {
		errorLog.Fatal("no csr source specified")
	}
	var (
		csr []byte
		err error
	)
	switch *path.string {
	case "": // read from stdin
		if csr, err = ioutil.ReadAll(os.Stdin); err != nil {
			errorLog.Fatal("Failed to read csr from stdin")
		}
	default: // read from a file
		if csr, err = ioutil.ReadFile(*path.string); err != nil {
			errorLog.Fatal("Failed to read csr from stdin")
		}
	}
	return csr
}

func (path *csrPath) String() string {
	if path.string != nil {
		return *path.string
	}
	return ""
}

func (path *csrPath) Set(val string) error {
	path.string = &val
	return nil
}

func (sans *sanList) Get() interface{} {
	return sans.string
}

func (sans *sanList) String() string {
	if sans != nil && sans.string != nil {
		return *sans.string
	}
	return ""
}

func newSanList(sans string) sanList {
	list := sanList{}
	_ = list.Set(sans)
	return list
}

func (sans *sanList) Set(val string) error {
	debugLog.Printf("Parsing Subject Alternative Names: %s\n", val)
	sans.string = &val
	for _, h := range strings.Split(val, ",") {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			concatIP(sans.ip, ip)
		} else if email := parseEmailAddress(h); email != nil {
			concatEmail(sans.email, email)
		} else {
			concatDNS(sans.dns, h)
		}
	}
	return nil
}

func concatIP(ipList []net.IP, vals ...interface{}) {
	list := ipList
ValLoop:
	for i := range vals {
		var ip net.IP
		switch vals[i].(type) {
		case string:
			if ip = net.ParseIP(strings.TrimSpace(vals[i].(string))); ip == nil {
				errorLog.Fatalf("Failed to parse ip: %s", vals[i])
			}
		case net.IP:
			ip = vals[i].(net.IP)
		default:
			errorLog.Fatalf("Failed to parse ip: %s", vals[i])
		}
		for j := range list {
			if list[j].Equal(ip) {
				continue ValLoop
			}
		}
		list = append(list, ip)
	}
}

func concatDNS(dnsList []string, vals ...string) {
	list := dnsList
ValLoop:
	for i := range vals {
		if vals[i] != "" {
			for j := range list {
				if list[j] == vals[i] {
					continue ValLoop
				}
			}
			list = append(list, vals[i])
		}
	}
}

func concatEmail(emailList []string, vals ...interface{}) {
	list := emailList
ValLoop:
	for i := range vals {
		var address *mail.Address
		switch vals[i].(type) {
		case string:
			address = parseEmailAddress(vals[i].(string))
		case mail.Address:
			tmp := vals[i].(mail.Address)
			address = &tmp
		default:
			errorLog.Fatalf("Failed to parse email: %s", vals[i])
		}
		for j := range list {
			if list[j] == address.String() {
				continue ValLoop
			}
		}
		list = append(list, address.String())
	}
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

func (dn distName) parseDN(template pkix.Name) pkix.Name {
	debugLog.Printf("Parsing Distinguished Name: %s\n", dn.String())
	template.CommonName = ""
	for _, element := range strings.Split(strings.Trim(dn.String(), "/"), "/") {
		pair := strings.Split(element, "=")
		if len(pair) != 2 {
			errorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		pair[0] = strings.ToUpper(pair[0])
		if pair[0] == "CN" {
			template.CommonName = pair[1]
		} else {
			value := []string{}
			if pair[1] != "" {
				value = append(value, pair[1])
			}
			switch pair[0] {
			case "C": // countryName
				template.Country = value
			case "L": // localityName
				template.Locality = value
			case "ST": // stateOrProvinceName
				template.Province = value
			case "O": // organizationName
				template.Organization = value
			case "OU": // organizationalUnitName
				template.OrganizationalUnit = value
			default:
				errorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
			}
		}
	}
	return template
}

func parseEmailAddress(address string) (email *mail.Address) {
	// implemented as a seperate function because net.mail.ParseAddress
	// panics instead of returning err on malformed addresses (appears to be a bug)
	defer func() {
		if recover() != nil {
			email = nil
		}
	}()
	email, err := mail.ParseAddress(strings.TrimSpace(address))
	if err != nil {
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
	saveKey(dest, manifest.privateKey, filepath.Join(manifest.path, "key.pem"))
	saveCSR(dest, manifest.CertificateRequest.Raw, filepath.Join(manifest.path, "csr.pem"))
}

func saveCSR(dest pkiWriter, der []byte, path string) {
	debugLog.Printf("Saving certificate signing request: %s\n", path)
	dest.writeData(marshalCSR(der), path, os.FileMode(0644), overwrite)
}

func readCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalCert(der)
}

func readKey(path string, pwd *password) *privateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(root, path), err)
	}
	return unMarshalKey(der, pwd)
}

// func readCSR(path string) *x509.CertificateRequest {
// 	der, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		errorLog.Fatalf("Failed to read certificate signing request file %s: %s", filepath.Join(root, path), err)
// 	}
// 	return unMarshalCSR(&der)
// }

func marshalCert(cert *x509.Certificate) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: pemCertHeader, Bytes: cert.Raw})
	return data
}

func unMarshalCert(der []byte) *x509.Certificate {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != pemCertHeader {
		errorLog.Fatal("Failed to decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errorLog.Fatalf("Failed to parse certificate: %s", err)
	}
	return crt
}

func marshalCSR(csr []byte) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: pemCSRHeader, Bytes: csr})
	return data
}

func unMarshalCSR(der []byte) *x509.CertificateRequest {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != pemCSRHeader {
		errorLog.Fatal("Failed to decode certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		errorLog.Fatal("Failed to parse certificate request")
	}
	return csr
}

func (key *privateKey) marshalKey() []byte {
	der, err := x509.MarshalECPrivateKey(key.PrivateKey)
	if err != nil {
		errorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if key.pwd.string == nil {
		data := pem.EncodeToMemory(&pem.Block{Type: pemKeyHeader, Bytes: der})
		return data
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, pemKeyHeader, der, []byte(*key.pwd.string), x509.PEMCipherAES256)
	if err != nil {
		errorLog.Fatalf("Failed to encrypt private key: %s", err)
	}
	data := pem.EncodeToMemory(block)
	return data
}

func unMarshalKey(der []byte, pwd *password) *privateKey {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != pemKeyHeader {
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
	block, _ = pem.Decode(der)
	if block == nil || block.Type != pemKeyHeader {
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
