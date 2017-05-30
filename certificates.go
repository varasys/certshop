package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	KeyHeader = `EC PRIVATE KEY`
	CRTHeader = `CERTIFICATE`
	CSRHeader = `CERTIFICATE REQUEST`
)

type CRTManifest struct {
	Path string
	CA   *CRTManifest
	*x509.Certificate
	*PrivateKey
	PublicKey *ecdsa.PublicKey
}

type CSRManifest struct {
	Path string
	*x509.CertificateRequest
	*PrivateKey
}

type SANSet struct {
	ip    []net.IP
	email []string
	dns   []string
}

func ParseSAN(san string, cn string, local, localhost bool) *SANSet {
	sanSet := &SANSet{[]net.IP{}, []string{}, []string{}}
	if local || localhost {
		sanSet.AppendIP(`127.0.0.1`, `::1`)
		sanSet.AppendDNS(`localhost`)
	}
	if localhost {
		if host, err := os.Hostname(); err != nil {
			ErrorLog.Fatalf("Failed to get local hostname: %s", err)
		} else {
			sanSet.AppendDNS(host)
		}
	}
	if cn != nilString {
		sanSet.AppendDNS(cn)
	}
	return sanSet
}

func (set *SANSet) AppendLocalSAN(hostname bool) {
	set.AppendIP(`127.0.0.1`, `::1`)
	set.AppendDNS(`localhost`)
	if hostname {
		if host, err := os.Hostname(); err != nil {
			ErrorLog.Fatalf("failed to append localhost to sans: %s", err)
		} else {
			set.AppendDNS(host)
		}
	}
}

func (set *SANSet) AppendIP(vals ...interface{}) {
OuterLoop:
	for i := range vals {
		var ip net.IP
		switch vals[i].(type) {
		case string:
			if ip = net.ParseIP(strings.TrimSpace(vals[i].(string))); ip == nil {
				ErrorLog.Fatalf("Failed to parse ip address: %s", vals[i])
			}
		case net.IP:
			// do nothing
		default:
			ErrorLog.Fatalf("Failed to parse ip address: %s", vals[i])
		}
		for j := range set.ip {
			if set.ip[j].Equal(ip) {
				continue OuterLoop
			}
		}
		set.ip = append(set.ip, ip)
	}
}

func (set *SANSet) AppendEmail(vals ...interface{}) {
ValLoop:
	for i := range vals {
		var address *mail.Address
		switch vals[i].(type) {
		case string:
			address = ParseEmailAddress(vals[i].(string))
		case mail.Address:
			tmp := vals[i].(mail.Address)
			address = &tmp
		default:
			ErrorLog.Fatalf("Failed to parse email: %s", vals[i])
		}
		for j := range set.email {
			if set.email[j] == address.String() {
				continue ValLoop
			}
		}
		set.email = append(set.email, address.String())
	}
}

func (set *SANSet) AppendDNS(vals ...string) {
OuterLoop:
	for i := range vals {
		vals[i] = strings.TrimSpace(vals[i])
		for j := range set.dns {
			if set.dns[j] == vals[i] {
				continue OuterLoop
			}
		}
		set.dns = append(set.dns, vals[i])
	}
}

type DistName struct {
	string
}

type PrivateKey struct {
	*ecdsa.PrivateKey
	pwd string
}

func (dn *DistName) Get() interface{} {
	return dn.string
}

func (dn *DistName) String() string {
	if dn.string != nilString {
		return dn.string
	}
	return ""
}

func (dn *DistName) Set(val string) error {
	dn.string = val
	return nil
}

func ReadCSR(path string) []byte {
	var csr []byte
	var err error
	switch path {
	case nilString:
		ErrorLog.Fatal("no csr source specified")
	case "": // read from stdin
		if csr, err = ioutil.ReadAll(os.Stdin); err != nil {
			ErrorLog.Fatalf("Failed to read csr from stdin: %s", err)
		}
	default: // read from a file
		if csr, err = ioutil.ReadFile(path); err != nil {
			ErrorLog.Fatalf("Failed to read csr from %s: %s", path, err)
		}
	}
	return csr
}

func AppendExtKeyUsage(usages []x509.ExtKeyUsage, vals ...x509.ExtKeyUsage) {
ValLoop:
	for i := range vals {
		for j := range usages {
			if vals[i] == usages[j] {
				continue ValLoop
			}
		}
		usages = append(usages, vals[i])
	}
}

func GenerateSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		ErrorLog.Fatalf("Failed to generate serial number: %s", err)
	}
	return serial
}

func GenerateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		ErrorLog.Fatalf("Failed to generate private key: %s", err)
	}
	return key
}

func ParseDN(template pkix.Name, dn string, cn string) pkix.Name {
	DebugLog.Printf("Parsing Distinguished Name: %s\n", dn)
	template.CommonName = ""
	for _, element := range strings.Split(strings.Trim(dn, "/"), "/") {
		pair := strings.Split(element, "=")
		if len(pair) != 2 {
			ErrorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		pair[0] = strings.ToUpper(strings.TrimSpace(pair[0]))
		pair[1] = strings.TrimSpace(pair[1])
		if pair[0] == "CN" {
			template.CommonName = pair[1]
		} else if pair[0] == "LN" { // local name
			template.ExtraNames = append(template.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 41},
				Value: pair[1],
			})
		} else if pair[0] == "E" { // email address
			template.ExtraNames = append(template.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{1, 2, 840, 113549, 1, 9, 1},
				Value: pair[1],
			})
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
				if oid := KnownOIDs[pair[0]]; oid != nil {
					template.ExtraNames = append(template.ExtraNames, pkix.AttributeTypeAndValue{
						Type:  oid,
						Value: pair[1],
					})
				} else if oid := ParseOID(pair[0]); oid != nil {
					template.ExtraNames = append(template.ExtraNames, pkix.AttributeTypeAndValue{
						Type:  oid,
						Value: pair[1],
					})
				}
				ErrorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
			}
		}
	}
	if cn != nilString {
		template.CommonName = cn
	}
	return template
}

var KnownOIDs = map[string][]int{
	"LN": []int{2, 5, 4, 41},                //local name
	"E":  []int{1, 2, 840, 113549, 1, 9, 1}, //email
}

func ParseOID(oidString string) (oid []int) {
	elements := strings.Split(oidString, ".")
	oid = make([]int, len(elements))
	var err error
	for i := range elements {
		if oid[i], err = strconv.Atoi(elements[i]); err != nil {
			return nil
		}
	}
	return oid
}

func ParseEmailAddress(address string) (email *mail.Address) {
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

func (manifest *CRTManifest) sign() {
	manifest.PublicKeyAlgorithm = x509.ECDSA
	manifest.SignatureAlgorithm = x509.ECDSAWithSHA384
	der, err := x509.CreateCertificate(rand.Reader, manifest.Certificate, manifest.CA.Certificate, manifest.PublicKey, manifest.CA.PrivateKey)
	if err != nil {
		ErrorLog.Fatalf("Failed to sign certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		ErrorLog.Fatalf("Failed to load signed certificate: %s", err)
	}
	manifest.Certificate = cert
}

func (manifest *CRTManifest) Save(dest pkiWriter) {
	baseName := filepath.Join(manifest.Path, filepath.Base(manifest.Path))
	if manifest.PrivateKey != nil {
		SaveKey(dest, manifest.PrivateKey, baseName+"-key.pem")
	}
	SaveCert(dest, manifest, baseName+".pem")
}

func SaveKey(dest pkiWriter, key *PrivateKey, path string) {
	DebugLog.Printf("Saving private key: %s\n", path)
	dest.writeData(key.MarshalKey(), path, os.FileMode(0600))
}

func SaveCert(dest pkiWriter, manifest *CRTManifest, path string) {
	DebugLog.Printf("Saving certificate: %s\n", path)
	dest.writeData(MarshalCert(manifest.Certificate), path, os.FileMode(0644))
}

func (manifest *CSRManifest) Save(dest pkiWriter) {
	SaveKey(dest, manifest.PrivateKey, filepath.Join(manifest.Path, "key.pem"))
	SaveCSR(dest, manifest.CertificateRequest.Raw, filepath.Join(manifest.Path, "csr.pem"))
}

func SaveCSR(dest pkiWriter, der []byte, path string) {
	DebugLog.Printf("Saving certificate signing request: %s\n", path)
	dest.writeData(MarshalCSR(der), path, os.FileMode(0644))
}

func ReadCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		ErrorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(Root, path), err)
	}
	return UnmarshalCert(der)
}

func ReadKey(path string, pwd string) *PrivateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		ErrorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(Root, path), err)
	}
	return UnmarshalKey(der, pwd)
}

// func readCSR(path string) *x509.CertificateRequest {
// 	der, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		errorLog.Fatalf("Failed to read certificate signing request file %s: %s", filepath.Join(root, path), err)
// 	}
// 	return unMarshalCSR(&der)
// }

func MarshalCert(cert *x509.Certificate) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: CRTHeader, Bytes: cert.Raw})
	return data
}

func UnmarshalCert(der []byte) *x509.Certificate {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != CRTHeader {
		ErrorLog.Fatal("Failed to decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ErrorLog.Fatalf("Failed to parse certificate: %s", err)
	}
	return crt
}

func MarshalCSR(csr []byte) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: CSRHeader, Bytes: csr})
	return data
}

func UnmarshalCSR(der []byte) *x509.CertificateRequest {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != CSRHeader {
		ErrorLog.Fatal("Failed to decode certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		ErrorLog.Fatal("Failed to parse certificate request")
	}
	return csr
}

func (key *PrivateKey) MarshalKey() []byte {
	der, err := x509.MarshalECPrivateKey(key.PrivateKey)
	if err != nil {
		ErrorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if key.pwd == nilString {
		data := pem.EncodeToMemory(&pem.Block{Type: KeyHeader, Bytes: der})
		return data
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, KeyHeader, der, []byte(key.pwd), x509.PEMCipherAES256)
	if err != nil {
		ErrorLog.Fatalf("Failed to encrypt private key: %s", err)
	}
	data := pem.EncodeToMemory(block)
	return data
}

func UnmarshalKey(der []byte, pwd string) *PrivateKey {
	var err error
	var key *ecdsa.PrivateKey
	block, _ := pem.Decode(der)
	if block == nil || block.Type != KeyHeader {
		ErrorLog.Fatal("Failed to decode private key pem block")
	}
	if der, err = DecryptPEM(block, pwd); err != nil {
		ErrorLog.Fatalf("Failed to decrypt private key: %s", err)
	}
	if key, err = x509.ParseECPrivateKey(der); err != nil {
		ErrorLog.Fatalf("Failed to parse private key: %s", err)
	}
	return &PrivateKey{PrivateKey: key, pwd: pwd}
}

func DecryptPEM(block *pem.Block, pwd string) ([]byte, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	} else if pwd == nilString {
		return nil, errors.New("key is encrypted, but \"-pass-in=password\" flag not provided")
	}
	return x509.DecryptPEMBlock(block, []byte(pwd))
}

func (manifest *CRTManifest) LoadCACert() {
	if filepath.Dir(manifest.Path) != "." {
		file := filepath.Dir(manifest.Path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.CA = &CRTManifest{
			Path:        filepath.Dir(manifest.Path),
			Certificate: ReadCert(file + ".pem"),
		}
	} else {
		manifest.CA = manifest
	}
}

func (manifest *CRTManifest) LoadCertChain() {
	if filepath.Dir(manifest.Path) != "." {
		manifest.LoadCACert()
		manifest.CA.LoadCertChain()
	}
}
