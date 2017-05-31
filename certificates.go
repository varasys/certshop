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
	// KeyHeader is the private key pem header
	KeyHeader = `EC PRIVATE KEY`
	// CertHeader is the certificate pem header
	CertHeader = `CERTIFICATE`
	// CSRHeader is the certificate signing request pem header
	CSRHeader = `CERTIFICATE REQUEST`
)

// CertManifest holds information required to create a signed certificate
type CertManifest struct {
	Path string
	CA   *CertManifest
	*x509.Certificate
	*PrivateKey
	PublicKey *ecdsa.PublicKey
}

// CSRManifest holds information required to create a certificate
// signing request
type CSRManifest struct {
	Path string
	*x509.CertificateRequest
	*PrivateKey
}

// SANSet helds information about subject alternative names
type SANSet struct {
	ip    []net.IP
	email []string
	dns   []string
}

// ParseSAN parses a string listing the subject alternative names, along with
// if cn != NilString the cn will be included as a DNS Name. If local is
// true then "127.0.0.1,::1" will be included as ip addresses and "localhost"
// will be included as a DNS name. If localhost is true then the local
// hostname will alse be included as a DNS name.
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
	if cn != NilString {
		sanSet.AppendDNS(cn)
	}
	return sanSet
}

// AppendLocalSAN adds localhost entries to the san list excluding duplicate
// entries.
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

// AppendIP adds new IP addresses to the san list excluding duplicate entries.
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

// AppendEmail adds new email addresses to the san list excluding duplicate
// entries.
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

// AppendDNS adds new dns host names to the san list excluding duplicate entries.
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

// DistName holds the raw string format of the distinguished name
type DistName struct {
	string
}

// PrivateKey holds a private key and associated password
// the password value is NilString if no password
type PrivateKey struct {
	*ecdsa.PrivateKey
	pwd string
}

// Get implements Get() required by the flag.Value interface
func (dn *DistName) Get() interface{} {
	return dn.string
}

// String implements String() required by the flag.Value interface
func (dn *DistName) String() string {
	if dn.string != NilString {
		return dn.string
	}
	return ""
}

// Set implements Set() required by the flag.Value interface
func (dn *DistName) Set(val string) error {
	dn.string = val
	return nil
}

// ReadCSR reads a .pem format certificate request and returns the .der
// format bytes
func ReadCSR(path string) []byte {
	var csr []byte
	var err error
	switch path {
	case NilString:
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

// AppendExtKeyUsage appends a ExtKeyUsage bit excluding duplicates
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

// GenerateSerial returns a big random number (presumed to be globally unique)
// to be used as a certificate serial number
func GenerateSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		ErrorLog.Fatalf("Failed to generate serial number: %s", err)
	}
	return serial
}

// GenerateKey generates a new ecdsa-P384 private key
func GenerateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		ErrorLog.Fatalf("Failed to generate private key: %s", err)
	}
	return key
}

// ParseDN parses the dn string and returns a pkix.Name. Default values are
// copied from the template before parsing. If cn != NilString it ultimately
// overides the final cn value (this is a convienence to allow users to
// specify a cn without having to use the "/CN={}" format)
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
	if cn != NilString {
		template.CommonName = cn
	}
	return template
}

// KnownOIDs is a map of known oids and associated strings to be used in the
// -dn argument. Local name (2.5.4.41=emailAddress) is included specifically
// so digital signature certificates can identify an individuals name written
// in their local language (and the English version stored in the cn). Ideally
// digital signature certificates should include
// "/CN="English Name"/E="Email Addresss"/LN="Local Name" so this information
// is clearly presented.
var KnownOIDs = map[string][]int{
	"LN": []int{2, 5, 4, 41},                //local name
	"E":  []int{1, 2, 840, 113549, 1, 9, 1}, //email
}

// ParseOID converts a oid string (ie. "2.5.4.41") to an integer array
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

// ParseEmailAddress parses an email address and returns the address if
// successful, otherwise nil. This can parse both normal emails ("me@here.com")
// and also "Me Here <me@here.com>" format
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

// Sign signs a certificate
func (manifest *CertManifest) Sign() {
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

// Save saves a certificate and associated key to a PKIWriter
func (manifest *CertManifest) Save(dest PKIWriter) {
	baseName := filepath.Join(manifest.Path, filepath.Base(manifest.Path))
	if manifest.PrivateKey != nil {
		SaveKey(dest, manifest.PrivateKey, baseName+"-key.pem")
	}
	SaveCert(dest, manifest, baseName+".pem")
}

// SaveKey saves the private key
func SaveKey(dest PKIWriter, key *PrivateKey, path string) {
	DebugLog.Printf("Saving private key: %s\n", path)
	dest.WriteData(key.MarshalKey(), path, os.FileMode(0600))
}

// SaveCert saves the certificate
func SaveCert(dest PKIWriter, manifest *CertManifest, path string) {
	DebugLog.Printf("Saving certificate: %s\n", path)
	dest.WriteData(MarshalCert(manifest.Certificate), path, os.FileMode(0644))
}

// Save saves a certificate signing request and associated key to a PKIWwriter
func (manifest *CSRManifest) Save(dest PKIWriter) {
	SaveKey(dest, manifest.PrivateKey, filepath.Join(manifest.Path, "key.pem"))
	SaveCSR(dest, manifest.CertificateRequest.Raw, filepath.Join(manifest.Path, "csr.pem"))
}

// SaveCSR saves
func SaveCSR(dest PKIWriter, der []byte, path string) {
	DebugLog.Printf("Saving certificate signing request: %s\n", path)
	dest.WriteData(MarshalCSR(der), path, os.FileMode(0644))
}

// ReadCert reads a certificate from a file
func ReadCert(path string) *x509.Certificate {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		ErrorLog.Fatalf("Failed to read certificate file %s: %s", filepath.Join(Root, path), err)
	}
	return UnmarshalCert(der)
}

// ReadKey reads a private key from a file
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

// MarshalCert converts a x509.Certificate to a der encoded byte array
func MarshalCert(cert *x509.Certificate) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: CertHeader, Bytes: cert.Raw})
	return data
}

// UnmarshalCert cenverts a der encoded byte array to a x509.Certificate
func UnmarshalCert(der []byte) *x509.Certificate {
	block, _ := pem.Decode(der)
	if block == nil || block.Type != CertHeader {
		ErrorLog.Fatal("Failed to decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ErrorLog.Fatalf("Failed to parse certificate: %s", err)
	}
	return crt
}

// MarshalCSR converts a der encoded csr to a .pem format
func MarshalCSR(csr []byte) []byte {
	data := pem.EncodeToMemory(&pem.Block{Type: CSRHeader, Bytes: csr})
	return data
}

// UnmarshalCSR converts a der encoded csr to x509.CertificateRequest
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

// MarshalKey pem encodes a ecdsa.PrivateKey
func (key *PrivateKey) MarshalKey() []byte {
	der, err := x509.MarshalECPrivateKey(key.PrivateKey)
	if err != nil {
		ErrorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if key.pwd == NilString {
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

// UnmarshalKey pem decodes a private key to an ecdsa.PrivateKey
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

// DecryptPEM is a helper function to decrypt pem blocks
func DecryptPEM(block *pem.Block, pwd string) ([]byte, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	} else if pwd == NilString {
		return nil, errors.New("key is encrypted, but \"-pass-in=password\" flag not provided")
	}
	return x509.DecryptPEMBlock(block, []byte(pwd))
}

// LoadCACert is a helper function for loading a certificate
// from a file
func (manifest *CertManifest) LoadCACert() {
	if filepath.Dir(manifest.Path) != "." {
		file := filepath.Dir(manifest.Path)
		file = filepath.Join(file, filepath.Base(file))
		manifest.CA = &CertManifest{
			Path:        filepath.Dir(manifest.Path),
			Certificate: ReadCert(file + ".pem"),
		}
	} else {
		manifest.CA = manifest
	}
}

// LoadCertChain is used to chain ca certs to a subject cert
func (manifest *CertManifest) LoadCertChain() {
	if filepath.Dir(manifest.Path) != "." {
		manifest.LoadCACert()
		manifest.CA.LoadCertChain()
	}
}
