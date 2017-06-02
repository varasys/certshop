package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// SANSet helds information about subject alternative names
type SANSet struct {
	ip    []net.IP
	email []string
	dns   []string
}

// CertSet is the access point to the file backed certificate, request,
// and keys persistance manager.
type CertSet struct {
	Path               string
	certificate        *x509.Certificate
	key                *ecdsa.PrivateKey
	certificateRequest *x509.CertificateRequest
}

// Certificate return the x509.Certificate associated with the Path
// The certificate file will be loaded if not already
func (set *CertSet) Certificate() *x509.Certificate {
	if set.certificate == nil && filepath.Base(set.Path) != "." {
		set.certificate = ReadCert(filepath.Join(set.Path, filepath.Base(set.Path+".pem")))
	}
	return set.certificate
}

// Key return the ecdsa.PrivateKey associated with the Path
// The key file will be loaded if not already
func (set *CertSet) Key(pwd string) *ecdsa.PrivateKey {
	if set.key == nil && filepath.Base(set.Path) != "." {
		set.key = ReadKey(filepath.Join(set.Path, filepath.Base(set.Path+"-key.pem")), pwd)
	}
	return set.key
}

// CertificateRequest return the x509.CertificateRequest associated with the
// Path. The certificate request file will be loaded if not already
func (set *CertSet) CertificateRequest() *x509.CertificateRequest {
	if set.certificateRequest == nil && filepath.Base(set.Path) != "." {
		set.certificateRequest = ReadCSR(filepath.Join(set.Path, filepath.Base(set.Path+"-csr.pem")))
	}
	return set.certificateRequest
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

// ReadCSR reads a .pem format certificate request and returns the .der
// format bytes
func ReadCSR(path string) *x509.CertificateRequest {
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
	return UnmarshalCSR(csr)
}

// AppendExtKeyUsage appends a ExtKeyUsage bit excluding duplicates
func AppendExtKeyUsage(usages []x509.ExtKeyUsage, vals ...x509.ExtKeyUsage) []x509.ExtKeyUsage {
ValLoop:
	for i := range vals {
		for j := range usages {
			if vals[i] == usages[j] {
				continue ValLoop
			}
		}
		usages = append(usages, vals[i])
	}
	return usages
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
	if dn != NilString {
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
func (manifest *CertFlags) Sign() {
	manifest.SubjectCert.PublicKeyAlgorithm = x509.ECDSA
	manifest.SubjectCert.SignatureAlgorithm = x509.ECDSAWithSHA384
	der, err := x509.CreateCertificate(rand.Reader, manifest.SubjectCert, manifest.IssuingCert, manifest.SubjectCert.PublicKey, manifest.IssuingKey)
	if err != nil {
		ErrorLog.Fatalf("Failed to sign certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		ErrorLog.Fatalf("Failed to load signed certificate: %s", err)
	}
	manifest.SubjectCert = cert
}

//Sign signs a certificate request
func (manifest *CSRFlags) Sign() {
	der, err := x509.CreateCertificateRequest(rand.Reader, manifest.CertificateRequest, manifest.Key)
	if err != nil {
		ErrorLog.Fatalf("Failed to sign certificate request: %s", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		ErrorLog.Fatalf("Failed to load signed certificate request: %s", err)
	}
	manifest.CertificateRequest = csr
}

// Save saves a certificate and associated key to a PKIWriter
func (manifest *CertFlags) Save(dest PKIWriter) {
	baseName := filepath.Join(manifest.Path, filepath.Base(manifest.Path))
	if manifest.SubjectKey != nil {
		SaveKey(dest, manifest.SubjectKey, manifest.SubjectPass, baseName+"-key.pem")
	}
	SaveCert(dest, manifest.SubjectCert, baseName+".pem")
}

// SaveKey saves the private key
func SaveKey(dest PKIWriter, key *ecdsa.PrivateKey, pwd string, path string) {
	DebugLog.Printf("Saving private key: %s\n", path)
	dest.WriteData(MarshalKey(key, pwd), path, os.FileMode(0600))
}

// SaveCert saves the certificate
func SaveCert(dest PKIWriter, cert *x509.Certificate, path string) {
	DebugLog.Printf("Saving certificate: %s\n", path)
	dest.WriteData(MarshalCert(cert), path, os.FileMode(0644))
}

// Save saves a certificate signing request and associated key to a PKIWwriter
func (manifest *CSRFlags) Save(dest PKIWriter) {
	SaveKey(dest, manifest.Key, manifest.Password, filepath.Join(manifest.Path, "key.pem"))
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
func ReadKey(path string, pwd string) *ecdsa.PrivateKey {
	der, err := ioutil.ReadFile(path)
	if err != nil {
		ErrorLog.Fatalf("Failed to read private key file %s: %s", filepath.Join(Root, path), err)
	}
	return UnmarshalKey(der, pwd)
}

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
func MarshalKey(key *ecdsa.PrivateKey, pwd string) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		ErrorLog.Fatalf("Failed to marshal private key: %s", err)
	}
	if pwd == NilString {
		data := pem.EncodeToMemory(&pem.Block{Type: KeyHeader, Bytes: der})
		return data
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, KeyHeader, der, []byte(pwd), x509.PEMCipherAES256)
	if err != nil {
		ErrorLog.Fatalf("Failed to encrypt private key: %s", err)
	}
	data := pem.EncodeToMemory(block)
	return data
}

// UnmarshalKey pem decodes a private key to an ecdsa.PrivateKey
func UnmarshalKey(der []byte, pwd string) *ecdsa.PrivateKey {
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
	return key
}

// DecryptPEM is a helper function to decrypt pem blocks
func DecryptPEM(block *pem.Block, pwd string) ([]byte, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	} else if pwd == NilString {
		return nil, errors.New("key is encrypted, but password not provided")
	}
	return x509.DecryptPEMBlock(block, []byte(pwd))
}

// HashKeyID hashes an ecdsa.PublicKey for use as a certificate Subject ID
func HashKeyID(key *ecdsa.PublicKey) []byte {
	hash := sha1.Sum(MarshalKeyBitString(key).RightAlign())
	return hash[:]
}

// HashSHA256Fingerprint returns a sha-256 hash of a *x509.Certificate or
// *x509.CertificateRequest
func HashSHA256Fingerprint(entity interface{}) []byte {
	switch entity.(type) {
	case *x509.Certificate:
		hash := sha256.Sum256(entity.(*x509.Certificate).Raw)
		return hash[:]
	case *x509.CertificateRequest:
		hash := sha256.Sum256(entity.(*x509.CertificateRequest).Raw)
		return hash[:]
	default:
		ErrorLog.Fatalf(`Failed to hash fingerprint: unknown type`)
		return nil
	}
}

// HashSHA1Fingerprint returns a sha-1 hash of a *x509.Certificate or
// *x509.CertificateRequest
func HashSHA1Fingerprint(entity interface{}) []byte {
	switch entity.(type) {
	case *x509.Certificate:
		hash := sha1.Sum(entity.(*x509.Certificate).Raw)
		return hash[:]
	case *x509.CertificateRequest:
		hash := sha1.Sum(entity.(*x509.CertificateRequest).Raw)
		return hash[:]
	default:
		ErrorLog.Fatalf(`Failed to hash fingerprint: unknown type`)
		return nil
	}
}

// HashMD5Fingerprint returns a md5 hash of a *x509.Certificate or
// *x509.CertificateRequest
func HashMD5Fingerprint(entity interface{}) []byte {
	switch entity.(type) {
	case *x509.Certificate:
		hash := md5.Sum(entity.(*x509.Certificate).Raw)
		return hash[:]
	case *x509.CertificateRequest:
		hash := md5.Sum(entity.(*x509.CertificateRequest).Raw)
		return hash[:]
	default:
		ErrorLog.Fatalf(`Failed to hash fingerprint: unknown type`)
		return nil
	}
}

// MarshalKeyBitString extracts the asn1.BitString from the public key
func MarshalKeyBitString(key *ecdsa.PublicKey) asn1.BitString {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		ErrorLog.Fatalf(`Failed to marshal public key`)
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		ErrorLog.Fatalf(`Failed to unmarshal public key asn.1 bitstring`)
	}
	return publicKeyInfo.PublicKey
}
