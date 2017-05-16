package kubesec

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
	"flag"
	"strings"
	"os"
	"path/filepath"
)



func createCA2(args []string, path string, defaultDn string, defaultValidity time.Duration) {
	fs := flag.NewFlagSet("sub", flag.PanicOnError)
	dn := fs.String("dn", defaultDn, "certificate subject")
	maxPathLength := fs.Int("maxPathLength", 0, "max path length")
	validity := fs.Duration("validity", defaultValidity, "certificate validity duration")
	overwrite := fs.Bool("overwrite", false, "overwrite any existing files")

	err := fs.Parse(args)
	if err != nil {
		errorLog.Fatalf("Failed to parse ca sub-command arguments: %s", err)
	}

	if len(fs.Args()) > 1 {
		errorLog.Fatalf("Invalid path %s", strings.Join(fs.Args(), ","))
	} else if len(fs.Args()) == 1 {
		path = fs.Arg(0)
	}

	if ! *overwrite {
		_, err := os.Stat(filepath.Join(root, path))
		if err == nil {
			errorLog.Fatalf("Error: Directory exists, use -overwrite option to overwrite")
		}
	}
	
	manifest := certManifest{
		path: path,
		dn: *dn,
		validity: *validity,
		cert: &x509.Certificate{
			MaxPathLen: *maxPathLength,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
	}
}

type certManifest struct {
	path string // path of new certificate directory relative to root
	dn string // distinguished name (ie. "/CN=ca/O=acme/OU=widgets")
	sans string // subject alternative names (ie. "localhost,127.0.0.1")
	validity time.Duration

	key *ecdsa.PrivateKey
	cert *x509.Certificate
	signingCert *x509.Certificate
	signingKey *ecdsa.PrivateKey
}

func generateCertificate(root path dn sans string, keyUsage x509.KeyUsage, extKeyUsage x509.ExtKeyUsage) error {
	manifest := certManifest{
		root: root,
		path: path,
		cert: x509.Certificate{}
	}
	manifest.cert.KeyUsage = keyUsage
	manifest.cert.ExtKeyUsage = extKeyUsage
	if err := manifest.parseDN(dn); err != nil {

	}
	if err := manifest.parseSAN(sans); err != nil {

	}
	manifest.initCertificate()
	manifest.parseDN()
	manifest.parseSAN()
	manifest.sign()
	manifest.saveCertificate()
	manifest.savePrivateKey()
	manifest.saveCA()
}



func (*certManifest) initCertificate() error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	cert.notBefore = time.Now().UTC()
	cert.notAfter := cert.notBefore.AddDate(0, 0, *validity)
	cert.serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		errorLog.Fatalf("Failed to generate serial number: %s", err)
	}
}

func parseDn(dn string) *pkix.Name, error {
	infoLog.Printf("Parsing distinguished name: %s\n", dn)
	var caName pkix.Name
	if ca != nil {
		caName = ca.Subject
	} else {
		caName = pkix.Name{}
	}
	newName := &pkix.Name{}
	for _, element := range strings.Split(strings.Trim(dn, "/"), "/") {
		value := strings.Split(element, "=")
		if len(value) != 2 {
			errorLog.Fatalf("Failed to parse distinguised name: malformed element %s in dn", element)
		}
		switch strings.ToUpper(value[0]) {
		case "CN": // commonName
			newName.CommonName = value[1]
		case "C": // countryName
			if value[1] == "" {
				caName.Country = []string{}
			} else {
				newName.Country = append(newName.Country, value[1])
			}
		case "L": // localityName
			if value[1] == "" {
				caName.Locality = []string{}
			} else {
				newName.Locality = append(newName.Locality, value[1])
			}
		case "ST": // stateOrProvinceName
			if value[1] == "" {
				caName.Province = []string{}
			} else {
				newName.Province = append(newName.Province, value[1])
			}
		case "O": // organizationName
			if value[1] == "" {
				caName.Organization = []string{}
			} else {
				newName.Organization = append(newName.Organization, value[1])
			}
		case "OU": // organizationalUnitName
			if value[1] == "" {
				caName.OrganizationalUnit = []string{}
			} else {
				newName.OrganizationalUnit = append(newName.OrganizationalUnit, value[1])
			}
		default:
			errorLog.Fatalf("Failed to parse distinguised name: unknown element %s", element)
		}
	}
	if ca != nil {
		newName.Country = append(caName.Country, newName.Country...)
		newName.Locality = append(caName.Locality, newName.Locality...)
		newName.Province = append(caName.Province, newName.Province...)
		newName.Organization = append(caName.Organization, newName.Organization...)
		newName.OrganizationalUnit = append(caName.OrganizationalUnit, newName.OrganizationalUnit...)
	}
	return newName
}
