package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Commands[`kubernetes`] = &Command{
		Description: `manage pki for a kubernetes cluster (etcd, locksmith.d, fleet and api-server)`,
		HelpString:  `TODO`,
		Function: func(fs *GlobalFlags) {
			manifest := ParseKubernetesFlags(fs)
			if manifest.CreateCAs {
				CreateKubernetesPKI(manifest)
			}
			CreateKubernetesCertificates(manifest)
		},
	}
}

// KubernetesFlags holds meta information for managing kubernetes pki
type KubernetesFlags struct {
	flag.FlagSet
	Path         string
	EtcdPeerSANS string
	FleetSANS    string
	APISANS      string
	CertValidity int
	CreateCAs    bool
}

// ParseKubernetesFlags parses command line flags used to manage kubernetes pki
func ParseKubernetesFlags(global *GlobalFlags) *KubernetesFlags {
	DebugLog.Println(`Parsing kubernetes flags`)
	fs := KubernetesFlags{FlagSet: *flag.NewFlagSet(`kubernetes`, flag.ContinueOnError)}
	fs.BoolVar(&fs.CreateCAs, "create-cas", false, `create missing certificate authorities`)
	fs.StringVar(&fs.EtcdPeerSANS, "etcd-peer-san", "", `subject alternative names for etcd peer certificates
		typically private ip and hostnames`)
	fs.StringVar(&fs.FleetSANS, "fleet-san", "", `subject alternative names for fleet certificates
		typically an ip address on the fleet network`)
	fs.StringVar(&fs.APISANS, "api-san", "", `subject alternative names for the kubelet api server
		varies depending on how api server is accessed`)
	fs.IntVar(&fs.CertValidity, `validity`, 365+5, `validity of the certificates in days (ca certifitates are valid for this *5)`)
	help := fs.Bool(`help`, false, `show help message and exit`)
	if err := fs.Parse(global.Args[1:]); err != nil || *help {
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		global.Command.HelpString = buf.String()
		if err != nil {
			global.Command.PrintHelp(os.Stderr, fmt.Errorf("Failed to parse kubernetes command line options: %s", strings.Join(global.Args[1:], " ")))
		} else {
			global.Command.PrintHelp(os.Stdout, nil)
		}
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		ErrorLog.Fatalf(`Failed to parse certificate path: %s`, strings.Join(global.Args[1:], ` `))
	}
	return &fs
}

// CreateKubernetesPKI creates all the kubernetes certificate authorities
func CreateKubernetesPKI(manifest *KubernetesFlags) {
	if manifest.CreateCAs {
		if !Overwrite {
			if _, err := os.Stat(manifest.Path); err == nil {
				ErrorLog.Fatalf("Error %s already exists, use -overwrite flag to overwrite it", manifest.Path)
			}
		}
		certs := []string{"etcd_server_ca", "etcd_client_ca", "etcd_peer_ca", "api_server_ca"}
		writer := NewFileWriter()
		for i := range certs {
			key, template := PrepareCertTemplate(certs[i], manifest.CertValidity*5, x509.KeyUsageCertSign, []x509.ExtKeyUsage{})
			template.AuthorityKeyId = template.SubjectKeyId
			der, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, key)
			if err != nil {
				ErrorLog.Fatalf("Failed to sign certificate: %s", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				ErrorLog.Fatalf("Failed to parse signed certificate: %s", err)
			}
			SaveCert(writer, cert, filepath.Join(manifest.Path, certs[i], certs[i]+".pem"))
			SaveKey(writer, key, NilString, filepath.Join(manifest.Path, certs[i], certs[i]+"-key.pem"))
		}
	}
}

// CreateKubernetesCertificates creates all the kubernetes certificates
func CreateKubernetesCertificates(manifest *KubernetesFlags) {
	type certData struct {
		path     string
		cn       string
		usage    x509.KeyUsage
		extUsage []x509.ExtKeyUsage
		san      string
	}
	certs := []certData{
		certData{
			path:     "etcd_server_ca/etcd_server",
			cn:       "etcd_server",
			usage:    x509.KeyUsageCertSign,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			san:      "127.0.0.1,::1,localhost",
		},
	}
	writer := NewFileWriter()
	for i := range certs {
		key, template := PrepareCertTemplate(certs[i].cn, manifest.CertValidity, certs[i].usage, certs[i].extUsage)
		caDir := filepath.Dir(certs[i].path)
		caFile := filepath.Join(caDir, filepath.Base(caDir))
		ca := ReadCert(caFile + ".pem")
		caKey := ReadKey(caFile+"-key.pem", NilString)
		template.AuthorityKeyId = ca.SubjectKeyId
		der, err := x509.CreateCertificate(rand.Reader, template, ca, template.PublicKey, caKey)
		if err != nil {
			ErrorLog.Fatalf("Failed to sign certificate: %s", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			ErrorLog.Fatalf("Failed to parse signed certificate: %s", err)
		}
		path := certs[i].path
		path = filepath.Join(path, filepath.Base(path))
		SaveCert(writer, cert, path+".pem")
		SaveKey(writer, key, NilString, path+"-key.pem")
	}
}

// PrepareCertTemplate prepares a certificate template
func PrepareCertTemplate(cn string, validity int, usage x509.KeyUsage, extUsage []x509.ExtKeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	privateKey := GenerateKey()
	publicKey := &privateKey.PublicKey
	isCA := usage&x509.KeyUsageCertSign == x509.KeyUsageCertSign
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: GenerateSerial(),
		PublicKey:    publicKey,
		NotBefore:    RunTime,
		NotAfter:     RunTime.Add(time.Duration(validity) * time.Hour),
		IsCA:         isCA,
		BasicConstraintsValid: isCA,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          HashKeyID(publicKey),
		KeyUsage:              usage,
		ExtKeyUsage:           extUsage,
	}
	return privateKey, template
}
