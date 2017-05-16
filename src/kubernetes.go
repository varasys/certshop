package kubesec

import (
	"crypto/x509"
	"os"
)

func createKubernetes(args []string) {
	createCA([]string{"-maxPathLength=1"}, "ca", "/CN=kubernetes-ca", 10*365+5)
	createCA(nil, "ca/etcd-peer-ica", "/CN=etcd-peer-ica", 5*365+5)
	createCA(nil, "ca/etcd-server-ica", "/CN=etcd-server-ica", 5*365+5)
	createCA(nil, "ca/etcd-client-ica", "/CN=etcd-client-ica", 5*365+5)
	createCA(nil, "ca/api-server-ica", "/CN=api-server-ica", 5*365+5)
	createCA(nil, "ca/api-client-ica", "/CN=api-client-ica", 5*365+5)
	createCertificate(os.Args[2:], "ca/etcd-peer-ica/etcd-peer", "/CN=etcd-peer", 365+5,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	createCertificate(os.Args[2:], "ca/etcd-server-ica/etcd-server", "/CN=etcd-server", 365+5,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	createCertificate(os.Args[2:], "ca/etcd-client-ica/etcd-client", "/CN=etcd-client", 365+5,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	createCertificate(os.Args[2:], "ca/api-server-ica/api-server", "/CN=api-server", 365+5,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	createCertificate(os.Args[2:], "ca/api-client-ica/api-client", "/CN=api-client", 365+5,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}
