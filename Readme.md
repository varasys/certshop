# certshop

Certshop is an application for Mac, Linux and Windows to generate Private Key Infrastructure (PKI) Certificate Authorities (CA), Intermediate Certificate Authorities (ICA), and x.509 v3 certificates for TLS key exchanges and digital signatures and the certificate portion of OpenVPN config files. All private keys use Elliptic Curve secp384r1, and signatures are ECDSA Signature with SHA-384, which is believed to follow current best practices.

Binaries for Windows, Mac and Linux are available for download at https://github.com/varasys/certshop/releases.

## Quick Start

The following three commands will create a certificate authority, server certificate (and private key) and client certificate (and private key). By default, server certificates include "localhost" and "127.0.0.1" as Subject Alternative Names, so the server and client certificates generated below can be used directly assuming the client will only connect from the localhost.

```bash
certshop ca # create certificate authority key and cert
certshop server # create server key and cert
certshop client # create client key and cert
```

In order to connect to the server remotely using a public DNS name, the public DNS name should be used for the Common Name portion the Distinguished Name using the "-dn" flag. The following commands can be used instead of the commands above to create certificates for host "host.domain.com".

```bash
certshop ca
certshop server -dn="/CN=host.domain.com"
certshop client
```

Additional hostnames (or IP address, or email addresses) can be specified as Subject Alternative Names using the "-san" flag. The following command creates a server certificate that can be used for both host.domain.**com** and also host.domain.**org**.

```bash
certshop server -overwrite -dn="/CN=host.domain.com" -san="127.0.0.1,localhost,host.domain.org"
```

Note that the command above 1) uses the "-overwrite" flag since the certificates already exist from the previous step, and 2) includes "127.0.0.1" and "localhost" in the "-san" flag because they are not included by default when the "-san" flag is explicitly provided.

The Distinguished Name (-dn) flag expects a quoted list of key value pairs in the form `/key=value` where the following keys are valid (note that "/" is included in the beginning and as a separator between key value pairs):

- **CN** - Common Name (not inherited)
- **C** - Country  
- **L** - Locality  
- **ST** - State or Province  
- **O** - Organization  
- **OU** - Organizational Unit  

The Distinguished Name for a certificate is first inherited from the certificate authority which will sign the certificate, and then modified by the -dn flag of the certificate being generated. Inheritance of a value can be masked by leaving the value empty.

```bash
certshop ca -dn="/CA=My CA/O=My Organization/OU=My Organizational Unit"
certshop server -dn="/CA=host.domain.com/OU="
```

In the example above, the final distinguished name for the server will be "/CA=host.domain.com/O=My Organization". Note that "O" was inherited from the ca, and that since the server -dn flag includes "OU=" (ie. an empty value) the "OU" value is not inherited and left blank.

## Detailed Instructions

The full form of the certshop command is:

```bash
certshop command [flags] [path]
```

Where:

- **command** is one of the following  
	- **ca**: create a certificate authority  
	- **ica**: create an intermediate certificate authority  
	- **server**: create a server certificate  
	- **client**: create a client certificate  
	- **signature**: create a certificate for digital signatures (ie. for signing pdf files, etc.)  
	- **export**: export certificates in various formats to stdout as a compressed tarball (.tgz format)  
- Flags for the **ca** and **ica** command are:  
	- **-dn**: the Distinguished Name of the certificate (before considering inheritance from the parent ca)  
	- **-maxPathLength**: maximum number of subordinate Intermediate Certificate Authorities (ICA) (default = 0)  
	- **-validity**: number of days the certificate is valid starting from the current time (ca default = 10 years, ica default = 5 years)  
	- **-overwrite**: whether or not to overwrite existing files when creating certificates (default = false)  
- Flags for the **server**, **client**, and **signature** command are:  
	- **-dn**: the Distinguished Name of the certificate (before considering inheritance from the parent ca)  
	- **-san**: comma separated list of Subject Alternate Names  
	- **-validity**: number of days the certificate is valid starting from the current time (default = 370 days)  
	- **-overwrite**: whether or not to overwrite existing files when creating certificates (default = false)  
- Flags for the **export** command are:  
	- **-crt**: include the certificate (including CA cert and all ICA certs) in PEM format (default = true)  
	- **-key**: include the private key in PEM format (default = true)  
	- **-ca**: include the CA certificate (default = true)  
	- **-p12**: include the certificate and private key together in a password protected pkcs12 file (default = false)  
	- **-password**: password for the the pkcs12 private key (only used when -p12 = true)  
	- **-openvpn**: concat the certificate, private key and ca certificate into a text file that can be appended to the end of an openvpn configuration file to embed the certificates directly in the configuration file (default = false)

The **path** is a relative path from the current working folder to the folder to save the certificate, and the folders will be created when the certificate is generated if they don't already exist. CAs will use self-signed certificates and everything else will be signed by the certificate immediately above it in the path. The following default paths are defined for convenience when setting up a simple infrastructure with no ICA, which is why the path wasn't specified in the quick-start instructions.

- **ca**: ca  
- **ica**: ca/ica  
- **server**: ca/server  
- **client**: ca/client  
- **signature**: ca/sign  

## Using Intermediate Certificate Authorities
The "-maxPathLength" flag for a certificate authority or intermediate certificate authority limits the depth of subordinate intermediate certificate authorities that can sign certificates. By default -maxPathLength=0. The example below demonstrates the significance of maxPathLength.

```bash
certshop ca -maxPathLength=2 ca
certshop ica ca/ica # no problem with this ica
certshop ica ca/ica/ica2 # no problem with this ica
certshop ica ca/ica/ica2/ica3 # this will fail because it is nested too deep
```

## Exporting Files
One folder is created for each certificate key pair and includes the following files (where *name* is the last part of the path used to create the certificate):

- **name.crt**: the certificate file in PEM format  
- **name.key**: the key file in PEM format  
- **ca.pem**: the top level ca certificate in PEM format

If the certificate is a CA or ICA then it may have further sub-folders for each of the certificates it has signed.

The **ca.pem** file is included because if somebody else is an administrator of an ICA, you could send them the ICA folder for the certificates they are administering and they would be able to use the certshop program to create certificates from that ICA without needing the top level CA key.

Although all certificates and keys are stored in a flat file structure and you can copy the PEM format certificates and keys directly out of the file structure, the `export` command is provided for convenience, and to provide convertion to pkcs12 format and provide a snippet which can be used in an OpenVPN config file.

Refer to the "Flags for the **export** command" section above for a description of all of the export options. By default the flags are: `-crt=true -key=true -ca=true -p12=false -openvpn=false`.

The reason the **export** command writes to stdout instead of saving to a file is to make it easier to remotely connect to a server and create and download new certificates. Assuming you can connect to the computer where the certificates are stored, the following command would connect remotely, create a new server certificate, and download it to the local machine.

```bash
ssh localhost cd /path/to/ca/folder/parent; certshop create ca/server; certshop export ca/server | tar -zxvC /path/to/cert/destination/folder
```

This design was motivated by a need to provide cluster node certificates for kubernetes clusters. With this design, each node can securely connect to a "certificate server" via ssh to run the certshop program and create and download its own certificates.

Note that the `cd` command above uses the folder *above* the top level ca certificate folder (ie. the folder that the ca folder is located in).

To save a compressed tarball with the p12 file locally (as an example), run:

```bash
certshop export -crt=false -key=false -ca=false -p12=true -password="secret" ca > ca.tgz
```

## Issues

1. CRL and OCSP revocation is not currently implemented, but probably could be if there is demand for it.  
2. OpenSSL is called externally when exporting a certificate/key pair in .p12 format, so openssl must be installed and included in the current environment PATH.

## Contribution

Feel free to contribute, ask questions or provide advice at https://github.com/varasys/certshop.





