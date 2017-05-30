# Detailed Instructions
The certshop command uses the following form:

certshop [global_options] command [command_options] [path]

Where:

- **global_options** are optional and may include:    
  - **-root="./"** is the directory with the root ca folder (see *path* section below)  
  - **-overwrite=false** if true will overwrite existing directories and if false will exit with an error instead  
- **comand** is one of the following actions:  
  - commands to create certificate authorities:  
    - **ca** create a certificate authority (self signed root certificate)  
    - **ica** create an intermediate certificate authority  
  - commands to create certificates  
    - **server** create a server certificate  
    - **client** create a client certificate  
    - **peer** create a peer certificate (both server and client)  
    - **signature** create a digital signature certificate  
  - command to create certificate signing request and associated keys  
    - **csr** - create a key pair and certificate signing request  
  - informative commands  
    - **describe** - output description of a certificate, key, or csr to stderr  
    - **version** - output certshop version and build date and exit  
  - export certificates and key sets  
    - **export** - export certificate and key sets  
  - automate pki for common infrastructure  
    - **openvpn** - create and manage a ca for openvpn  
    - **kubernetes** - create and manage a ca for kubernetes  
- **command_options** may include the following  (see the description for each command for explination of the detailed meaning of each flag)
  - **-describe=true** whether to describe to the screen what is created  
  - **-export={format}** export created certificate and key to stoud where {format} = "tgz" or "p12"  
  - **-dn=""** foreslash (/) separated distinguished name (DN) for the subject certificate (ie. -dn="/CN=/server/O=ACME Co./OU=Info Security")  
  - **-sans=""** a comma separated list of ip addresses, email addresses, and hostnames to include as Subject Alternative Names (SAN) (ie. -sans="127.0.0.1,::1,localhost,admin@acme.com")  
  - **-maxICA=0** is the maximum depth of intermediate certificate authorities (ICA) which may be chained below the subject certificate  
  - **-validity={days}** is the validity period of the certificate in days starting from the certificate creation time  
  - **-subjectpass={pwd}** is the password for the subject certificate private key
  - **-issuerpass={pwd}** is the password for the issuing ca or ica private key  
  - **-csr={csr_path}** create certificate from certificate signing request (CSR) at csr\_path or from stdin if path is ""  
  - **-local= 

- **path** is the relative path (from the root director) to the target directory to either retreive or create certificates and keys  

# certshop
Certshop is a command line program for Linux, Macintosh and Windows to manage x.509 certificates including:

- Create Certificate Authorities  
- Create Intermediate Certificate Authorities  
- Create Certificates  
	- from Certificate Signing Request
	- Server  
	- Client  
	- Peer  
	- Digital Signature
- Helpers for setting up certificates for common infrastructure
	- OpenVPN  
	- Kubernetes (etcd, flannel and api-server)

# certshop

# Still need to update documentation to reflect updated functionality in kubesec.

Certshop is the easy way to create server certificates for web servers; and so much more...

Certshop is a standalone application for Mac, Linux and Windows to generate Private Key Infrastructure (PKI) Certificate Authorities (CA), Intermediate Certificate Authorities (ICA), and x.509 v3 certificates for TLS key exchanges and digital signatures and the certificate portion of OpenVPN config files.

All private keys use Elliptic Curve secp384r1, and signatures are ECDSA Signature with SHA-384, which is believed to follow current best practices. Certshop is written in go and uses go's standard cryptography libraries.

Binaries for Mac, Linux and Windows are available for download at https://github.com/varasys/certshop/releases.

## Quick Start
To make a Certificate Authority and a server certificate:

```bash
certshop ca -dn="/CN=My CA/O=My Organization/OU=My Organizational Unit" ca
certshop server -dn="/CN=host.domain.com" ca/host_domain_com
```

The "ca" private key and certificate will be in the "./ca" folder, and the server private key and certificate will be in the "./ca/host_domain_com" folder (refer to the "export" command below for other options). Every folder will also include a file called "ca.pem" with the ca certificate (without private key).

The server Distinguished Name ("-dn" flag) first inherits the DN from the ca, and then overwrites any values specifically provided in the server "-dn" flag, so the final DN for the server is "/CN=host.domain.com/O=My Organization/OU=My Organizational Unit".

Inheritance can be blocked by leaving the field empty. For instance -dn="/CN=host.domain.com/OU=" will prevent the OU from being inherited.

To make additional server or client certificates continue to run the `certshop server` command or `certshop client` command once for each certificate with the required DN information.
 
 ```bash
 # create a second server cert
 certshop server -dn="/CN=host2.domain.com" ca/host2_domain_com
 # create a client cert
 certshop client -dn="/CN=name of client" ca/name_of_client
 ```
 
Subject Alternative Names (SAN) may be provided with the "-san" flag. By default the SAN includes "127.0.0.1" and "localhost", but these defaults won't be included if the "-san" flag is explicitly supplied, so they should be included in the "-san" flag as shown below if needed.
 
 ```bash
 # create a server cert for my.domain.com and my.domain.org.
 certshop server -dn="/CN=my.domain.com" -san="127.0.0.1,localhost,my.domain.org" ca/my_domain_com
 ```

### Intermediate Certificate Authorities
Intermediate Certificate Authorities are created with the "ica" command.

Updating the first example to include an ICA is shown below.

```bash
certshop ca -dn="/CN=My CA/O=My Organization/OU=My Organizational Unit" ca
certshop ica -dn="/CN=My ICA" ca/ica
certshop server -dn="/CN=host.domain.com" ca/ica/host_domain_com
```

## Detailed Instructions

The full form of the certshop command is:

```bash
certshop command [flags] [path]
```

Where:

- **command** is one of the following:  
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
- Flags for the **server**, **client**, **peer**, and **signature** command are:  
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

### Distinguished Names

The Distinguished Name (DN) can be set with the "-dn" flag which expects a quoted list of key value pairs in the form `/key=value` where the keys listed below are valid. Note that "/" is included in the beginning and as a separator between key value pairs.

- **CN** - Common Name (never inherited)
- **C** - Country  
- **L** - Locality  
- **ST** - State or Province  
- **O** - Organization  
- **OU** - Organizational Unit  

The Distinguished Name for a certificate is first inherited from the certificate authority which will sign the certificate, and then modified by the "-dn" flag of the certificate being generated. Inheritance of a value can be masked by leaving the value empty.

```bash
certshop ca -dn="/CN=My CA/O=My Organization/OU=My Organizational Unit"
certshop server -dn="/CN=host.domain.com/OU="
```

In the example above, the final distinguished name for the server will be "/CA=host.domain.com/O=My Organization". Note that "O" was inherited from the ca, and that since the server -dn flag includes "OU=" (ie. an empty value) the "OU" value is not inherited and left blank.

### Certificate Path

The **path** is an absolute path or relative path from the current working folder to the folder to save the certificate, and the folders will be created when the certificate is generated if they don't already exist. CAs will use self-signed certificates and everything else will be signed by the certificate immediately above it in the path. The following default paths are defined for convenience when setting up a simple infrastructure with no ICA, but it is recommended to always specify a path.

- **ca**: ca  
- **ica**: ca/ica  
- **server**: ca/server  
- **client**: ca/client  
- **signature**: ca/sign  

## Using Intermediate Certificate Authorities
The "-maxPathLength" flag for a certificate authority or intermediate certificate authority limits the depth of subordinate intermediate certificate authorities that can sign certificates. By default "-maxPathLength=0" (so the CA can only sign end certificates and not any ICAs). The example below demonstrates the significance of maxPathLength.

```bash
certshop ca -maxPathLength=2 ca # there can't be more than 2 ICAs under this cert
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

Although all certificates and keys are stored in a flat file structure and you can copy the PEM format certificates and keys directly out of the file structure, the `export` command is provided for convenience, to provide conversion to pkcs12 format, and to provide a openvpn config snippet which can be used to embed the certificates and private key directly in an OpenVPN config file.

Refer to the "Flags for the **export** command" section above for a description of all of the export options. By default the flags are: `-crt=true -key=true -ca=true -p12=false -openvpn=false`.

The reason the **export** command writes to stdout instead of saving to a file is to make it easier to remotely connect to a server and create and download new certificates. Assuming you can connect to the computer where the certificates are stored, the following command would connect remotely, create a new server certificate, and download it to the local machine.

```bash
ssh certserver cd /path/to/ca/folder/parent; certshop create ca/server; certshop export ca/server \
| tar -zxvC /path/to/cert/destination/folder
```

When using automatic provisioning (ie. when creating a cluster), if the provisioner can connect to the machine being provisioned via ssh, and specifies the "-A" ssh flag (ForwardAgent) when connecting, and ssh-agent is running on the provisioner (start it with `ssh-agent && ssh-add`), then the *machine being provisioned* will be able to use the ssh keys from the user account on the provisioning server to connect to other machines (ie. to run `certshop` on a remote machine) even though the ssh keys aren't physically located on the machine being provisioned.  

When the "-crt" flag is specified the certificate will be included twice, once with the name according to the path and ".crt" extension, and the other file will be named "cert.pem". Other than the name, the two files are identical. The reason for including two files is because some users will want to a descriptive name, and other users will want a fixed unchanging name (especially when automatically provisioning new servers). The "-key" flag works similar except one file with the name according to the path with a ".key" extension, and the other file will be named "key.pem".

This design was motivated by a need to provide cluster node certificates for kubernetes clusters. With this design, each node can securely connect to a "certificate server" via ssh to run the certshop program and create and download its own certificates.

Note that the `cd` command above uses the folder *above* the top level ca certificate folder (ie. the folder that the ca folder is located in).

The following example shows how to export p12 format with the "-p12" and "-password" flags, and also how to pipe (ie. save) the results of the export command to a local ".tgz" file.

```bash
certshop export -crt=false -key=false -ca=false -p12=true -password="secret" ca > ca.tgz
```

## Issues

1. CRL and OCSP revocation is not currently implemented, but probably could be if there is demand for it.  
2. OpenSSL is called externally when exporting a certificate/key pair in .p12 format, so openssl must be installed and included in the current PATH (you can check this by confirming the command `which openssl` returns a valid path). Otherwise there are no other external dependencies.  

## Contribution

Feel free to contribute, ask questions or provide advice at https://github.com/varasys/certshop.
