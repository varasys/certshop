#!/bin/bash -xe

go build .
rm -rf test
mkdir test

APP="./certshop -root=test"

# General notes
#
# Extension for created entities are:
#    certificates - ".pem"
#    private keys - "-key.pem"
#    certificate request - "-csr.pem"
#
# command usage is: certshop [global_flags] command [command_flags] cert_path
# global_flags include (default values shown):
#    -debug=false - output additional debug information
#    -root="./" - change working directory (cert_path is relative to this directory)
#    -overwrite=false - abort if cert_path already exists (to prevent accidentally overwriting existing certificates)
# commands are:
#  certificate creation:
#    ca - create a self signed certificate authority
#    ica - create an intermediate certificate authority
#    server - create a server certificate
#    client - create a client certificate
#    peer - create a peer certificate (includes BOTH server and client extensions)
#    signature - create a digital signature certificate
#  certificate signing request:
#    csr - create private key and certificate signing request
#  export existing certificates:
#    export - export certificate set as .tgz (with .pem format files) or .p12
#  describe existing key, certificate or certificate signing request
#    describe - describe certificate or key
#  change private key encription:
#    encrypt - encrypt, decrypt or change private key password
#  application information:
#    version - print program version and exit
# certificate creation command_flags include:
#    -dn - distinguished name (ie. -dn="/CN=server1/O=ACME Co./OU=IT")
#    -cn - common name (overrides CN from -dn flag) but meant as a convienence when only the CN part of the distinguised name is required
#    -san - subject alternative names (ie. -san="127.0.0.1,::1,localhost,me@here.com")
#    -local=false - include "127.0.0.1,::1,localhost" in subject alternative names (default is true for server and peer certs)
#    -localhost=false - include "127.0.0.1,::1,localhost,${HOSTNAME}" (no need to specify -local)
#    -subject-pass - password for new private key
#    -issuing-pass - password for the existing issuing (signing certificate) private key
#    -describe=true - output certificate description after creation
#    -csr - use -dn, -san and private key from certificate request
#    -maxICA - maximum depth of subordinate intermediate certificate authorities
#    -inherit-dn=true - inherit distinguished name from signing certificate (before updating according to -dn and -cn flags)
#    -validity - certificate validity (days after creation)
# certificate signing request command_flags include:
#    -dn - distinguished name (ie. -dn="/CN=server1/O=ACME Co./OU=IT")
#    -cn - common name (overrides CN from -dn flag) but meant as a convienence when only the CN part of the distinguised name is required
#    -san - subject alternative names (ie. -san="127.0.0.1,::1,localhost,me@here.com")
#    -local=false - include "127.0.0.1,::1,localhost" in subject alternative names (default is true for server and peer certs)
#    -localhost=false - include "127.0.0.1,::1,localhost,${HOSTNAME}" (no need to specify -local)
# export command_flags include:
#    -export-key=true - export the private key
#    -export-ca=ca_path - export ca located at ca_path
#    -export-format=tgz - export format (tgz or p12)
#    -pass-in - existing private key password
#    -pass-out - exported private key password (required for p12 format)
# describe command_flags include:
#    -password - private key password
#    -key - display private key (when path is a directory)
#    -crt - display certificate (when path is a directory)
#    -csr - display csr (when path is a directory)
# encrypt command_flags include (note that path must be a file and not a directory):
#    -in-pass - existing private key password
#    -out-pass - new private key password
# path is a relative path from the root directory. The signature hierarchy follows the path hierarchy. Each certificate will be signed by the certficate above it in the path, or will be a self-signed certificate authority if only one directory is listed.


echo 'create self signed server'
$APP server bare_server

echo 'self signed server with sans="127.0.0.1,::1,localhost"'
$APP server -local local_server

echo 'self signed server with sans="127.0.0.1,::1,localhost,${HOSTNAME}"'
$APP server -localhost localhost_server

echo 'self signed server with distinguished name and subject alternative names'
$APP server -localhost -dn="/CN=server.acme.com/O=ACME Co./OU=IT" -san="192.168.1.45,server2.acme.com" acme_server

echo 'certificate authority'
$APP ca simple_ca

echo 'certificate authority with distinguised name (which will be inherited by subordinate certificates except CN)'
$APP ca -dn="/CN=ACME CA/O=ACME Co./OU=IT" acme_ca

echo 'server certificate'
$APP server -cn="server1" -local -san="server1.acme.com" acme_ca/acme_server

echo 'client certificate'
$APP client -cn="client1" acme_ca/client1

echo 'create server and client certificates using self-signed server cert as ca for client certs (ie. for openvpn)'
$APP server -cn="ACME VPN Server" -localhost -san="vpn.acme.com" vpn_server
$APP client -cn="ACME VPN Client" vpn_server/vpn_client

echo 'export the certificates created above along with the relevant ca the
server is self-signed, but still needs a ca cert to use to validate client
certificates which is the same as the server cert (since it is self-signed),
and the client also uses the server cert as a ca'
$APP export -export-ca=vpn_server/vpn_server.pem vpn_server > test/openvpn_server.tgz
echo 'the export command chains certs, so the exported vpn_server.pem file
will include the client certificate and the server cert'
$APP export -export-ca=vpn_server/vpn_server.pem vpn_server/vpn_client > test/openvpn_client.tgz

echo 'add password to vpn_client private key created above'
$APP encrypt -out-pass="1234" vpn_server/vpn_client/vpn_client-key.pem

echo 'change the password added above'
$APP encrypt -in-pass="1234" -out-pass="4321" vpn_server/vpn_client/vpn_client-key.pem

echo 'remove the password added above'
$APP encrypt -in-pass="4321" vpn_server/vpn_client/vpn_client-key.pem

echo 'create a new encrypted private key and certificate signing request'
$APP csr -cn="ACME VPN Client 2" client_csr

echo 'create a new vpn client using the csr created above and signed by the openvpn server certificate created above'
$APP client -csr=client_csr/client_csr-csr.pem vpn_server/vpn_client2



# #create server certificate
# $APP server -localhost my_ca/server1

# #create client certificate
# $APP client -dn="/CN=client1" my_ca/client1
