#!/bin/bash

APP="./certshop"

rm -rf ca csr \
&& $APP ca -maxPathLength=2 -dn="/CN=test ca/O=ACME/OU=skunk" ca \
&& $APP ica -maxPathLength=1 -dn="/CN=test ica1" ca/ica1 \
&& $APP -root ca ica -dn="/CN=test ica2" -subjectPass=1234 ica1/ica2 \
&& $APP server -issuerPass=1234 -subjectPass=4321 ca/ica1/ica2/server \
&& $APP client ca/ica1/client \
&& $APP csr -dn="/CN=test csr" -sans="127.0.0.1,localhost,anyville.com" csr \
&& $APP client -csrFile csr/csr-csr.pem -issuerPass=1234 ca/ica1/ica2/client2

#self signed server
$APP server -localhost my_server > my_server.tgz
ls -lh my_server.tgz

#self signed server with common name
$APP server -localhost -dn="CN=server.acme.com" my_server | tar -zxv
ls -lh my_server
cat my_server *

#show certificate differences
$APP describe my_server

#self signed server with subject alternative names
$APP server -localhost -dn="CN=server.acme.com" -san="192.168.1.45,server2.acme.com" my_server | tar -zxv

#show certificate details
$APP describe my_server

#certificate authority
$APP ca my_ca
$APP describe my_ca

#include dn information
$APP -overwrite ca -dn="/CN=acme ca/O=Acme/OU=Information Security" my_ca

#create server certificate
$APP server -localhost my_ca/server1

#create client certificate
$APP client -dn="/CN=client1" my_ca/client1


