#!/bin/bash


go build .
rm -rf test
mkdir test
cd test

APP="../certshop"

#self signed server
$APP server -localhost my_server > my_server.tgz
ls -lh my_server.tgz

# #self signed server with common name
# $APP server -localhost -dn="CN=server.acme.com" my_server | tar -zxv
# ls -lh my_server
# cat my_server *

# #show certificate differences
# $APP describe my_server

# #self signed server with subject alternative names
# $APP server -localhost -dn="CN=server.acme.com" -san="192.168.1.45,server2.acme.com" my_server | tar -zxv

# #show certificate details
# $APP describe my_server

# #certificate authority
# $APP ca my_ca
# $APP describe my_ca

# #include dn information
# $APP -overwrite ca -dn="/CN=acme ca/O=Acme/OU=Information Security" my_ca

# #create server certificate
# $APP server -localhost my_ca/server1

# #create client certificate
# $APP client -dn="/CN=client1" my_ca/client1
