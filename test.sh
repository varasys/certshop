#!/bin/bash

rm -rf ca
go build .
./kubesec ca -maxPathLength=2 -dn="/CN=test ca/O=ACME/OU=skunk" ca
./kubesec ica -maxPathLength=1 -dn="/CN=test ica1" ca/ica1
./kubesec -root ca ica -dn="/CN=test ica2" ica1/ica2
