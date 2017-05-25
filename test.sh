#!/bin/bash

APP="./certshop"

rm -rf ca csr \
&& go build . \
&& $APP ca -maxPathLength=2 -dn="/CN=test ca/O=ACME/OU=skunk" ca \
&& $APP ica -maxPathLength=1 -dn="/CN=test ica1" ca/ica1 \
&& $APP -root ca ica -dn="/CN=test ica2" -subjectPass=1234 ica1/ica2 \
&& $APP server -issuerPass=1234 -subjectPass=4321 ca/ica1/ica2/server \
&& $APP client ca/ica1/client \
&& $APP csr -dn="/CN=test csr" -sans="127.0.0.1,localhost,anyville.com" csr \
&& $APP client -csrFile csr/csr-csr.pem -issuerPass=1234 ca/ica1/ica2/client2
