#!/bin/bash

APP="./certshop"

rm -rf ca \
&& go build . \
&& $APP ca -maxPathLength=2 -dn="/CN=test ca/O=ACME/OU=skunk" ca \
&& $APP ica -maxPathLength=1 -dn="/CN=test ica1" ca/ica1 \
&& $APP -root ca ica -dn="/CN=test ica2" ica1/ica2 \
&& $APP server ca/ica1/ica2/server \
&& $APP client ca/ica1/client
