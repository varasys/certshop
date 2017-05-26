#!/usr/bin/make -f

SHELL=/bin/sh

BINARY=certshop

# These are the values we want to pass for VERSION and BUILD
# git tag 1.0.1
# git commit -am "One more change after the tags"
VERSION=`git describe --tags`
BUILD=`date +%FT%T%z`

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

build: *.go
	go build ${LDFLAGS} -o ${BINARY}

test: build
	./test.sh

install:
	go install ${LDFLAGS}

clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

.PHONY: clean install
