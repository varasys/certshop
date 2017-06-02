package main

import "os"

func init() {
	Commands[`help`] = &Command{
		Description: `print help and exit`,
		Function: func(fs *GlobalFlags) {
			printGlobalHelp(os.Stdout, fs)
		},
	}
}

func printGlobalHelp(writer *os.File, fs *GlobalFlags) {
	_, _ = writer.WriteString(`
certshop is a command line program for managing public key infrastructure
using ECP384 certificates with ECP384-SHA384 signatures and using AES256
encryption for private keys.

In other words, it makes x509 certificates for things like:
  certificate authorities
  intermediate certificate authorities
  webservers
  vpn servers and clients
  kubernetes clusters
  digital signatures
  encryption and authentication of any TLS stream

certshop is a complete replacement for openssl for the tasks listed above,
and is very streamlined to accomplish these tasks. ECP386 private keys,
ECDSA-SHA384 signatures and AES256 private key encryption were chosen because
they are currently generally considered best practices. Additional algorithms
were specifically not included to minimize application complexity (if you know
you need another algorithm you are probably doing something special and
are experienced with openssl).

Usage:
    certshop [global flags] command [command flags] path

where:
  global flags are:
`)
	fs.SetOutput(writer)
	fs.PrintDefaults()
	_, _ = writer.WriteString(`
  and command is one of:
    ca:        create a private key and self signed certificate authority
    ica:       create a private key and intermediate certificate authority
    server:    create a private key and server certifacate
    client:    create a private key and client certificate
    peer:      create a private key and peer (server AND client) certificate
    signature: create a private key and digital signature certificate
    csr:       create a private key and certificate signing request
    export:    export keys and certificates
    encrypt:   add/remove/change private key AES256 encryption
    describe:  describe a key, certificate or csr to stdout
    help:      print this help message to stdout and exit
    version:   print certshop version and build date to stdout and  exit

  type "certshop [command] -help" to see help and command flags for each command.

  path is the path within the pki hierarchy of the command target certificate
  directory (relative to the -root flag which is "./" by default).
`)
	_ = writer.Sync()
}
