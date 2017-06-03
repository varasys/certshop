package main

import "os"
import "text/template"
import "io"
import "bytes"

func init() {
	Commands[`help`] = &Command{
		Description: `print help and exit`,
		Function: func(fs *GlobalFlags) {
			printGlobalHelp(os.Stdout, fs)
		},
	}
}

func printGlobalHelp(writer io.Writer, fs *GlobalFlags) {
	templateString := `
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
they are currently generally considered best practices.

Usage:
  certshop [global flags] command [command flags] path

where:
  global flags are:
{{.Flags}}

  and command is one of:
{{range $key, $value := .Commands}}    {{printf "%-15s" $value.Name}}{{$value.Description}}
{{end}}

  type "certshop [command] -help" to see help and command flags for each command.

  path is the path within the pki hierarchy of the command target certificate
  directory (relative to the -root flag which is "./" by default).
`
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	if template, err := template.New("help").Parse(templateString); err != nil {
		ErrorLog.Fatalf("Failed to parse global help template: %s", err)
	} else {
		if err := template.Execute(writer, &helpArgs{
			Flags:    buf.String(),
			Commands: &Commands,
		}); err != nil {
			ErrorLog.Fatalf("Failed to parse global help template: %s", err)
		}
	}
}

type helpArgs struct {
	Flags    string
	Commands *map[string]*Command
}
