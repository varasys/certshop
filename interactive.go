package main

import (
	"io/ioutil"
	"os"
	"text/template"
)

func RunInteractive() {
	defer func() {
		WriteStdOut(`
Thank you for visiting the certshop. We hope you found everything you needed
and invite you to visit again soon.`)
	}()
	WriteStdOut(`Welcome to the certshop.

We invite you to use our interactive interface to browse the shop and
test the merchandise. After each product is created the command used
to create the product will be shown, and can be used to run certshop
in scripted mode to recreate the product (with a new private key).

Our special today is 100% off (yeah, free!!) all products in the shop.

Don't forget to read the license agreement for the usual caveats.
`)
	for {
		WriteStdOut(`
Select an option from the menu below:
`)
		templateString := `{{range $key, $value := .}}  {{printf "%-5d" $key}}{{$value.Description}}
{{end}}`
		if template, err := template.New(`menu`).Parse(templateString); err != nil {
			ErrorLog.Fatalf("Failed to parse menu template: %s", err)
		} else {
			_ = template.Execute(os.Stdout, menuItems)
		}
		WriteStdOut(`
Option: `)
		if data, err := ioutil.ReadAll(os.Stdin); err != nil {
			ErrorLog.Fatalf("Failed to read from stdin: %s", err)
		} else {
			WriteStdOut(string(data))
		}
		os.Exit(0)
	}
}

// WriteStdOut is a convienence function to catch errors
// to avoid having to check on each write
func WriteStdOut(str string) {
	if _, err := os.Stdout.WriteString(str); err != nil {
		ErrorLog.Fatalf("Failed to write to stdout: %s", err)
	}
}

type menuItem struct {
	Command     string
	Description string
	Function    func(string)
}

var menuItems = map[int]*menuItem{
	1: &menuItem{
		Description: `Create self signed certificate authority (ca)`,
	},
	2: &menuItem{
		Description: `Create intermediate certificate authority (ica)`,
	},
	3: &menuItem{
		Description: `Create ca which can be used as a server certificate and also sign client certificates`,
	},
	4: &menuItem{
		Description: `Create server certificate`,
	},
	5: &menuItem{
		Description: `Create client certificate`,
	},
	6: &menuItem{
		Description: `Create peer (server and client) certificate`,
	},
	7: &menuItem{
		Description: `Create certificate signing request (csr)`,
	},
	8: &menuItem{
		Description: `Export items in .pem or .p12 format`,
	},
	9: &menuItem{
		Description: `Add/remove/update private key AES256 encryption`,
	},
	10: &menuItem{
		Description: `Describe certificate, certificate signing request and/or private key`,
	},
	11: &menuItem{
		Description: `Show program version, build date and license`,
	},
	12: &menuItem{
		Description: `Exit`,
		Function: func(command string) {
			os.Exit(0)
		},
	},
}
