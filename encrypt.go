package main

import (
	"flag"
	"path/filepath"
	"strings"
)

func init() {
	Commands[`encrypt`] = &Command{
		Description: `add/remove/change private key AES256 encryption password`,
		HelpString:  `TODO`,
		Function: func(fs *GlobalFlags) {
			Encrypt(ParseEncryptFlags(fs.Args))
		},
	}
}

// EncryptFlags hold encrypt command line options
type EncryptFlags struct {
	flag.FlagSet
	Path    string
	InPass  string
	OutPass string
}

// ParseEncryptFlags parses command line options for the encrypt command
func ParseEncryptFlags(args []string) *EncryptFlags {
	DebugLog.Println(`Parsing encrypt flags`)
	fs := EncryptFlags{FlagSet: *flag.NewFlagSet(`ca`, flag.ContinueOnError)}
	fs.StringVar(&fs.InPass, "in-pass", NilString, "Existing password")
	fs.StringVar(&fs.OutPass, "out-pass", NilString, "New Password")
	if err := fs.Parse(args[1:]); err != nil {
		ErrorLog.Fatalf("Failed to parse encrypt command line options: %s", err)
	}
	if len(fs.Args()) == 1 {
		fs.Path = filepath.Clean(fs.Args()[0])
	} else {
		ErrorLog.Fatalf(`Failed to parse private key path: %s`, strings.Join(fs.Args(), ` `))
	}
	return &fs
}

// Encrypt changes the password for a private key file
func Encrypt(flags *EncryptFlags) {
	key := ReadKey(flags.Path, flags.InPass)
	writer := NewStdoutWriter()
	defer writer.Close()
	SaveKey(writer, key, flags.OutPass, "")
}
