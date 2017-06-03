package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	Commands[`encrypt`] = &Command{
		Description: `add/remove/change private key AES256 encryption password`,
		HelpString:  `TODO`,
		Function: func(fs *GlobalFlags) {
			Encrypt(ParseEncryptFlags(fs))
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
func ParseEncryptFlags(global *GlobalFlags) *EncryptFlags {
	DebugLog.Println(`Parsing encrypt flags`)
	fs := EncryptFlags{FlagSet: *flag.NewFlagSet(`ca`, flag.ContinueOnError)}
	fs.StringVar(&fs.InPass, "in-pass", NilString, "Existing password")
	fs.StringVar(&fs.OutPass, "out-pass", NilString, "New Password")
	help := fs.Bool(`help`, false, `show help message and exit`)
	if err := fs.Parse(global.Args[1:]); err != nil || *help {
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		global.Command.HelpString = buf.String()
		if err != nil {
			global.Command.PrintHelp(os.Stderr, fmt.Errorf("Failed to parse encrypt command line options: %s", strings.Join(global.Args[1:], " ")))
		} else {
			global.Command.PrintHelp(os.Stdout, nil)
		}
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
