package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var (
	// Version is populated using "-ldflags -X `git describe --tags`" build option
	// build using the Makefile to inject this value
	Version string
	// Build is populated using "-ldflags -X `date +%FT%T%z`" build option
	// build using the Makefile to inject this value
	Build string
	// License is populated using "-ldflags -X `cat LICENSE`" build option
	// build using the Makefile to inject this value
	License string
	// InfoLog logs informational messages to stderr
	InfoLog = log.New(os.Stderr, ``, 0)
	// DebugLog logs additional debugging information to stderr when the -debug
	// flag is used
	DebugLog = log.New(ioutil.Discard, ``, 0)
	// ErrorLog logs error messages (which are typically fatal)
	// The philosophy of this program is to fail fast on an error and not try
	// to do any recovery (so the user knows something is wrong and can
	// explicitely fix it)
	ErrorLog = log.New(os.Stderr, `Error: `, 0)
	// Root is the working directory (defaults to "./")
	Root string
	// Overwrite specifies not to abort if the output directory already exists
	Overwrite bool
	// RunTime stores the time the program started running (used to determine
	// certificate NotBefore and NotAfter values)
	RunTime time.Time
	// NilString is a string used to determine whether user input to a flag
	// was provided. This is done by setting the default flag value to
	// NilString.
	NilString = `\x00` // default for string flags (used to detect if user supplied value)
	// Commands is a map from the string name of a command to meta information required to execute the command
	Commands        = map[string]*Command{}
	flagHelpStrings = map[string]string{}
)

func init() {
	RunTime = time.Now().UTC()
	Commands[`version`] = &Command{
		Description: `display certshop version and build date and exit`,
		Function: func(fs *GlobalFlags) {
			InfoLog.Printf("certshop %s\nBuilt: %s\nCopyright (c) 2017 VARASYS Limited", Version, Build)
			InfoLog.Print(License)
			os.Exit(0)
		},
	}
}

func main() {
	fs := ParseGlobalFlags(os.Args[1:])
	if fs.Command != nil {
		fs.Command.Function(fs)
	} else {
		ErrorLog.Printf("Error parsing command: %s", strings.Join(os.Args, ` `))
		printGlobalHelp(os.Stderr, fs)
	}
}

// Command holds meta information about each command
type Command struct {
	Command     string
	Description string
	HelpString  string
	Function    func(*GlobalFlags)
}

// Name does a reverse lookup in the Commands map and returns the key
func (command *Command) Name() string {
	for key, value := range Commands {
		if command == value {
			return key
		}
	}
	ErrorLog.Fatalf("Failed to lookup command name")
	return ""
}

// PrintHelp prints a help message for a command
func (command *Command) PrintHelp(writer *os.File, err error) {
	if tmpl, err2 := template.New("help").Parse(`
{{.Description}}

command line flags:
{{.HelpString}}
`); err2 != nil {
		ErrorLog.Fatalf("Failed to parse help template: %s", err2)
	} else {
		if err3 := tmpl.Execute(writer, command); err != nil {
			ErrorLog.Fatalf("Failed to execute help template: %s", err3)
		}
		if err3 := writer.Sync(); err != nil {
			ErrorLog.Fatalf("Failed to flush output: %s", err3)
		}
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// GlobalFlags holds the global command line flags
type GlobalFlags struct {
	flag.FlagSet
	Root    string
	Debug   bool
	Command *Command
	Args    []string
}

// ParseGlobalFlags parses the global command line flags
func ParseGlobalFlags(args []string) *GlobalFlags {
	DebugLog.Println(`Parsing global flags`)
	fs := GlobalFlags{FlagSet: *flag.NewFlagSet(`certshop`, flag.ContinueOnError)}
	fs.StringVar(&fs.Root, `root`, `./`, `certificate tree root directory`)
	fs.BoolVar(&Overwrite, `overwrite`, false, `don't abort if output directory already exists`)
	fs.BoolVar(&fs.Debug, `debug`, false, `output extra debugging information`)
	if err := fs.Parse(args); err != nil {
		printGlobalHelp(os.Stderr, &fs)
		ErrorLog.Fatalf(`Failed to parse global flags: %s`, strings.Join(args, ` `))
	}
	if fs.Debug {
		DebugLog = log.New(os.Stderr, ``, log.Lshortfile)
		ErrorLog.SetFlags(log.Lshortfile)
	}
	if root, err := filepath.Abs(fs.Root); err != nil {
		ErrorLog.Fatalf("Failed to parse root path %s: %s", fs.Root, err)
	} else {
		fs.Root = root
		SetRootDir(fs.Root)
	}
	fs.Args = fs.FlagSet.Args()
	if len(fs.Args) > 0 {
		fs.Command = Commands[fs.Args[0]]
	} else {
		fs.Command = Commands[`help`]
	}
	return &fs
}

// SetRootDir sets the applications working directory
func SetRootDir(root string) {
	DebugLog.Printf("Using root directory: %s", root)
	if err := os.MkdirAll(root, os.FileMode(0755)); err != nil {
		ErrorLog.Fatalf("Failed to create root directory %s: %s", root, err)
	}
	if err := os.Chdir(root); err != nil {
		ErrorLog.Fatalf("Failed to set root directory to %s: %s", root, err)
	}
}
