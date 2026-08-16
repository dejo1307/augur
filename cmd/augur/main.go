// Command augur shows you what is hidden in a file, and writes a clean copy.
//
// This is the entrypoint and nothing more: argument handling belongs in
// internal/cli, the interactive loop in internal/tui, and neither may be imported
// into anything but here.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dejo1307/augur/internal/cli"
	"github.com/dejo1307/augur/internal/tui"
	"github.com/dejo1307/augur/pkg/finding"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `augur — see what is hidden in a file

usage:
  augur                    open the interactive viewer
  augur FILE               open FILE in the interactive viewer
  augur scan FILE [--json] report findings and exit
  augur clean FILE -o OUT  write a cleaned copy without prompting
  augur agents             scan the instruction files your coding agents read
  augur upgrade [--check]  replace this binary with the newest release

exit codes:
  0  nothing found
  1  findings present
  2  could not read or parse the file
`

func main() {
	if len(os.Args) < 2 {
		run("")
		return
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "--version", "version":
		fmt.Printf("augur %s\n", version)
	case "--categories":
		for _, c := range finding.Categories() {
			fmt.Println(c)
		}
	case "scan":
		os.Exit(cli.Scan(os.Args[2:], os.Stdout, os.Stderr))
	case "clean":
		os.Exit(cli.Clean(os.Args[2:], os.Stdout, os.Stderr))
	case "agents":
		os.Exit(cli.Agents(os.Args[2:], os.Stdout, os.Stderr))
	case "upgrade":
		os.Exit(cli.Upgrade(os.Args[2:], version, os.Stdout, os.Stderr))
	default:
		// Anything else is taken to be a path: `augur FILE` opens the viewer.
		// Guessing wrong is cheap here — a nonexistent path reports itself — and
		// the alternative makes the commonest invocation the longest one.
		if strings.HasPrefix(os.Args[1], "-") {
			fmt.Fprintf(os.Stderr, "augur: unknown flag %q\n\n%s", os.Args[1], usage)
			os.Exit(cli.ExitError)
		}
		run(os.Args[1])
	}
}

func run(path string) {
	if err := tui.Run(path); err != nil {
		fmt.Fprintln(os.Stderr, "augur:", err)
		os.Exit(cli.ExitError)
	}
}
