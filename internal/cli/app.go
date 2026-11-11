// Package cli implements the azpgaad commands.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/auth"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

// Exit codes, identical on every OS (see README: Exit codes).
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitNotLoggedIn = 3
	ExitInternal    = 4
)

// App holds everything a command touches outside the process, so tests can replace it.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time

	StdinIsTerminal  func() bool
	StdoutIsTerminal func() bool
	// ReadPassword reads a line from the terminal without echo.
	ReadPassword func() (string, error)

	NewCredential func() (azcore.TokenCredential, error)
	HTTP          *http.Client
	GraphBase     string
	// OpenDB opens the database connection described by cfg.
	OpenDB func(cfg pg.ConnConfig) pg.DB

	Version string
	Commit  string

	// per-run state
	globals globalFlags
	db      pg.DB
	prof    *profile.Profile
	stdin   *bufio.Reader
}

type globalFlags struct {
	tokenFile string
	output    string
	query     string
	debug     bool
	echo      bool
}

// New returns an App wired to the real process environment.
func New(version string) *App {
	return &App{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		Getenv:           os.Getenv,
		Now:              time.Now,
		StdinIsTerminal:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		StdoutIsTerminal: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		ReadPassword: func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(b), err
		},
		NewCredential: auth.NewCredential,
		HTTP:          &http.Client{Timeout: time.Minute},
		GraphBase:     auth.GraphBaseURL,
		OpenDB:        func(cfg pg.ConnConfig) pg.DB { return pg.NewLive(cfg) },
		Version:       version,
	}
}

// exitError carries an exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

func notLoggedIn(err error) error { return &exitError{code: ExitNotLoggedIn, err: err} }

// cobra reports these problems as plain errors; they are usage errors.
var usagePrefixes = []string{
	"unknown command", "unknown flag", "unknown shorthand flag", "flag needs an argument",
	"invalid argument", "required flag", "if any flags in the group", "at least one of the flags",
	"accepts ", "requires at least", "requires at most", "too many arguments",
}

// colonSwitch matches --switch:true / --switch:false (also 1/0), a common form in
// PowerShell and MSBuild scripts.
var colonSwitch = regexp.MustCompile(`^(--[A-Za-z0-9][A-Za-z0-9-]*):(?i)(true|false|1|0)$`)

// colonSwitches rewrites --switch:value to --switch=value (which pflag understands) for
// boolean values, up to a "--" terminator. Anything else is left for pflag to handle.
func colonSwitches(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		if arg == "--" {
			copy(out[i:], args[i:])
			return out
		}
		if m := colonSwitch.FindStringSubmatch(arg); m != nil {
			arg = m[1] + "=" + strings.ToLower(m[2])
		}
		out[i] = arg
	}
	return out
}

// Run executes args and returns the process exit code. It is the only place that decides
// exit codes; main calls os.Exit with the result.
func (a *App) Run(args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(a.Stderr, "azpgaad: internal error: %v\n%s", r, debug.Stack())
			code = ExitInternal
		}
	}()
	a.globals = globalFlags{}
	a.stdin = bufio.NewReader(a.Stdin)
	defer func() {
		if a.db != nil {
			a.db.Close()
			a.db = nil
		}
	}()

	root := a.rootCommand()
	root.SetArgs(colonSwitches(args))
	root.SetIn(a.Stdin)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		return ExitOK
	}
	fmt.Fprintln(a.Stderr, "azpgaad: error:", err)
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	msg := err.Error()
	for _, p := range usagePrefixes {
		if strings.HasPrefix(msg, p) {
			fmt.Fprintln(a.Stderr, "Run 'azpgaad --help' for usage.")
			return ExitUsage
		}
	}
	return ExitError
}

func (a *App) warn(msg string) { fmt.Fprintln(a.Stderr, "azpgaad: warning:", msg) }

// info writes a status line to stderr, keeping stdout for the result.
func (a *App) info(msg string) { fmt.Fprintln(a.Stderr, "azpgaad:", msg) }

func (a *App) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "azpgaad",
		Short:         "Manage Microsoft Entra roles on Azure Database for PostgreSQL",
		Version:       a.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `azpgaad manages Microsoft Entra (Azure AD) roles and privileges on Azure Database
for PostgreSQL flexible server, as a single static binary with no dependencies.

Start with 'azpgaad login', which writes a token file. Every other command reads the
token file from --token-file or the PGAADTOKENFILE environment variable (a path).

Without a token file (e.g. in a short-lived CI container), set PGAADSERVER instead: every
command then gets its own Microsoft Entra token from DefaultAzureCredential and writes
nothing to disk. Optional: PGAADUSER (else looked up in Microsoft Graph), PGAADDATABASE
(default postgres), PGAADSSLMODE (default verify-full), PGAADSSLROOTCERT (default system,
or a PEM file). A token file, if named, takes precedence.

Switches accept --switch, --switch=true|false and --switch:true|false.`,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	pf := root.PersistentFlags()
	pf.StringVar(&a.globals.tokenFile, "token-file", "", "token file written by 'azpgaad login' (default: $PGAADTOKENFILE)")
	pf.StringVarP(&a.globals.output, "output", "o", "tsv", "output format: tsv (an object as a 'key: value' list, an array as tab-separated rows), json (indented) or jsonc (compact, one line)")
	pf.StringVar(&a.globals.query, "query", "", "JMESPath query applied to the JSON result (same as az --query)")
	pf.BoolVar(&a.globals.debug, "debug", false, "show every SQL statement and its parameter values on stderr")
	pf.BoolVar(&a.globals.echo, "echo", false, "write each statement that changes something to stderr as SQL as it runs (BEGIN/COMMIT included; --dry-run statements are marked)")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		switch a.globals.output {
		case "tsv", "json", "jsonc":
		default:
			return usageErrorf("--output must be tsv, json or jsonc, not %q", a.globals.output)
		}
		return nil
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &exitError{code: ExitUsage, err: err}
	})

	root.AddCommand(
		a.versionCommand(),
		a.loginCommand(),
		a.serverCommand(),
		a.dbCommand(),
		a.schemaCommand(),
		a.tableCommand(),
		a.defaultPrivilegesCommand(),
		a.principalCommand(),
		a.roleCommand(),
		a.applyCommand(),
		a.privilegesCommand(),
		a.ownerCommand(),
	)
	return root
}

// confirm asks before a destructive action unless --yes was given. Without a terminal it
// refuses rather than hanging.
func (a *App) confirm(yes bool, question string) error {
	if yes {
		return nil
	}
	if !a.StdinIsTerminal() {
		return usageErrorf("%s: refusing without --yes (no terminal to confirm on)", question)
	}
	fmt.Fprintf(a.Stderr, "%s [y/N] ", question)
	line, _ := a.stdin.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errors.New("aborted")
}
