package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/auth"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			commit := a.Commit
			if bi, ok := debug.ReadBuildInfo(); ok && commit == "" {
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" {
						commit = s.Value
					}
				}
			}
			return a.print(struct {
				Version   string `json:"version"`
				Commit    string `json:"commit"`
				GoVersion string `json:"goVersion"`
				OS        string `json:"os"`
				Arch      string `json:"arch"`
			}{a.Version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH})
		},
	}
}

func (a *App) loginCommand() *cobra.Command {
	var (
		server, database, sslmode, rootcert string
		port                                int
		useAzure                            bool
		username, pgUser, pgPassEnv         string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and write the token file used by every other command",
		Long: `Connects once to check the credentials, then writes the token file named by
--token-file or $PGAADTOKENFILE.

  --azure                 Microsoft Entra token from DefaultAzureCredential (environment
                          service principal, workload identity, managed identity, az CLI,
                          azd). The token is stored and refreshed automatically when it is
                          within 10 minutes of expiry. The Postgres username is --username,
                          else looked up in Microsoft Graph, else taken from the token.
  --pg-username U         Plain Postgres authentication. The password comes from the
                          environment variable named by --pg-pass-env-var (default
                          PGPASSWORD, like psql). If that default isn't set, you're
                          prompted; a variable named explicitly must be set.`,
		Example: `  export PGAADTOKENFILE=~/.azpgaad/test.json
  azpgaad login --server myserver.postgres.database.azure.com --azure
  PGPASSWORD=... azpgaad login --server myserver --pg-username admin
  azpgaad login --server myserver --pg-username admin --pg-pass-env-var ADMIN_PASSWORD`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			path, err := a.tokenPath()
			if err != nil {
				return err
			}
			p, err := a.newProfile("--", server, port, database, sslmode, rootcert)
			if err != nil {
				return err
			}
			var how string
			if useAzure {
				if err := a.loginAzure(ctx, p, username); err != nil {
					return err
				}
				how = "a Microsoft Entra token (DefaultAzureCredential)"
			} else {
				pw, src, err := a.readPassword(pgPassEnv, cmd.Flags().Changed("pg-pass-env-var"))
				if err != nil {
					return err
				}
				p.User, p.Auth = pgUser, profile.Auth{Method: "pg", Password: pw}
				how = "a password (" + src + ")"
			}
			a.info(loginLine(p, how))

			db := a.openDB(p)
			defer db.Close()
			s, err := db.In(ctx, database)
			if err != nil {
				return err
			}
			var check struct {
				CurrentUser string `json:"currentUser"`
				Version     string `json:"version"`
			}
			if err := queryInto(ctx, s, &check, sqlLoginCheck); err != nil {
				return err
			}
			if err := profile.Save(path, p); err != nil {
				return err
			}
			out := newLoginInfo(path, p)
			out.User, out.ServerVersion = check.CurrentUser, check.Version
			return a.print(out)
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show the connection settings in the token file (never the token or password)",
		Long: `Reads the token file named by --token-file or $PGAADTOKENFILE and shows what the
other commands will use (or, without a token file, the PGAAD* environment variables;
see azpgaad --help): server, port, database, user, authentication method, sslmode,
trusted CAs (sslrootcert: 'system' for the machine's trust store, or 'embedded' for a PEM
file copied in at login, with the certificate subjects), and for --azure the token's
expiry. Nothing is refreshed and the server isn't contacted.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if a.useEnvLogin() {
				p, err := a.envProfile()
				if err != nil {
					return err
				}
				return a.print(newLoginInfo("", p))
			}
			path, err := a.tokenPath()
			if err != nil {
				return err
			}
			p, err := profile.Load(path)
			if err != nil {
				return notLoggedIn(err)
			}
			return a.print(newLoginInfo(path, p))
		},
	})
	f := cmd.Flags()
	f.StringVar(&server, "server", "", "server name (expanded to <name>.postgres.database.azure.com) or fully qualified host name")
	f.IntVar(&port, "port", 5432, "port")
	f.StringVar(&database, "database", "postgres", "database to connect to by default")
	f.StringVar(&sslmode, "sslmode", "verify-full", "TLS mode: "+strings.Join(pg.ValidSSLModes, ", "))
	f.StringVar(&rootcert, "sslrootcert", "system", "trusted CAs: 'system' (the machine's trust store) or a PEM file path")
	f.BoolVar(&useAzure, "azure", false, "authenticate with a Microsoft Entra token (DefaultAzureCredential)")
	f.StringVar(&username, "username", "", "Postgres role name for --azure (default: looked up in Microsoft Graph)")
	f.StringVar(&pgUser, "pg-username", "", "Postgres user name for plain password authentication")
	f.StringVar(&pgPassEnv, "pg-pass-env-var", "PGPASSWORD", "environment variable holding the password for --pg-username (if the default isn't set: prompt)")
	_ = cmd.MarkFlagRequired("server")
	cmd.MarkFlagsMutuallyExclusive("azure", "pg-username")
	cmd.MarkFlagsOneRequired("azure", "pg-username")
	cmd.MarkFlagsMutuallyExclusive("username", "pg-username")
	cmd.MarkFlagsMutuallyExclusive("pg-pass-env-var", "azure")
	return cmd
}

// newProfile checks and normalizes the connection settings shared by login and the
// PGAADSERVER environment variables. flagPrefix names the settings in errors ("--" for
// login's flags, "PGAAD" for the environment variables).
func (a *App) newProfile(flagPrefix, server string, port int, database, sslmode, rootcert string) (*profile.Profile, error) {
	name := func(s string) string {
		if flagPrefix == "--" {
			return "--" + s
		}
		return flagPrefix + strings.ToUpper(s)
	}
	if server == "" {
		return nil, usageErrorf("%s is required", name("server"))
	}
	if !contains(pg.ValidSSLModes, sslmode) {
		return nil, usageErrorf("%s must be one of %s", name("sslmode"), strings.Join(pg.ValidSSLModes, ", "))
	}
	switch sslmode {
	case "disable", "allow", "prefer":
		a.warn(fmt.Sprintf("%s %s may send the password/token unencrypted", name("sslmode"), sslmode))
	}
	root := profile.RootCert{Mode: "system"}
	if rootcert != "" && rootcert != "system" {
		pemBytes, err := os.ReadFile(rootcert)
		if err != nil {
			return nil, usageErrorf("%s: %v", name("sslrootcert"), err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pemBytes) {
			return nil, usageErrorf("%s: no PEM certificates found in %s", name("sslrootcert"), rootcert)
		}
		root = profile.RootCert{Mode: "pem", PEM: string(pemBytes)}
	}
	if !strings.Contains(server, ".") {
		server += ".postgres.database.azure.com"
	}
	return &profile.Profile{
		V: profile.Version, Server: server, Port: port, Database: database,
		SSLMode: sslmode, SSLRootCert: root,
	}, nil
}

func (a *App) loginAzure(ctx context.Context, p *profile.Profile, username string) error {
	cred, err := a.NewCredential()
	if err != nil {
		return err
	}
	tok, err := auth.GetToken(ctx, cred, auth.DatabaseScope, a.Now())
	if err != nil {
		return err
	}
	if username == "" {
		r := auth.Resolver{Cred: cred, HTTP: a.HTTP, GraphBase: a.GraphBase, Now: a.Now, Warn: a.warn}
		if username, err = r.Username(ctx, tok.Value); err != nil {
			return err
		}
	}
	p.User = username
	p.Auth = profile.Auth{Method: "azure", Token: tok.Value, Expires: tok.Expires}
	return nil
}

// loginInfo describes a token file, for login and login show. It never includes the
// token or password.
type loginInfo struct {
	Source              string   `json:"source"`
	TokenFile           string   `json:"tokenFile,omitempty"`
	Server              string   `json:"server"`
	Port                int      `json:"port"`
	Database            string   `json:"database"`
	User                string   `json:"user"`
	Method              string   `json:"method"`
	SSLMode             string   `json:"sslmode"`
	SSLRootCert         string   `json:"sslrootcert"`
	SSLRootCertSubjects []string `json:"sslrootcertSubjects,omitempty"`
	Expires             string   `json:"expires,omitempty"`
	ServerVersion       string   `json:"serverVersion,omitempty"`
}

func newLoginInfo(path string, p *profile.Profile) loginInfo {
	source := "token file"
	if path == "" {
		source = "environment (" + envServer + ")"
	}
	info := loginInfo{
		Source: source, TokenFile: path, Server: p.Server, Port: p.Port, Database: p.Database, User: p.User,
		Method: p.Auth.Method, SSLMode: p.SSLMode, SSLRootCert: "system",
	}
	if p.SSLRootCert.Mode == "pem" {
		info.SSLRootCert = "embedded"
		rest := []byte(p.SSLRootCert.PEM)
		for {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				break
			}
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				info.SSLRootCertSubjects = append(info.SSLRootCertSubjects, c.Subject.String())
			}
		}
	}
	if p.Auth.Method == "azure" {
		info.Expires = formatTime(p.Auth.Expires)
	}
	return info
}

// loginLine is the status line login prints before connecting, e.g.
// "logging into server s.postgres.database.azure.com:5432 (database postgres, sslmode
// verify-full) as alice@contoso.com with a Microsoft Entra token (DefaultAzureCredential)".
func loginLine(p *profile.Profile, how string) string {
	return fmt.Sprintf("logging into server %s:%d (database %s, sslmode %s) as %s with %s",
		p.Server, p.Port, p.Database, p.SSLMode, p.User, how)
}

// readPassword returns the password for --pg-username and where it came from: the value
// of envVar (default PGPASSWORD) if set; otherwise a prompt, unless the variable was named
// explicitly (then it must be set) or there is no terminal to prompt on.
func (a *App) readPassword(envVar string, explicit bool) (pw, source string, err error) {
	if v := a.Getenv(envVar); v != "" {
		return v, "from $" + envVar, nil
	}
	if explicit {
		return "", "", usageErrorf("--pg-pass-env-var: environment variable %s is not set or empty", envVar)
	}
	if !a.StdinIsTerminal() {
		return "", "", usageErrorf("no password: set %s or pass --pg-pass-env-var (there is no terminal to prompt on)", envVar)
	}
	fmt.Fprint(a.Stderr, "Password: ")
	pw, err = a.ReadPassword()
	fmt.Fprintln(a.Stderr)
	return pw, "entered at the prompt", err
}

func (a *App) serverCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "server", Short: "Server information"}
	cmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show the server version, current user and pgaadauth version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := a.session(ctx, aadDatabase)
			if err != nil {
				return err
			}
			var info struct {
				Version          string  `json:"version"`
				VersionNum       int     `json:"versionNum"`
				VersionString    string  `json:"versionString"`
				CurrentUser      string  `json:"currentUser"`
				SessionUser      string  `json:"sessionUser"`
				Database         string  `json:"database"`
				PgaadauthVersion *string `json:"pgaadauthVersion"`
			}
			if err := queryInto(ctx, s, &info, sqlServerInfo); err != nil {
				return err
			}
			return a.print(struct {
				Version          string  `json:"version"`
				VersionNum       int     `json:"versionNum"`
				Major            int     `json:"major"`
				Minor            int     `json:"minor"`
				VersionString    string  `json:"versionString"`
				CurrentUser      string  `json:"currentUser"`
				SessionUser      string  `json:"sessionUser"`
				Database         string  `json:"database"`
				PgaadauthVersion *string `json:"pgaadauthVersion"`
			}{
				info.Version,
				info.VersionNum,
				info.VersionNum / 10000,
				info.VersionNum % 10000,
				info.VersionString,
				info.CurrentUser,
				info.SessionUser,
				info.Database,
				info.PgaadauthVersion,
			})
		},
	})
	return cmd
}

type namedOwner struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

func (a *App) listSchemas(ctx context.Context, database string, all bool) ([]namedOwner, error) {
	s, err := a.session(ctx, database)
	if err != nil {
		return nil, err
	}
	var out []namedOwner
	err = queryInto(ctx, s, &out, sqlSchemas, all)
	return out, err
}

func (a *App) dbCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Databases and database privileges"}
	var withSchemas, allSchemas bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List databases (optionally with their schemas)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := a.session(ctx, aadDatabase)
			if err != nil {
				return err
			}
			var dbs []namedOwner
			if err := queryInto(ctx, s, &dbs, sqlDatabases); err != nil {
				return err
			}
			if !withSchemas {
				return a.print(dbs)
			}
			type dbWithSchemas struct {
				Name    string       `json:"name"`
				Owner   string       `json:"owner"`
				Schemas []namedOwner `json:"schemas"`
				Error   *string      `json:"error"`
			}
			out := make([]dbWithSchemas, 0, len(dbs))
			for _, d := range dbs {
				row := dbWithSchemas{Name: d.Name, Owner: d.Owner}
				schemas, err := a.listSchemas(ctx, d.Name, allSchemas)
				if err != nil {
					msg := err.Error()
					row.Error = &msg
				} else {
					row.Schemas = schemas
				}
				out = append(out, row)
			}
			return a.print(out)
		},
	}
	list.Flags().BoolVar(&withSchemas, "with-schemas", false, "also list each database's schemas (databases that can't be opened get an error field)")
	list.Flags().BoolVar(&allSchemas, "all-schemas", false, "include pg_*, information_schema and cron")
	cmd.AddCommand(list, a.dbGrantCommand(true), a.dbGrantCommand(false))
	return cmd
}

func (a *App) schemaCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "schema", Short: "Schemas and schema privileges"}
	var database string
	var all bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List schemas in a database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := a.listSchemas(cmd.Context(), database, all)
			if err != nil {
				return err
			}
			return a.print(out)
		},
	}
	list.Flags().StringVar(&database, "database", "", "database (default: the token file's database)")
	list.Flags().BoolVar(&all, "all-schemas", false, "include pg_*, information_schema and cron")
	cmd.AddCommand(list, a.schemaGrantCommand(true), a.schemaGrantCommand(false))
	return cmd
}

func (a *App) principalCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "principal", Short: "Microsoft Entra principals"}
	var excludeSelf bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List Microsoft Entra principals (pgaadauth_list_principals)",
		Long: `Lists the PostgreSQL roles mapped to Microsoft Entra objects:
  select * from pg_catalog.pgaadauth_list_principals(false)
(false = all Microsoft Entra roles, admins and non-admins.)

` + docPrincipalFields + `

--exclude-self and --exclude-name/--exclude-names leave principals out, e.g. to find roles
that aren't in a desired list (JMESPath --query has no set difference).
Built-in principals (names starting with ` + builtinPrefix + `) are left out
unless --include-builtin.
` + docsSeeAlso,
		Args: cobra.NoArgs,
	}
	exclude := a.addList(list, "exclude-name", "exclude-names", "principal name to leave out", false)
	var includeBuiltin bool
	list.Flags().BoolVar(&includeBuiltin, "include-builtin", false, "include built-in principals (names starting with "+builtinPrefix+")")
	list.Flags().BoolVar(&excludeSelf, "exclude-self", false, "leave out the logged-in user")
	list.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		names, _, err := a.listValues(cmd, exclude)
		if err != nil {
			return err
		}
		if names == nil {
			names = []string{}
		}
		s, err := a.session(ctx, aadDatabase)
		if err != nil {
			return err
		}
		var out []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			ObjectID string `json:"objectId"`
			TenantID string `json:"tenantId"`
			IsMFA    bool   `json:"isMfa"`
			IsAdmin  bool   `json:"isAdmin"`
		}
		if err := queryInto(ctx, s, &out, sqlPrincipals, excludeSelf, names); err != nil {
			return err
		}
		kept := out[:0]
		for _, p := range out {
			if includeBuiltin || !isBuiltinPrincipal(p.Name) {
				kept = append(kept, p)
			}
		}
		return a.print(kept)
	}
	cmd.AddCommand(list)
	return cmd
}

// builtinPrefix marks built-in Entra principals (by name; Microsoft doesn't document them). principal list hides
// them by default and apply never prunes them.
const builtinPrefix = "aad_"

func isBuiltinPrincipal(name string) bool { return strings.HasPrefix(name, builtinPrefix) }

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
