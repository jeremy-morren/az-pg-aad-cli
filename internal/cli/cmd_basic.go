package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

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
			if !contains(pg.ValidSSLModes, sslmode) {
				return usageErrorf("--sslmode must be one of %s", strings.Join(pg.ValidSSLModes, ", "))
			}
			switch sslmode {
			case "disable", "allow", "prefer":
				a.warn(fmt.Sprintf("--sslmode %s may send the password/token unencrypted", sslmode))
			}
			root := profile.RootCert{Mode: "system"}
			if rootcert != "" && rootcert != "system" {
				pemBytes, err := os.ReadFile(rootcert)
				if err != nil {
					return usageErrorf("--sslrootcert: %v", err)
				}
				if !x509.NewCertPool().AppendCertsFromPEM(pemBytes) {
					return usageErrorf("--sslrootcert: no PEM certificates found in %s", rootcert)
				}
				root = profile.RootCert{Mode: "pem", PEM: string(pemBytes)}
			}
			if !strings.Contains(server, ".") {
				server += ".postgres.database.azure.com"
			}
			p := &profile.Profile{
				V: profile.Version, Server: server, Port: port, Database: database,
				SSLMode: sslmode, SSLRootCert: root,
			}
			if useAzure {
				if err := a.loginAzure(ctx, p, username); err != nil {
					return err
				}
			} else {
				pw, err := a.readPassword(pgPassEnv, cmd.Flags().Changed("pg-pass-env-var"))
				if err != nil {
					return err
				}
				p.User, p.Auth = pgUser, profile.Auth{Method: "pg", Password: pw}
			}

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
			out := struct {
				TokenFile   string     `json:"tokenFile"`
				Server      string     `json:"server"`
				Database    string     `json:"database"`
				User        string     `json:"user"`
				Method      string     `json:"method"`
				SSLMode     string     `json:"sslmode"`
				SSLRootCert string     `json:"sslrootcert"`
				Expires     *time.Time `json:"expires"`
				Version     string     `json:"serverVersion"`
			}{path, p.Server, p.Database, check.CurrentUser, p.Auth.Method, p.SSLMode, root.Mode, nil, check.Version}
			if p.Auth.Method == "azure" {
				out.Expires = &p.Auth.Expires
			}
			return a.print(out)
		},
	}
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

// readPassword returns the password for --pg-username: the value of envVar (default
// PGPASSWORD) if set; otherwise a prompt, unless the variable was named explicitly (then
// it must be set) or there is no terminal to prompt on.
func (a *App) readPassword(envVar string, explicit bool) (string, error) {
	if v := a.Getenv(envVar); v != "" {
		return v, nil
	}
	if explicit {
		return "", usageErrorf("--pg-pass-env-var: environment variable %s is not set or empty", envVar)
	}
	if !a.StdinIsTerminal() {
		return "", usageErrorf("no password: set %s or pass --pg-pass-env-var (there is no terminal to prompt on)", envVar)
	}
	fmt.Fprint(a.Stderr, "Password: ")
	pw, err := a.ReadPassword()
	fmt.Fprintln(a.Stderr)
	return pw, err
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
` + docsSeeAlso,
		Args: cobra.NoArgs,
	}
	exclude := a.addList(list, "exclude-name", "exclude-names", "principal name to leave out", false)
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
		return a.print(out)
	}
	cmd.AddCommand(list)
	return cmd
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
