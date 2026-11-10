package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

func verbs(grant bool) (verb, prep, use string) {
	if grant {
		return "GRANT", "TO", "grant"
	}
	return "REVOKE", "FROM", "revoke"
}

// privCmd holds the flags shared by the privilege grant/revoke commands.
type privCmd struct {
	names, privs, schemas *listFlag
	database              string
	dryRun                bool
	// ifExists (revoke only) skips grantees, schemas and tables that don't exist, so a
	// revoke can be re-run safely. Grants are already idempotent in Postgres.
	ifExists bool
	skipped  []string
}

func (a *App) newPrivCmd(cmd *cobra.Command, allowed []string, withSchemas, grant bool) *privCmd {
	p := &privCmd{}
	p.names = a.addList(cmd, "name", "names", "grantee role name", true)
	p.privs = a.addList(cmd, "privilege", "privileges", "privilege ("+strings.Join(allowed, ", ")+")", true)
	if withSchemas {
		p.schemas = a.addList(cmd, "schema", "schemas", "schema (default: every non-system schema)", false)
	}
	cmd.Flags().StringVar(&p.database, "database", "", "database (required)")
	cmd.Flags().BoolVar(&p.dryRun, "dry-run", false, "print the SQL without running it")
	if !grant {
		cmd.Flags().BoolVar(&p.ifExists, "if-exists", false, "skip roles, schemas and tables that don't exist instead of failing")
	}
	_ = cmd.MarkFlagRequired("database")
	return p
}

func (a *App) privValues(cmd *cobra.Command, p *privCmd, allowed []string) (names, privs []string, err error) {
	if names, _, err = a.listValues(cmd, p.names); err != nil {
		return
	}
	var raw []string
	if raw, _, err = a.listValues(cmd, p.privs); err != nil {
		return
	}
	if privs, err = normalizePrivileges(p.privs.plural, raw, allowed); err != nil {
		return
	}
	names = dedupe(names)
	if p.ifExists {
		var skipped []string
		if names, skipped, err = a.existingRoles(cmd.Context(), names); err != nil {
			return
		}
		p.skipped = append(p.skipped, skipped...)
	}
	return names, privs, nil
}

// targetSchemas returns --schema/--schemas (checked to exist) or every non-system schema.
func (a *App) targetSchemas(ctx context.Context, cmd *cobra.Command, p *privCmd) ([]string, error) {
	requested, given, err := a.listValues(cmd, p.schemas)
	if err != nil {
		return nil, err
	}
	if !given {
		all, err := a.listSchemas(ctx, p.database, false)
		if err != nil {
			return nil, err
		}
		out := make([]string, len(all))
		for i, s := range all {
			out[i] = s.Name
		}
		return out, nil
	}
	requested = dedupe(requested)
	if len(requested) == 0 {
		return nil, nil
	}
	s, err := a.session(ctx, p.database)
	if err != nil {
		return nil, err
	}
	var existing []string
	if err := queryInto(ctx, s, &existing, sqlSchemasNamed, requested); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range requested {
		switch {
		case contains(existing, r):
			out = append(out, r)
		case p.ifExists:
			p.skipped = append(p.skipped, "schema:"+r)
		default:
			return nil, fmt.Errorf("schema %q does not exist in database %s", r, p.database)
		}
	}
	return out, nil
}

func (a *App) dbGrantCommand(grant bool) *cobra.Command {
	verb, prep, use := verbs(grant)
	cmd := &cobra.Command{
		Use:   use,
		Short: strings.ToUpper(use[:1]) + use[1:] + " database privileges (CONNECT, CREATE, TEMPORARY)",
		Args:  cobra.NoArgs,
	}
	p := a.newPrivCmd(cmd, dbPrivileges, false, grant)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		names, privs, err := a.privValues(cmd, p, dbPrivileges)
		if err != nil {
			return err
		}
		var stmts []string
		if len(names) > 0 && len(privs) > 0 {
			stmts = []string{fmt.Sprintf("%s %s ON DATABASE %s %s %s", verb, strings.Join(privs, ", "), pg.Ident(p.database), prep, pg.Idents(names))}
		}
		// Database privileges can be changed from any database; use the AAD one so no
		// extra connection is opened.
		return a.execStatements(cmd.Context(), aadDatabase, stmts, p.dryRun, p.skipped...)
	}
	return cmd
}

func (a *App) schemaGrantCommand(grant bool) *cobra.Command {
	verb, prep, use := verbs(grant)
	cmd := &cobra.Command{
		Use:   use,
		Short: strings.ToUpper(use[:1]) + use[1:] + " schema privileges (USAGE, CREATE)",
		Args:  cobra.NoArgs,
	}
	p := a.newPrivCmd(cmd, schemaPrivileges, true, grant)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		names, privs, err := a.privValues(cmd, p, schemaPrivileges)
		if err != nil {
			return err
		}
		if len(names) == 0 || len(privs) == 0 {
			return a.execStatements(ctx, p.database, nil, p.dryRun, p.skipped...)
		}
		schemas, err := a.targetSchemas(ctx, cmd, p)
		if err != nil {
			return err
		}
		var stmts []string
		for _, s := range schemas {
			stmts = append(stmts, fmt.Sprintf("%s %s ON SCHEMA %s %s %s", verb, strings.Join(privs, ", "), pg.Ident(s), prep, pg.Idents(names)))
		}
		return a.execStatements(ctx, p.database, stmts, p.dryRun, p.skipped...)
	}
	return cmd
}

func (a *App) tableCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "table", Short: "Table privileges"}
	cmd.AddCommand(a.tableGrantCommand(true), a.tableGrantCommand(false))
	return cmd
}

func (a *App) tableGrantCommand(grant bool) *cobra.Command {
	verb, prep, use := verbs(grant)
	cmd := &cobra.Command{
		Use:   use,
		Short: strings.ToUpper(use[:1]) + use[1:] + " table privileges (all tables in the schemas, or named tables)",
		Args:  cobra.NoArgs,
	}
	p := a.newPrivCmd(cmd, tablePrivileges, true, grant)
	tables := a.addList(cmd, "table", "tables", "table name (looked up in the selected schemas)", false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		names, privs, err := a.privValues(cmd, p, tablePrivileges)
		if err != nil {
			return err
		}
		wanted, named, err := a.listValues(cmd, tables)
		if err != nil {
			return err
		}
		if len(names) == 0 || len(privs) == 0 || (named && len(wanted) == 0) {
			return a.execStatements(ctx, p.database, nil, p.dryRun, p.skipped...)
		}
		schemas, err := a.targetSchemas(ctx, cmd, p)
		if err != nil {
			return err
		}
		head := fmt.Sprintf("%s %s ON", verb, strings.Join(privs, ", "))
		tail := fmt.Sprintf("%s %s", prep, pg.Idents(names))
		var stmts []string
		if !named {
			for _, s := range schemas {
				stmts = append(stmts, fmt.Sprintf("%s ALL TABLES IN SCHEMA %s %s", head, pg.Ident(s), tail))
			}
			return a.execStatements(ctx, p.database, stmts, p.dryRun, p.skipped...)
		}
		wanted = dedupe(wanted)
		s, err := a.session(ctx, p.database)
		if err != nil {
			return err
		}
		var found []struct {
			Schema string `json:"schema"`
			Name   string `json:"name"`
		}
		if err := queryInto(ctx, s, &found, sqlTablesNamed, schemas, wanted); err != nil {
			return err
		}
		where := map[string][]string{}
		for _, f := range found {
			where[f.Name] = append(where[f.Name], f.Schema)
		}
		var targets []string
		for _, t := range wanted {
			switch len(where[t]) {
			case 0:
				if p.ifExists {
					p.skipped = append(p.skipped, "table:"+t)
					continue
				}
				return fmt.Errorf("table %q not found in schema(s) %s of database %s", t, strings.Join(schemas, ", "), p.database)
			case 1:
				targets = append(targets, qualified(where[t][0], t))
			default:
				return fmt.Errorf("table %q exists in schemas %s: choose one with --schema", t, strings.Join(where[t], ", "))
			}
		}
		if len(targets) > 0 {
			stmts = []string{fmt.Sprintf("%s TABLE %s %s", head, strings.Join(targets, ", "), tail)}
		}
		return a.execStatements(ctx, p.database, stmts, p.dryRun, p.skipped...)
	}
	return cmd
}

func (a *App) defaultPrivilegesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "default-privileges", Short: "Default privileges for objects created later"}
	cmd.AddCommand(a.defaultPrivilegesGrantCommand(true), a.defaultPrivilegesGrantCommand(false))
	return cmd
}

func (a *App) defaultPrivilegesGrantCommand(grant bool) *cobra.Command {
	verb, prep, use := verbs(grant)
	var on string
	cmd := &cobra.Command{
		Use:   use,
		Short: strings.ToUpper(use[:1]) + use[1:] + " default privileges (ALTER DEFAULT PRIVILEGES)",
		Long: `ALTER DEFAULT PRIVILEGES … IN SCHEMA … ` + verb + ` … ON <objects> ` + prep + ` <roles>.

Without --for-role/--for-roles this only affects objects created later by the logged-in
user, not by other roles (Postgres semantics). Name the roles that will create the
objects (e.g. the application's role) with --for-role.`,
		Args: cobra.NoArgs,
	}
	all := append(append([]string{}, tablePrivileges...), "USAGE", "EXECUTE")
	p := a.newPrivCmd(cmd, all, true, grant)
	forRoles := a.addList(cmd, "for-role", "for-roles", "role whose future objects are affected", false)
	cmd.Flags().StringVar(&on, "on", "tables", "object type: tables, sequences or functions")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		allowed, ok := defaultObjects[on]
		if !ok {
			return usageErrorf("--on must be tables, sequences or functions")
		}
		names, privs, err := a.privValues(cmd, p, allowed)
		if err != nil {
			return err
		}
		owners, _, err := a.listValues(cmd, forRoles)
		if err != nil {
			return err
		}
		if p.ifExists {
			var skipped []string
			if owners, skipped, err = a.existingRoles(ctx, dedupe(owners)); err != nil {
				return err
			}
			p.skipped = append(p.skipped, skipped...)
		}
		if len(names) == 0 || len(privs) == 0 {
			return a.execStatements(ctx, p.database, nil, p.dryRun, p.skipped...)
		}
		schemas, err := a.targetSchemas(ctx, cmd, p)
		if err != nil {
			return err
		}
		head := "ALTER DEFAULT PRIVILEGES"
		if owners = dedupe(owners); len(owners) > 0 {
			head += " FOR ROLE " + pg.Idents(owners)
		}
		var stmts []string
		for _, s := range schemas {
			stmts = append(stmts, fmt.Sprintf("%s IN SCHEMA %s %s %s ON %s %s %s",
				head, pg.Ident(s), verb, strings.Join(privs, ", "), strings.ToUpper(on), prep, pg.Idents(names)))
		}
		return a.execStatements(ctx, p.database, stmts, p.dryRun, p.skipped...)
	}
	return cmd
}

func (a *App) privilegesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "privileges", Short: "Inspect privileges"}
	var database, level string
	list := &cobra.Command{
		Use:   "list",
		Short: "Effective privileges per role (database, schema, table or default privileges)",
		Args:  cobra.NoArgs,
	}
	names := a.addList(list, "name", "names", "role name (default: all non-system roles and PUBLIC)", false)
	list.Flags().StringVar(&database, "database", "", "database (default: the token file's database)")
	list.Flags().StringVar(&level, "level", "db", "db, schema, table or default")
	list.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		roles, given, err := a.listValues(cmd, names)
		if err != nil {
			return err
		}
		s, err := a.session(ctx, database)
		if err != nil {
			return err
		}
		if database == "" {
			database = a.prof.Database
		}
		if level == "default" {
			if !given {
				roles = []string{}
			}
			var out []struct {
				Owner      string  `json:"owner"`
				Schema     *string `json:"schema"`
				ObjectType string  `json:"objectType"`
				Grantee    string  `json:"grantee"`
				Privilege  string  `json:"privilege"`
			}
			if err := queryInto(ctx, s, &out, sqlPrivilegesDefault, dedupe(roles)); err != nil {
				return err
			}
			return a.print(out)
		}
		if !given {
			if err := queryInto(ctx, s, &roles, sqlDefaultRoleNames); err != nil {
				return err
			}
			roles = append(roles, "public")
		}
		roles = dedupe(roles)
		switch level {
		case "db":
			var out []struct {
				Role       string   `json:"role"`
				Database   string   `json:"database"`
				Privileges []string `json:"privileges"`
			}
			if err := queryInto(ctx, s, &out, sqlPrivilegesDB, database, roles); err != nil {
				return err
			}
			return a.print(out)
		case "schema":
			var out []struct {
				Role       string   `json:"role"`
				Schema     string   `json:"schema"`
				Privileges []string `json:"privileges"`
			}
			if err := queryInto(ctx, s, &out, sqlPrivilegesSchema, roles); err != nil {
				return err
			}
			return a.print(out)
		case "table":
			var out []struct {
				Role       string   `json:"role"`
				Schema     string   `json:"schema"`
				Table      string   `json:"table"`
				Privileges []string `json:"privileges"`
			}
			if err := queryInto(ctx, s, &out, sqlPrivilegesTable, roles); err != nil {
				return err
			}
			return a.print(out)
		default:
			return usageErrorf("--level must be db, schema, table or default")
		}
	}
	cmd.AddCommand(list)
	return cmd
}
