package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

func (a *App) roleCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "role", Short: "Postgres roles, including Microsoft Entra principals"}
	cmd.AddCommand(
		a.roleListCommand(),
		a.roleCreateCommand(),
		a.roleEnableOIDCommand(),
		a.roleDropCommand(),
		a.roleGrantCommand(true),
		a.roleGrantCommand(false),
		a.roleRevokeAllCommand(),
	)
	return cmd
}

// roleInfo is one role in 'role list'.
type roleInfo struct {
	RoleName     string   `json:"roleName"`
	MemberOf     []string `json:"memberOf"`
	DBPrivileges []string `json:"dbPrivileges"`
	Database     *string  `json:"database"`
	AAD          *aadInfo `json:"aad"`
}

type aadInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	ObjectID string `json:"objectId"`
	TenantID string `json:"tenantId"`
	IsAdmin  bool   `json:"isAdmin"`
}

func (a *App) roleListCommand() *cobra.Command {
	var database string
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles with memberships, Entra details and (with --database) database privileges",
		Long: `Lists PostgreSQL roles (pg_roles), each with:
  roleName      the role
  memberOf      roles it is a member of (null if none)
  dbPrivileges  with --database: which of CONNECT, CREATE, TEMPORARY it has there,
                including through membership (null if none)
  aad           null for roles that aren't Microsoft Entra principals, otherwise
                {name, type, objectId, tenantId, isAdmin} from pgaadauth_list_principals

` + docPrincipalFields + docsSeeAlso,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := a.session(ctx, aadDatabase)
			if err != nil {
				return err
			}
			var db *string
			if database != "" {
				db = &database
			}
			var rows []struct {
				RoleName     string   `json:"roleName"`
				MemberOf     []string `json:"memberOf"`
				DBPrivileges []string `json:"dbPrivileges"`
				AADName      *string  `json:"aadName"`
				AADType      string   `json:"aadType"`
				AADObjectID  string   `json:"aadObjectId"`
				AADTenantID  string   `json:"aadTenantId"`
				AADIsAdmin   bool     `json:"aadIsAdmin"`
			}
			if err := queryInto(ctx, s, &rows, sqlRoles, all, db); err != nil {
				return err
			}
			out := make([]roleInfo, 0, len(rows))
			for _, r := range rows {
				ri := roleInfo{RoleName: r.RoleName, MemberOf: r.MemberOf, DBPrivileges: r.DBPrivileges, Database: db}
				if r.AADName != nil {
					ri.AAD = &aadInfo{*r.AADName, r.AADType, r.AADObjectID, r.AADTenantID, r.AADIsAdmin}
				}
				out = append(out, ri)
			}
			return a.print(out)
		},
	}
	cmd.Flags().StringVar(&database, "database", "", "also report CONNECT/CREATE/TEMPORARY on this database")
	cmd.Flags().BoolVar(&all, "all", false, "include pg_*, azure* and replication roles")
	return cmd
}

// principal is one Entra principal to create or label.
type principal struct {
	Name  string `json:"name"`
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Admin bool   `json:"admin"`
	MFA   bool   `json:"mfa"`
}

// principalFlags reads --name/--oid/--type/--admin/--mfa or --principals.
type principalFlags struct {
	name, oid, typ, principals string
	admin, mfa                 bool
}

func (a *App) addPrincipalFlags(cmd *cobra.Command, withMFA bool) *principalFlags {
	p := &principalFlags{}
	f := cmd.Flags()
	f.StringVar(&p.name, "name", "", "name of the PostgreSQL role")
	f.StringVar(&p.oid, "oid", "", "Microsoft Entra object ID (for applications: the service principal's object ID, from Enterprise Applications)")
	f.StringVar(&p.typ, "type", "", "Microsoft Entra object type: user, group or service (applications and managed identities)")
	f.BoolVar(&p.admin, "admin", false, "PostgreSQL admin: member of azure_pg_admin, with CREATEROLE and CREATEDB")
	single := []string{"oid", "type", "admin"}
	jsonFields := `{"name","oid","type","admin"}`
	if withMFA {
		f.BoolVar(&p.mfa, "mfa", false, "enforce MFA (tests the token's mfa claim; no effect if the tenant already requires MFA for all tokens; see --help)")
		single = append(single, "mfa")
		jsonFields = `{"name","oid","type","admin","mfa"}`
	}
	f.StringVar(&p.principals, "principals", "", "JSON array of "+jsonFields+" objects, or @file / @- (instead of --name/--oid/--type)")
	cmd.MarkFlagsMutuallyExclusive("name", "principals")
	cmd.MarkFlagsOneRequired("name", "principals")
	cmd.MarkFlagsRequiredTogether("name", "oid", "type")
	for _, s := range single {
		cmd.MarkFlagsMutuallyExclusive(s, "principals")
	}
	return p
}

func (a *App) principalValues(cmd *cobra.Command, p *principalFlags) ([]principal, error) {
	var list []principal
	if cmd.Flags().Changed("principals") {
		raw, err := a.readArg(p.principals)
		if err != nil {
			return nil, usageErrorf("--principals: %v", err)
		}
		if err := jsonUnmarshal(raw, &list); err != nil || list == nil {
			return nil, usageErrorf(`--principals: expected a JSON array of {"name","oid","type"} objects: %v`, err)
		}
	} else {
		list = []principal{{Name: p.name, OID: p.oid, Type: p.typ, Admin: p.admin, MFA: p.mfa}}
	}
	for i, pr := range list {
		if pr.Name == "" {
			return nil, usageErrorf("principal %d: name is required", i)
		}
		oid, err := normalizeOID("oid", pr.OID)
		if err != nil {
			return nil, err
		}
		if err := checkType("type", pr.Type); err != nil {
			return nil, err
		}
		list[i].OID = oid
	}
	return list, nil
}

// errDryRun ends a --dry-run transaction: everything ran (so the server checked it) and
// is then rolled back.
var errDryRun = errors.New("dry run: rolled back")

// dryRunTx runs fn in a transaction that is always rolled back, returning fn's error (nil
// if fn succeeded).
func dryRunTx(ctx context.Context, s pg.Session, fn func(pg.Executor) error) error {
	err := s.Tx(ctx, func(ex pg.Executor) error {
		if err := fn(ex); err != nil {
			return err
		}
		return errDryRun
	})
	if errors.Is(err, errDryRun) {
		return nil
	}
	return err
}

// labelStatement maps an existing role to p's Microsoft Entra object (what enable-oid runs).
func labelStatement(p principal) string {
	label := fmt.Sprintf("aadauth,oid=%s,type=%s", p.OID, p.Type)
	if p.Admin {
		label += ",admin"
	}
	return fmt.Sprintf("SECURITY LABEL FOR %s ON ROLE %s IS %s", pg.Ident("pgaadauth"), pg.Ident(p.Name), pg.Literal(label))
}

// createStatement creates p (pgaadauth_create_principal_with_oid), with the values inlined
// so it can be shown and echoed as is.
func createStatement(p principal) string {
	return pg.Inline(sqlCreatePrincipal, p.Name, p.OID, p.Type, p.Admin, p.MFA)
}

// Conflict policies for an existing role with the requested name: error, skip (same object
// ID only), relabel (update the mapping, keeping the role and its privileges) or recreate
// (drop and create again).
var onConflictValues = []string{"error", "skip", "relabel", "recreate"}

const docOnConflict = `--on-conflict decides what happens when a role with the name already exists:
  error     (default) fail
  skip      leave it if it's an Entra role with the same object ID; fail otherwise
            (same as --if-not-exists)
  relabel   if the object ID differs (e.g. a managed identity deleted and recreated with
            the same name, which gives it a new object ID), or the role isn't an Entra
            role yet, update the mapping with SECURITY LABEL (what enable-oid does). The
            role keeps its memberships, privileges and owned objects. Admin is taken
            from --admin; --mfa can't be changed this way.
  recreate  drop the role and create it again. Fails if it still owns objects or holds
            privileges (see 'role revoke-all' and 'owner reassign'); relabel avoids that.
Roles with the same object ID are left alone by skip, relabel and recreate.`

func (a *App) roleCreateCommand() *cobra.Command {
	var ifNotExists, dryRun bool
	var onConflict string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create Microsoft Entra roles from object IDs (pgaadauth_create_principal_with_oid)",
		Long: `Creates a PostgreSQL role linked to a Microsoft Entra object by its object ID:
  select * from pg_catalog.pgaadauth_create_principal_with_oid(roleName, objectId, objectType, isAdmin, isMfa)
Runs in the postgres database, where the pgaadauth functions live.

--name: name of the role to create.

` + docObjectID + `

` + docPrincipalTypes + `

` + docAdmin + `

` + docMFA + `

` + docValidation + `

All principals are created in one transaction: if any fails, none is created.
--dry-run runs the creation and rolls it back, so every object ID is checked by the
server without changing anything.

` + docOnConflict + `
` + docsSeeAlso,
		Example: `  azpgaad role create --name my-app --oid 00000000-0000-0000-0000-000000000000 --type service
  azpgaad role create --if-not-exists --principals '[{"name":"a","oid":"…","type":"user"}]'
  azpgaad role create --name my-app --oid <new object ID> --type service --on-conflict relabel`,
		Args: cobra.NoArgs,
	}
	pf := a.addPrincipalFlags(cmd, true)
	cmd.Flags().BoolVar(&ifNotExists, "if-not-exists", false, "skip roles that already exist with the same object ID (same as --on-conflict skip)")
	cmd.Flags().StringVar(&onConflict, "on-conflict", "error", "when the role exists: error, skip, relabel or recreate (see --help)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "create in a transaction and roll back: the server checks everything, nothing changes")
	cmd.MarkFlagsMutuallyExclusive("if-not-exists", "on-conflict")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		if ifNotExists {
			onConflict = "skip"
		}
		if !contains(onConflictValues, onConflict) {
			return usageErrorf("--on-conflict must be one of %s", strings.Join(onConflictValues, ", "))
		}
		list, err := a.principalValues(cmd, pf)
		if err != nil {
			return err
		}
		// action: created, exists (left alone), relabelled or recreated. In a dry run it's
		// what would happen.
		type result struct {
			Name   string `json:"name"`
			OID    string `json:"oid"`
			Action string `json:"action"`
		}
		type output struct {
			DryRun     bool     `json:"dryRun"`
			Principals []result `json:"principals"`
		}
		out := output{DryRun: dryRun, Principals: []result{}}
		if len(list) == 0 {
			return a.print(out)
		}
		s, err := a.session(ctx, aadDatabase)
		if err != nil {
			return err
		}
		names := make([]string, len(list))
		for i, p := range list {
			names[i] = p.Name
		}
		var existingRows []struct {
			Name     string  `json:"name"`
			ObjectID *string `json:"objectId"`
		}
		if err := queryInto(ctx, s, &existingRows, sqlExistingRoles, names); err != nil {
			return err
		}
		existing := map[string]*string{}
		for _, r := range existingRows {
			existing[r.Name] = r.ObjectID
		}
		type step struct {
			p      principal
			action string
		}
		var todo []step
		for _, p := range list {
			oid, exists := existing[p.Name]
			sameOID := exists && oid != nil && strings.EqualFold(*oid, p.OID)
			switch {
			case !exists:
				todo = append(todo, step{p, "created"})
			case onConflict == "error":
				return fmt.Errorf("role %q already exists (use --if-not-exists to skip it, or --on-conflict)", p.Name)
			case sameOID:
				out.Principals = append(out.Principals, result{p.Name, p.OID, "exists"})
			case onConflict == "relabel":
				if p.MFA {
					a.warn(fmt.Sprintf("role %q: --mfa is not applied when relabelling an existing role", p.Name))
				}
				todo = append(todo, step{p, "relabelled"})
			case onConflict == "recreate":
				todo = append(todo, step{p, "recreated"})
			case oid == nil:
				return fmt.Errorf("role %q already exists but is not a Microsoft Entra role (--on-conflict relabel maps it to the object ID)", p.Name)
			default:
				return fmt.Errorf("role %q already exists with object ID %s, not %s (--on-conflict relabel updates the mapping)", p.Name, *oid, p.OID)
			}
		}
		create := func(ex pg.Executor) error {
			for _, st := range todo {
				p := st.p
				switch st.action {
				case "relabelled":
					if err := ex.Exec(ctx, labelStatement(p)); err != nil {
						return fmt.Errorf("relabel %q (%s %s): %w", p.Name, p.Type, p.OID, err)
					}
				case "recreated":
					if err := ex.Exec(ctx, "DROP ROLE "+pg.Ident(p.Name)); err != nil {
						if pe := pg.AsError(err); pe != nil && pe.Code == "2BP01" {
							return fmt.Errorf("recreate %q: %w\nThe role still owns objects or holds privileges; --on-conflict relabel keeps them", p.Name, err)
						}
						return fmt.Errorf("recreate %q: %w", p.Name, err)
					}
					fallthrough
				default:
					if err := ex.Exec(ctx, sqlCreatePrincipal, p.Name, p.OID, p.Type, p.Admin, p.MFA); err != nil {
						return fmt.Errorf("create %q (%s %s): %w", p.Name, p.Type, p.OID, err)
					}
				}
				out.Principals = append(out.Principals, result{p.Name, p.OID, st.action})
			}
			return nil
		}
		if dryRun {
			err = dryRunTx(ctx, s, create)
		} else {
			err = s.Tx(ctx, create)
		}
		if err != nil {
			return err
		}
		return a.print(out)
	}
	return cmd
}

func (a *App) roleEnableOIDCommand() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "enable-oid",
		Short: "Map existing roles to Microsoft Entra object IDs (SECURITY LABEL … pgaadauth)",
		Long: `Enables Microsoft Entra authentication for an existing PostgreSQL role. Azure Database
for PostgreSQL stores the mapping between a role and its Microsoft Entra object in a
security label:
  SECURITY LABEL for "pgaadauth" on role "<roleName>" is 'aadauth,oid=<objectId>,type=<objectType>,admin'

--name: name of an existing PostgreSQL role.

` + docObjectID + `

` + docPrincipalTypes + `

--admin: adds "admin" to the label. If present, the role can manage other Microsoft Entra
roles.

` + docValidation + `

All labels are applied in one transaction. --dry-run applies them and rolls back, so the
server checks every object ID without changing anything.
` + docsSeeAlso,
		Args: cobra.NoArgs,
	}
	pf := a.addPrincipalFlags(cmd, false)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "apply in a transaction and roll back: the server checks everything, nothing changes")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		list, err := a.principalValues(cmd, pf)
		if err != nil {
			return err
		}
		var stmts []string
		for _, p := range list {
			stmts = append(stmts, labelStatement(p))
		}
		if !dryRun || len(stmts) == 0 {
			return a.execStatements(ctx, aadDatabase, stmts, false)
		}
		s, err := a.session(ctx, aadDatabase)
		if err != nil {
			return err
		}
		err = dryRunTx(ctx, s, func(ex pg.Executor) error {
			for _, st := range stmts {
				if err := ex.Exec(ctx, st); err != nil {
					return fmt.Errorf("%s: %w", st, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return a.print(stmtResult{DryRun: true, Database: aadDatabase, Statements: stmts})
	}
	return cmd
}

func (a *App) roleDropCommand() *cobra.Command {
	var ifExists, yes, dryRun bool
	cmd := &cobra.Command{
		Use:   "drop",
		Short: "Drop roles by name or Microsoft Entra object ID",
		Long: `Drops roles with DROP ROLE (one statement, so all or nothing). Object IDs are resolved to
role names with pgaadauth_list_principals.

From Microsoft's documentation: the Azure portal only shows admin roles, so non-admin
Microsoft Entra roles are dropped with SQL (this command) or the ARM API.

A role that still owns objects or holds privileges can't be dropped; see
'azpgaad owner reassign' and 'azpgaad role revoke-all'.
` + docsSeeAlso,
		Args: cobra.NoArgs,
	}
	names := a.addList(cmd, "name", "names", "role name", false)
	oids := a.addList(cmd, "oid", "oids", "Microsoft Entra object ID", false)
	cmd.MarkFlagsOneRequired("name", "names", "oid", "oids")
	cmd.MarkFlagsMutuallyExclusive("name", "oid")
	cmd.MarkFlagsMutuallyExclusive("names", "oids")
	cmd.MarkFlagsMutuallyExclusive("name", "oids")
	cmd.MarkFlagsMutuallyExclusive("names", "oid")
	cmd.Flags().BoolVar(&ifExists, "if-exists", false, "don't fail on roles that don't exist")
	cmd.Flags().BoolVar(&yes, "yes", false, "don't ask for confirmation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the SQL without running it")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		roleNames, _, err := a.listValues(cmd, names)
		if err != nil {
			return err
		}
		oidList, byOID, err := a.listValues(cmd, oids)
		if err != nil {
			return err
		}
		if byOID {
			for i, o := range oidList {
				if oidList[i], err = normalizeOID("oids", o); err != nil {
					return err
				}
			}
			oidList = dedupe(oidList)
			if len(oidList) > 0 {
				s, err := a.session(ctx, aadDatabase)
				if err != nil {
					return err
				}
				var found []struct {
					Name     string `json:"name"`
					ObjectID string `json:"objectId"`
				}
				if err := queryInto(ctx, s, &found, sqlPrincipalsByOID, oidList); err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, f := range found {
					roleNames = append(roleNames, f.Name)
					seen[strings.ToLower(f.ObjectID)] = true
				}
				for _, o := range oidList {
					if !seen[o] && !ifExists {
						return fmt.Errorf("no Microsoft Entra role has object ID %s (use --if-exists to ignore)", o)
					}
				}
			}
		}
		roleNames = dedupe(roleNames)
		if len(roleNames) == 0 {
			return a.execStatements(ctx, aadDatabase, nil, dryRun)
		}
		stmt := "DROP ROLE "
		if ifExists {
			stmt += "IF EXISTS "
		}
		stmt += pg.Idents(roleNames)
		if !dryRun {
			if err := a.confirm(yes, "Drop role(s) "+strings.Join(roleNames, ", ")+"?"); err != nil {
				return err
			}
		}
		if err := a.execStatements(ctx, aadDatabase, []string{stmt}, dryRun); err != nil {
			if pe := pg.AsError(err); pe != nil && pe.Code == "2BP01" {
				return fmt.Errorf("%w\nThe role still owns objects or holds privileges: see 'azpgaad owner reassign' and 'azpgaad role revoke-all'", err)
			}
			return err
		}
		return nil
	}
	return cmd
}

func (a *App) roleGrantCommand(grant bool) *cobra.Command {
	verb, prep, use := "GRANT", "TO", "grant"
	if !grant {
		verb, prep, use = "REVOKE", "FROM", "revoke"
	}
	var dryRun bool
	cmd := &cobra.Command{
		Use:   use,
		Short: strings.ToUpper(use[:1]) + use[1:] + " role membership (e.g. pg_read_all_data)",
		Args:  cobra.NoArgs,
	}
	members := a.addList(cmd, "name", "names", "member role name", true)
	roles := a.addList(cmd, "role", "roles", "role to "+use, true)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the SQL without running it")
	var ifExists bool
	if !grant {
		cmd.Flags().BoolVar(&ifExists, "if-exists", false, "skip roles that don't exist instead of failing")
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		m, _, err := a.listValues(cmd, members)
		if err != nil {
			return err
		}
		r, _, err := a.listValues(cmd, roles)
		if err != nil {
			return err
		}
		m, r = dedupe(m), dedupe(r)
		var skipped []string
		if ifExists {
			var sm, sr []string
			if m, sm, err = a.existingRoles(ctx, m); err != nil {
				return err
			}
			if r, sr, err = a.existingRoles(ctx, r); err != nil {
				return err
			}
			skipped = append(sm, sr...)
		}
		var stmts []string
		if len(m) > 0 && len(r) > 0 {
			stmts = []string{fmt.Sprintf("%s %s %s %s", verb, pg.Idents(r), prep, pg.Grantees(m))}
		}
		return a.execStatements(ctx, aadDatabase, stmts, dryRun, skipped...)
	}
	return cmd
}

func (a *App) roleRevokeAllCommand() *cobra.Command {
	var database string
	var yes, dryRun, memberships bool
	cmd := &cobra.Command{
		Use:   "revoke-all",
		Short: "Revoke all database and schema privileges on a database from roles (and, with --memberships, their role memberships)",
		Long: `Revokes every privilege on --database itself and on each of its non-system schemas
from the roles, in one transaction: what you do before dropping them, or to take
everything away from a principal that is no longer wanted.

--memberships also revokes the roles' memberships, e.g. pg_read_all_data and
pg_write_all_data (which apply in every database). Memberships in Azure-managed roles
(azure_pg_admin and other azure* roles, replication) are left alone.

Table privileges and default privileges aren't included: see 'table revoke' and
'default-privileges revoke'.`,
		Args: cobra.NoArgs,
	}
	names := a.addList(cmd, "name", "names", "role name", true)
	var ifExists bool
	cmd.Flags().StringVar(&database, "database", "", "database (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "don't ask for confirmation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the SQL without running it")
	cmd.Flags().BoolVar(&ifExists, "if-exists", false, "skip roles that don't exist instead of failing")
	cmd.Flags().BoolVar(&memberships, "memberships", false, "also revoke the roles' role memberships (e.g. pg_read_all_data)")
	_ = cmd.MarkFlagRequired("database")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		n, _, err := a.listValues(cmd, names)
		if err != nil {
			return err
		}
		n = dedupe(n)
		var skipped []string
		if ifExists {
			if n, skipped, err = a.existingRoles(ctx, n); err != nil {
				return err
			}
		}
		if len(n) == 0 {
			return a.execStatements(ctx, database, nil, dryRun, skipped...)
		}
		schemas, err := a.listSchemas(ctx, database, false)
		if err != nil {
			return err
		}
		stmts := []string{fmt.Sprintf("REVOKE ALL PRIVILEGES ON DATABASE %s FROM %s", pg.Ident(database), pg.Grantees(n))}
		for _, s := range schemas {
			stmts = append(stmts, fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM %s", pg.Ident(s.Name), pg.Grantees(n)))
		}
		if memberships {
			s, err := a.session(ctx, database)
			if err != nil {
				return err
			}
			var rows []struct {
				Member string   `json:"member"`
				Roles  []string `json:"roles"`
			}
			if err := queryInto(ctx, s, &rows, sqlMembershipsOf, n); err != nil {
				return err
			}
			for _, r := range rows {
				stmts = append(stmts, fmt.Sprintf("REVOKE %s FROM %s", pg.Idents(r.Roles), pg.Ident(r.Member)))
			}
		}
		if err := a.warnPublicConnect(ctx, database); err != nil {
			return err
		}
		if !dryRun {
			if err := a.confirm(yes, fmt.Sprintf("Revoke all privileges on %s from %s?", database, strings.Join(n, ", "))); err != nil {
				return err
			}
		}
		return a.execStatements(ctx, database, stmts, dryRun, skipped...)
	}
	return cmd
}

// warnPublicConnect warns when PUBLIC can still connect, since revoking CONNECT from a
// role then doesn't stop it connecting.
func (a *App) warnPublicConnect(ctx context.Context, database string) error {
	s, err := a.session(ctx, database)
	if err != nil {
		return err
	}
	var public bool
	if err := queryInto(ctx, s, &public, sqlPublicConnect, database); err != nil {
		return err
	}
	if public {
		a.warn(fmt.Sprintf("PUBLIC has CONNECT on database %s, so revoking CONNECT from individual roles does not stop them connecting (to change that: azpgaad db revoke --name PUBLIC --privilege CONNECT --database %s)",
			database, shellQuote(database)))
	}
	return nil
}
