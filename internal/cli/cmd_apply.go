package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

// applySpec is the desired state for 'apply'.
type applySpec struct {
	Principals []specPrincipal `json:"principals"`
}

type specPrincipal struct {
	principal
	// Roles the principal is a member of (e.g. pg_read_all_data).
	Roles []string `json:"roles"`
	// Databases maps a database name to the privileges granted on it (CONNECT, CREATE,
	// TEMPORARY or ALL).
	Databases map[string][]string `json:"databases"`
}

// applyChange is one line of the diff, and one statement.
type applyChange struct {
	// Op is + (create or grant), - (revoke or drop) or ~ (relabel or recreate).
	Op        string `json:"op"`
	Principal string `json:"principal"`
	What      string `json:"what"`
	SQL       string `json:"sql"`
	exec      func(ctx context.Context, ex pg.Executor) error
}

var allDBPrivileges = []string{"CONNECT", "CREATE", "TEMPORARY"}

const applyLong = `Brings Microsoft Entra principals, their role memberships and their database privileges
to the state described by --spec, in one transaction on one connection: either every
change is made or none is. Prints the changes as a diff (op, principal, what, sql):
  +  create a principal, grant a membership or privilege
  -  revoke, or drop a principal (--prune)
  ~  relabel or recreate a principal whose object ID changed (--on-conflict)

--spec is JSON (inline, @file or @- for stdin):
  {"principals": [
    {"name": "my-app", "oid": "<object ID>", "type": "service",
     "admin": false, "mfa": false,
     "roles": ["pg_read_all_data", "pg_write_all_data"],
     "databases": {"appdb": ["CONNECT", "TEMPORARY"]}}
  ]}
name, oid and type are required; the rest default to false/none. Privileges are CONNECT,
CREATE, TEMPORARY (TEMP) or ALL. Only direct grants count: privileges a principal gets
through PUBLIC or a role membership aren't compared or revoked.

Without --prune nothing is taken away: missing principals are created and missing
memberships and privileges granted (a batch grant for many principals in one run).
--prune revoke also revokes memberships and database privileges that the spec doesn't
list, from the listed principals and from Entra principals the spec doesn't mention.
--prune drop does the same for listed principals and drops the unlisted ones (their
database privileges are revoked first; objects they own, or schema and table privileges
in other databases, make the drop fail and nothing is changed).
Pruning never touches the logged-in user, Entra admins (isAdmin), built-in principals
(names starting with ` + builtinPrefix + `), memberships in Azure-managed roles (azure_pg_admin and
other azure* roles, replication), or principals named by --exclude-prefix/--exclude-prefixes.
--managed-prefix/--managed-prefixes limit pruning of unlisted principals to names with
those prefixes (e.g. when several teams or tools share a server). It asks for confirmation unless --yes.

` + docOnConflict + `

--dry-run runs everything in the transaction and rolls it back, so the server checks
object IDs, role and database names, and whether drops would succeed.

Schema, table and default privileges aren't managed by apply; use the db, schema, table
and default-privileges commands for those.`

func (a *App) applyCommand() *cobra.Command {
	var specArg, prune, onConflict string
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a desired state for Entra principals, memberships and database privileges (one transaction)",
		Long:  applyLong,
		Example: `  azpgaad apply --spec @roles.json --dry-run
  azpgaad apply --spec @roles.json
  azpgaad apply --spec @roles.json --prune drop --managed-prefix app_ --yes`,
		Args: cobra.NoArgs,
	}
	cmd.Flags().StringVar(&specArg, "spec", "", "desired state as JSON, or @file / @- (see --help)")
	cmd.Flags().StringVar(&prune, "prune", "", "also remove what the spec doesn't list: revoke, or drop (unlisted principals are dropped)")
	cmd.Flags().StringVar(&onConflict, "on-conflict", "error", "when a listed role exists with another object ID or isn't an Entra role: error, skip, relabel or recreate")
	exclude := a.addList(cmd, "exclude-prefix", "exclude-prefixes", "name prefix of principals never to prune (e.g. ones managed elsewhere)", false)
	managed := a.addList(cmd, "managed-prefix", "managed-prefixes", "with --prune, only prune unlisted principals whose names start with this", false)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "make the changes in a transaction and roll back: the server checks everything, nothing changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "don't ask for confirmation before revoking or dropping (--prune)")
	_ = cmd.MarkFlagRequired("spec")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		if prune != "" && prune != "revoke" && prune != "drop" {
			return usageErrorf("--prune must be revoke or drop")
		}
		if !contains(onConflictValues, onConflict) {
			return usageErrorf("--on-conflict must be one of %s", strings.Join(onConflictValues, ", "))
		}
		raw, err := a.readArg(specArg)
		if err != nil {
			return usageErrorf("--spec: %v", err)
		}
		spec, err := parseApplySpec(raw)
		if err != nil {
			return err
		}
		prefixes, _, err := a.listValues(cmd, exclude)
		if err != nil {
			return err
		}
		managedPrefixes, _, err := a.listValues(cmd, managed)
		if err != nil {
			return err
		}
		s, err := a.session(ctx, aadDatabase)
		if err != nil {
			return err
		}
		state, err := readApplyState(ctx, s, spec)
		if err != nil {
			return err
		}
		changes, err := a.planApply(spec, state, prune, onConflict, prefixes, managedPrefixes)
		if err != nil {
			return err
		}
		if !dryRun {
			removals := 0
			for _, c := range changes {
				if c.Op == "-" {
					removals++
				}
			}
			if removals > 0 {
				if err := a.confirm(yes, fmt.Sprintf("Apply %d change(s), %d of them revokes or drops?", len(changes), removals)); err != nil {
					return err
				}
			}
		}
		run := func(ex pg.Executor) error {
			for _, c := range changes {
				if err := c.exec(ctx, ex); err != nil {
					err = fmt.Errorf("%s %s: %s: %w", c.Op, c.Principal, c.What, err)
					if pe := pg.AsError(err); pe != nil && pe.Code == "2BP01" {
						err = fmt.Errorf("%w\nThe role still owns objects or holds privileges in some database: see 'azpgaad owner reassign' and 'azpgaad role revoke-all'", err)
					}
					return err
				}
			}
			return nil
		}
		switch {
		case len(changes) == 0:
			a.info("no changes")
		case dryRun:
			if err := dryRunTx(ctx, s, run); err != nil {
				return err
			}
			a.info(fmt.Sprintf("%d change(s) checked and rolled back (--dry-run)", len(changes)))
		default:
			if err := s.Tx(ctx, run); err != nil {
				return err
			}
			a.info(fmt.Sprintf("%d change(s) applied", len(changes)))
		}
		if changes == nil {
			changes = []applyChange{}
		}
		return a.print(changes)
	}
	return cmd
}

func parseApplySpec(raw []byte) (*applySpec, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var spec applySpec
	if err := dec.Decode(&spec); err != nil {
		return nil, usageErrorf(`--spec: expected {"principals": [{"name", "oid", "type", "roles", "databases"}]}: %v`, err)
	}
	seen := map[string]bool{}
	for i := range spec.Principals {
		p := &spec.Principals[i]
		if p.Name == "" {
			return nil, usageErrorf("--spec: principal %d: name is required", i)
		}
		if seen[p.Name] {
			return nil, usageErrorf("--spec: principal %q is listed twice", p.Name)
		}
		seen[p.Name] = true
		oid, err := normalizeOID("spec: "+p.Name+": oid", p.OID)
		if err != nil {
			return nil, err
		}
		p.OID = oid
		if err := checkType("spec: "+p.Name+": type", p.Type); err != nil {
			return nil, err
		}
		for _, r := range p.Roles {
			if r == "" {
				return nil, usageErrorf("--spec: principal %q: empty role name", p.Name)
			}
		}
		p.Roles = dedupe(p.Roles)
		for db, privs := range p.Databases {
			if db == "" {
				return nil, usageErrorf("--spec: principal %q: empty database name", p.Name)
			}
			norm, err := normalizePrivileges("spec: "+p.Name+": databases: "+db, privs, dbPrivileges)
			if err != nil {
				return nil, err
			}
			if contains(norm, "ALL") {
				norm = allDBPrivileges
			}
			p.Databases[db] = norm
		}
	}
	return &spec, nil
}

// applyState is what exists on the server, for the listed names and every Entra principal.
type applyState struct {
	currentUser string
	entra       map[string]entraPrincipal // Entra principals by name
	entraNames  []string                  // sorted
	roles       map[string]*string        // listed names that exist -> object ID (nil: not Entra)
	memberOf    map[string][]string       // role -> roles it's a member of (not azure*)
	dbPrivs     map[string]map[string][]string
}

type entraPrincipal struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	ObjectID string `json:"objectId"`
	IsMFA    bool   `json:"isMfa"`
	IsAdmin  bool   `json:"isAdmin"`
}

func readApplyState(ctx context.Context, ex pg.Executor, spec *applySpec) (*applyState, error) {
	st := &applyState{entra: map[string]entraPrincipal{}, roles: map[string]*string{},
		memberOf: map[string][]string{}, dbPrivs: map[string]map[string][]string{}}
	var who struct {
		CurrentUser string `json:"currentUser"`
	}
	if err := queryInto(ctx, ex, &who, sqlLoginCheck); err != nil {
		return nil, err
	}
	st.currentUser = who.CurrentUser
	var principals []entraPrincipal
	if err := queryInto(ctx, ex, &principals, sqlPrincipals, false, []string{}); err != nil {
		return nil, err
	}
	for _, p := range principals {
		st.entra[p.Name] = p
		st.entraNames = append(st.entraNames, p.Name)
	}
	sort.Strings(st.entraNames)

	names := make([]string, 0, len(spec.Principals))
	for _, p := range spec.Principals {
		names = append(names, p.Name)
	}
	var existing []struct {
		Name     string  `json:"name"`
		ObjectID *string `json:"objectId"`
	}
	if err := queryInto(ctx, ex, &existing, sqlExistingRoles, names); err != nil {
		return nil, err
	}
	for _, r := range existing {
		st.roles[r.Name] = r.ObjectID
	}

	all := dedupe(append(append([]string{}, names...), st.entraNames...))
	var members []struct {
		Member string   `json:"member"`
		Roles  []string `json:"roles"`
	}
	if err := queryInto(ctx, ex, &members, sqlMembershipsOf, all); err != nil {
		return nil, err
	}
	for _, m := range members {
		st.memberOf[m.Member] = m.Roles
	}
	var grants []struct {
		Role       string   `json:"role"`
		Database   string   `json:"database"`
		Privileges []string `json:"privileges"`
	}
	if err := queryInto(ctx, ex, &grants, sqlDatabaseGrants, all); err != nil {
		return nil, err
	}
	for _, g := range grants {
		if st.dbPrivs[g.Role] == nil {
			st.dbPrivs[g.Role] = map[string][]string{}
		}
		st.dbPrivs[g.Role][g.Database] = g.Privileges
	}
	return st, nil
}

// planApply works out the changes, in execution order: principals (create, relabel,
// recreate), grants, then revokes and drops.
func (a *App) planApply(spec *applySpec, st *applyState, prune, onConflict string, excludePrefixes, managedPrefixes []string) ([]applyChange, error) {
	var create, grant, remove []applyChange
	stmt := func(op, who, what, sql string) applyChange {
		return applyChange{Op: op, Principal: who, What: what, SQL: sql,
			exec: func(ctx context.Context, ex pg.Executor) error { return ex.Exec(ctx, sql) }}
	}
	createChange := func(p principal) applyChange {
		return applyChange{Op: "+", Principal: p.Name, What: fmt.Sprintf("principal (%s %s)", p.Type, p.OID),
			SQL: createStatement(p),
			exec: func(ctx context.Context, ex pg.Executor) error {
				return ex.Exec(ctx, sqlCreatePrincipal, p.Name, p.OID, p.Type, p.Admin, p.MFA)
			}}
	}
	revokeDBs := func(op, name string, current map[string][]string, keep map[string][]string) []applyChange {
		var out []applyChange
		for _, db := range sortedKeys(current) {
			extra := minus(current[db], keep[db])
			if len(extra) == 0 {
				continue
			}
			out = append(out, stmt(op, name, strings.Join(extra, ", ")+" on database "+db,
				fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s", strings.Join(extra, ", "), pg.Ident(db), pg.Ident(name))))
		}
		return out
	}

	listed := map[string]bool{}
	for _, sp := range spec.Principals {
		p := sp.principal
		listed[p.Name] = true
		curRoles, curDBs := st.memberOf[p.Name], st.dbPrivs[p.Name]
		oid, exists := st.roles[p.Name]
		switch {
		case !exists:
			create = append(create, createChange(p))
			curRoles, curDBs = nil, nil
		case oid != nil && strings.EqualFold(*oid, p.OID):
			if e, ok := st.entra[p.Name]; ok && e.IsAdmin != p.Admin {
				a.warn(fmt.Sprintf("%s: admin is %v on the server but %v in the spec; not changed (relabel or recreate the role to change it)", p.Name, e.IsAdmin, p.Admin))
			}
		default:
			was := "is not a Microsoft Entra role"
			if oid != nil {
				was = "has object ID " + *oid
			}
			switch onConflict {
			case "error":
				return nil, fmt.Errorf("role %q already exists and %s, not %s (see --on-conflict)", p.Name, was, p.OID)
			case "skip":
				a.warn(fmt.Sprintf("role %q %s, not %s; left as is (--on-conflict skip)", p.Name, was, p.OID))
			case "relabel":
				create = append(create, stmt("~", p.Name, fmt.Sprintf("relabel (%s %s; it %s)", p.Type, p.OID, was), labelStatement(p)))
			case "recreate":
				// Database privileges would block DROP ROLE; memberships go with the role.
				create = append(create, revokeDBs("~", p.Name, curDBs, nil)...)
				create = append(create, stmt("~", p.Name, "drop (it "+was+")", "DROP ROLE "+pg.Ident(p.Name)))
				c := createChange(p)
				c.Op = "~"
				create = append(create, c)
				curRoles, curDBs = nil, nil
			}
		}

		if add := minus(sp.Roles, curRoles); len(add) > 0 {
			grant = append(grant, stmt("+", p.Name, "member of "+strings.Join(add, ", "),
				fmt.Sprintf("GRANT %s TO %s", pg.Idents(add), pg.Ident(p.Name))))
		}
		for _, db := range sortedKeys(sp.Databases) {
			if add := minus(sp.Databases[db], curDBs[db]); len(add) > 0 {
				grant = append(grant, stmt("+", p.Name, strings.Join(add, ", ")+" on database "+db,
					fmt.Sprintf("GRANT %s ON DATABASE %s TO %s", strings.Join(add, ", "), pg.Ident(db), pg.Ident(p.Name))))
			}
		}
		if prune != "" {
			if extra := minus(curRoles, sp.Roles); len(extra) > 0 {
				remove = append(remove, stmt("-", p.Name, "member of "+strings.Join(extra, ", "),
					fmt.Sprintf("REVOKE %s FROM %s", pg.Idents(extra), pg.Ident(p.Name))))
			}
			remove = append(remove, revokeDBs("-", p.Name, curDBs, sp.Databases)...)
		}
	}

	if prune != "" {
		var keptAdmins []string
		for _, name := range st.entraNames {
			if listed[name] || name == st.currentUser || isBuiltinPrincipal(name) || hasAnyPrefix(name, excludePrefixes) ||
				(len(managedPrefixes) > 0 && !hasAnyPrefix(name, managedPrefixes)) {
				continue
			}
			if st.entra[name].IsAdmin {
				keptAdmins = append(keptAdmins, name)
				continue
			}
			if prune == "revoke" {
				if roles := st.memberOf[name]; len(roles) > 0 {
					remove = append(remove, stmt("-", name, "member of "+strings.Join(roles, ", "),
						fmt.Sprintf("REVOKE %s FROM %s", pg.Idents(roles), pg.Ident(name))))
				}
			}
			remove = append(remove, revokeDBs("-", name, st.dbPrivs[name], nil)...)
			if prune == "drop" {
				remove = append(remove, stmt("-", name, "drop principal", "DROP ROLE "+pg.Ident(name)))
			}
		}
		if len(keptAdmins) > 0 {
			a.info("not pruned (Entra admins): " + strings.Join(keptAdmins, ", "))
		}
	}
	return append(append(create, grant...), remove...), nil
}

// minus returns the values of a not in b, in a's order.
func minus(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
