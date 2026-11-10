package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

func jsonUnmarshal(b []byte, out any) error { return json.Unmarshal(b, out) }

// Queries return plain result sets. Column aliases match the json tags of the Go structs
// they're decoded into (case-insensitively, see pg.Rows.Decode), and those tags are the
// output field names.

// Prefix filters use starts_with (PostgreSQL 11+), not LIKE: in LIKE '_' is a wildcard, and
// escaping it ('pg\_%') only works while standard_conforming_strings is on.

// nonSystemSchema is the schema filter used everywhere: excludes pg_* (but not e.g.
// "pgadmin"), information_schema and cron.
const nonSystemSchema = `(not starts_with(n.nspname, 'pg_') and n.nspname not in ('information_schema', 'cron'))`

// nonSystemRole hides Postgres/Azure internal roles.
const nonSystemRole = `(not starts_with(r.rolname, 'pg_') and not starts_with(r.rolname, 'azure') and r.rolname <> 'replication')`

const sqlServerInfo = `select current_setting('server_version') as version,
  current_setting('server_version_num')::int as versionnum,
  version() as versionstring,
  current_user as currentuser,
  session_user as sessionuser,
  current_database() as database,
  (select e.extversion from pg_extension e where e.extname = 'pgaadauth') as pgaadauthversion`

const sqlLoginCheck = `select current_user as currentuser, current_setting('server_version') as version`

const sqlDatabases = `select d.datname as name, pg_get_userbyid(d.datdba) as owner
from pg_database d
where not d.datistemplate
order by d.datname`

// $1: include system schemas
const sqlSchemas = `select n.nspname as name, pg_get_userbyid(n.nspowner) as owner
from pg_namespace n
where $1::boolean or ` + nonSystemSchema + `
order by n.nspname`

// $1: exclude current_user, $2: names to exclude
const sqlPrincipals = `select t.rolname as name, t.principaltype as type, t.objectid, t.tenantid,
  t.ismfa = 1 as ismfa, t.isadmin = 1 as isadmin
from pg_catalog.pgaadauth_list_principals(false) t
where (not $1::boolean or t.rolname <> current_user)
  and not (t.rolname = any($2::text[]))
order by t.rolname`

// $1: include system roles, $2: database for dbPrivileges (null to skip)
const sqlRoles = `select r.rolname as rolename,
  (select array_agg(m.rolname::text order by m.rolname)
   from pg_auth_members am join pg_roles m on m.oid = am.roleid
   where am.member = r.oid) as memberof,
  case when $2::text is null then null else
    (select array_agg(p.p order by p.ord)
     from unnest(array['CONNECT', 'CREATE', 'TEMPORARY']) with ordinality p(p, ord)
     where has_database_privilege(r.oid, $2::text, p.p)) end as dbprivileges,
  a.rolname as aadname, a.principaltype as aadtype, a.objectid as aadobjectid,
  a.tenantid as aadtenantid, a.isadmin = 1 as aadisadmin
from pg_roles r
left join pg_catalog.pgaadauth_list_principals(false) a on a.rolname = r.rolname
where $1::boolean or ` + nonSystemRole + `
order by r.rolname`

// $1: role names. The ones that exist, with their object ID (null if not an Entra role).
const sqlExistingRoles = `select r.rolname as name, a.objectid
from pg_roles r
left join pg_catalog.pgaadauth_list_principals(false) a on a.rolname = r.rolname
where r.rolname = any($1::text[])`

// $1: role names. The ones that exist.
const sqlRolesNamed = `select r.rolname from pg_roles r where r.rolname = any($1::text[]) order by r.rolname`

const sqlCreatePrincipal = `select pg_catalog.pgaadauth_create_principal_with_oid($1::text, $2::text, $3::text, $4::boolean, $5::boolean)`

// $1: lower-case object IDs
const sqlPrincipalsByOID = `select t.rolname as name, t.objectid
from pg_catalog.pgaadauth_list_principals(false) t
where lower(t.objectid) = any($1::text[])
order by t.rolname`

// $1: database
const sqlPublicConnect = `select has_database_privilege('public', $1::text, 'CONNECT')`

// $1: schema names. The ones that exist.
const sqlSchemasNamed = `select n.nspname from pg_namespace n where n.nspname = any($1::text[]) order by n.nspname`

// $1: schemas, $2: table names
const sqlTablesNamed = `select n.nspname as schema, c.relname as name
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f')
  and n.nspname = any($1::text[])
  and c.relname = any($2::text[])
order by n.nspname, c.relname`

const sqlDefaultRoleNames = `select r.rolname from pg_roles r where ` + nonSystemRole + ` order by r.rolname`

// $1: database, $2: roles
const sqlPrivilegesDB = `select r.name as role, $1::text as database,
  coalesce((select array_agg(p.p order by p.ord)
            from unnest(array['CONNECT', 'CREATE', 'TEMPORARY']) with ordinality p(p, ord)
            where has_database_privilege(r.name, $1::text, p.p)), '{}') as privileges
from unnest($2::text[]) with ordinality r(name, ord)
order by r.ord`

// $1: roles
const sqlPrivilegesSchema = `select r.name as role, n.nspname as schema, x.privs as privileges
from unnest($1::text[]) with ordinality r(name, ord)
cross join pg_namespace n
cross join lateral (select array_agg(p.p order by p.ord) privs
                    from unnest(array['USAGE', 'CREATE']) with ordinality p(p, ord)
                    where has_schema_privilege(r.name, n.oid, p.p)) x
where ` + nonSystemSchema + ` and x.privs is not null
order by r.ord, n.nspname`

// $1: roles
const sqlPrivilegesTable = `select r.name as role, t.nspname as schema, t.relname as "table", x.privs as privileges
from unnest($1::text[]) with ordinality r(name, ord)
cross join (select c.oid, n.nspname, c.relname
            from pg_class c join pg_namespace n on n.oid = c.relnamespace
            where c.relkind in ('r', 'p', 'v', 'm', 'f') and ` + nonSystemSchema + `) t
cross join lateral (select array_agg(p.p order by p.ord) privs
                    from unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) with ordinality p(p, ord)
                    where has_table_privilege(r.name, t.oid, p.p)) x
where x.privs is not null
order by r.ord, t.nspname, t.relname`

// $1: grantee filter (empty = all)
const sqlPrivilegesDefault = `select pg_get_userbyid(d.defaclrole) as owner, n.nspname as schema,
  case d.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences' when 'f' then 'functions'
                       when 'T' then 'types' when 'n' then 'schemas' end as objecttype,
  g.grantee, a.privilege_type as privilege
from pg_default_acl d
left join pg_namespace n on n.oid = d.defaclnamespace
cross join lateral aclexplode(d.defaclacl) a
cross join lateral (select case when a.grantee = 0 then 'public' else pg_get_userbyid(a.grantee) end grantee) g
where cardinality($1::text[]) = 0 or g.grantee = any($1::text[])
order by 1, 2, d.defaclobjtype, g.grantee, a.privilege_type`

// Objects in the current database whose ownership can be reassigned. Sequences owned by a
// table column and extension members follow their parent and are skipped.
const sqlOwners = `with objs as (
  select 'database' kind, null::text sch, d.datname::text name, null::text args, pg_get_userbyid(d.datdba) owner, 0 ord
  from pg_database d where d.datname = current_database()
  union all
  select 'schema', n.nspname, n.nspname, null, pg_get_userbyid(n.nspowner), 1
  from pg_namespace n where ` + nonSystemSchema + `
  union all
  select case c.relkind when 'r' then 'table' when 'p' then 'table' when 'v' then 'view'
                        when 'm' then 'materialized view' when 'S' then 'sequence' when 'f' then 'foreign table' end,
         n.nspname, c.relname, null, pg_get_userbyid(c.relowner), 2
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p', 'v', 'm', 'S', 'f') and ` + nonSystemSchema + `
    and not exists (select 1 from pg_depend dep where dep.classid = 'pg_class'::regclass and dep.objid = c.oid
                    and (dep.deptype = 'e' or (c.relkind = 'S' and dep.deptype in ('a', 'i'))))
  union all
  select case p.prokind when 'a' then 'aggregate' when 'p' then 'procedure' else 'function' end,
         n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner), 3
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where ` + nonSystemSchema + `
    and not exists (select 1 from pg_depend dep where dep.classid = 'pg_proc'::regclass and dep.objid = p.oid and dep.deptype = 'e')
)
select kind as type, sch as schema, name, args, owner
from objs
order by ord, sch, name, args`

// $1: role names. Whether current_user is a member of each.
const sqlMembership = `select r.rolname as role, pg_has_role(current_user, r.oid, 'MEMBER') as member
from pg_roles r
where r.rolname = any($1::text[])`

// --- privilege keywords (can't be parameters, so they're whitelisted) ---

var (
	dbPrivileges     = []string{"CONNECT", "CREATE", "TEMPORARY", "ALL"}
	schemaPrivileges = []string{"USAGE", "CREATE", "ALL"}
	tablePrivileges  = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "ALL"}
	defaultObjects   = map[string][]string{
		"tables":    tablePrivileges,
		"sequences": {"USAGE", "SELECT", "UPDATE", "ALL"},
		"functions": {"EXECUTE", "ALL"},
	}
)

// normalizePrivileges upper-cases, maps TEMP to TEMPORARY, checks against allowed and
// removes duplicates.
func normalizePrivileges(flag string, privs, allowed []string) ([]string, error) {
	var out []string
	for _, p := range privs {
		u := strings.ToUpper(strings.TrimSpace(p))
		if u == "TEMP" {
			u = "TEMPORARY"
		}
		if u == "ALL PRIVILEGES" {
			u = "ALL"
		}
		ok := false
		for _, a := range allowed {
			if u == a {
				ok = true
				break
			}
		}
		if !ok {
			return nil, usageErrorf("--%s: %q is not one of %s", flag, p, strings.Join(allowed, ", "))
		}
		out = append(out, u)
	}
	return dedupe(out), nil
}

// normalizeOID accepts an object ID in any of .NET Guid.Parse's formats - D
// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), N (32 hex digits), B ({D}), P ((D)) - plus
// urn:uuid:D, in any case with surrounding whitespace, and returns the canonical lowercase
// D form that Entra and pgaadauth use (pgaadauth_list_principals returns object IDs that way).
func normalizeOID(flag, oid string) (string, error) {
	s := strings.TrimSpace(oid)
	if len(s) > 2 && s[0] == '(' && s[len(s)-1] == ')' {
		s = s[1 : len(s)-1] // P format; uuid.Parse handles D, N, B and urn:uuid:
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return "", usageErrorf("--%s: %q is not an object ID (GUID)", flag, oid)
	}
	return u.String(), nil
}

var principalTypes = []string{"user", "group", "service"}

func checkType(flag, t string) error {
	for _, v := range principalTypes {
		if t == v {
			return nil
		}
	}
	return usageErrorf("--%s: %q must be one of %s", flag, t, strings.Join(principalTypes, ", "))
}

func qualified(schema, name string) string {
	return fmt.Sprintf("%s.%s", pg.Ident(schema), pg.Ident(name))
}
