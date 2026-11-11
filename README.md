# azpgaad

Manage Microsoft Entra (Azure AD) roles and privileges on **Azure Database for PostgreSQL flexible server** from the command line. It ships as a single static binary with no runtime dependencies: neither psql or libpq are required.

Everything here builds on Microsoft's [Manage Microsoft Entra roles](https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-entra-users) documentation; `azpgaad <command> --help` quotes the relevant parts.

## Installation

There are download scripts in the repository that get the latest release (or the one pinned with `--version`/`-Version`) for the current platform.

`shell` (POSIX):

```sh
# Linux / macOS (sh, bash, dash, busybox ash, zsh): saves ./azpgaad
# Git Bash/MSYS2/Cygwin: saves .\azpgaad.exe
curl --fail --silent --show-error --location "https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.sh" | sh
# options: --output PATH, --version vX.Y.Z (pin a release, e.g. in pipelines), --require-attestation
curl --fail --silent --show-error --location "https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.sh" | sh -s -- --output /usr/local/bin/azpgaad --version v0.1.0
```

Powershell (`powershell.exe` and `pwsh` both supported):

```powershell
# Windows PowerShell 5.1 or PowerShell 7 (Windows/Linux/macOS): saves .\azpgaad.exe (or ./azpgaad)
(Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.ps1').Content | Invoke-Expression
# with parameters: -OutFile, -Version, -RequireAttestation
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.ps1').Content)) -OutFile .\tools\azpgaad.exe
```

`cmd.exe` (batch):

```bat
rem cmd.exe / batch files (Windows 10+ includes curl.exe); runs download.ps1 via Windows PowerShell
curl.exe --fail --silent --show-error --location --output download.cmd "https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.cmd"
call download.cmd --output tools\azpgaad.exe
del download.cmd
if errorlevel 1 exit /b 1
rem options: --output PATH, --version vX.Y.Z, --require-attestation; exit 0 ok, 1 failed, 2 bad arguments
```

Or download a binary or a versioned `.tar.gz` from [Releases](https://github.com/jeremy-morren/az-pg-aad-cli/releases).

## Log in

`login` checks/acquires the credentials and writes a **token file**. Every other command reads it from `--token-file` or from the `PGAADTOKENFILE` environment variable, which holds the path to the token file.

```sh
export PGAADTOKENFILE="$(mktemp)"        # PowerShell: $env:PGAADTOKENFILE = (New-TemporaryFile)
azpgaad login --server myserver --azure  # myserver is automatically normalized to myserver.postgres.database.azure.com
azpgaad login show                       # what the token file holds (never the token or password)
```

| Option | Meaning |
|---|---|
| `--azure [--username U]` | Microsoft Entra token from `DefaultAzureCredential`: environment service principal, workload identity, managed identity (user-assigned: set `AZURE_CLIENT_ID`), az CLI, azd. The token is stored in the token file and refreshed automatically within 10 minutes of expiry. If `--username` is omitted, the Postgres role name is looked up in Microsoft Graph: `/me` for users or `servicePrincipals/{oid}` for managed identities and service principals, which needs no Graph permissions. If Graph isn't available it falls back to the token's `upn` claim. |
| `--pg-username PG-USER [--pg-pass-env-var VAR]` | Plain Postgres authentication. The password is read from the environment variable `VAR` (default `PGPASSWORD`, like psql). If the default variable isn't set you're prompted; a variable you name explicitly must be set. |
| `--sslmode` | `disable`, `allow`, `prefer`, `require`, `verify-ca` or `verify-full` (**default `verify-full`**): verifies server certificate (with same meaning as `psql`) (see [Table 32.1. SSL Mode Descriptions](https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-PROTECTION) |
| `--sslrootcert` | `system` (default): the machine's trust store (CryptoAPI on Windows). Alternatively, supply a CA PEM file: only those are trusted, and the PEM is copied into the token file. |

The token file is plain JSON written to disk, containing all details subsequent commands require to connect to the database. `login` reports what it is about to do on stderr (`logging into server myserver.postgres.database.azure.com:5432 (database postgres, sslmode verify-full) as alice@contoso.com with a Microsoft Entra token (DefaultAzureCredential)`).

`login show` prints the token file's settings without contacting the server:

```
source:      token file
tokenFile:   /tmp/tmp.Xb3kq9
server:      myserver.postgres.database.azure.com
port:        5432
database:    postgres
user:        alice@contoso.com
method:      azure
sslmode:     verify-full
sslrootcert: system
expires:     2026-11-11 14:38:28 +10:00
```

`sslrootcert` is `system` or `embedded` (a PEM copied in at login, listed by certificate subject in `sslrootcertSubjects`).

## Commands

```
azpgaad version | login show | server info
azpgaad db list [--with-schemas] | schema list --database D
azpgaad principal list [--exclude-self] [--exclude-names JSON] [--include-builtin]
azpgaad role list [--database D] | role create [--on-conflict relabel] | role enable-oid | role drop
azpgaad role grant|revoke --names JSON --roles JSON          # role membership
azpgaad role revoke-all --names JSON --database D [--memberships]
azpgaad db|schema|table|default-privileges grant|revoke --names JSON --privileges JSON --database D
azpgaad privileges list --database D [--level db|schema|table|default]
azpgaad owner list|reassign --database D [--to R]
azpgaad apply --spec @state.json [--prune revoke|drop] [--dry-run]   # desired state, one transaction
```

Run `azpgaad <command> --help` for details.

## Usage

Give a managed identity read/write access to a database, then remove it again:

```bash
export PGAADTOKENFILE=~/.azpgaad/prod.json
azpgaad login --server myserver --azure

# Create the Entra role and let it connect to "appdb"
azpgaad role create --name my-app --oid 00000000-0000-0000-0000-000000000000 --type service --if-not-exists
azpgaad db grant --name my-app --privilege CONNECT --database appdb

# Read and write every table, in every database
azpgaad role grant --name my-app --roles '["pg_read_all_data","pg_write_all_data"]'

# Check the permissions available to my-app
azpgaad role list --database appdb --query "[?roleName=='my-app']"

# Remove: revoke everything on appdb, then drop the role
azpgaad role revoke --name my-app --roles '["pg_read_all_data","pg_write_all_data"]' --if-exists
azpgaad role revoke-all --name my-app --database appdb --yes
azpgaad role drop --name my-app --yes
```

Or describe the desired state and let `apply` work out the difference (one transaction, printed as a diff):

```bash
cat > state.json <<'EOF'
{"principals": [
  {"name": "my-app", "oid": "00000000-0000-0000-0000-000000000000", "type": "service",
   "roles": ["pg_read_all_data", "pg_write_all_data"],
   "databases": {"appdb": ["CONNECT"]}}
]}
EOF
azpgaad apply --spec @state.json --dry-run              # what would change; checked by the server, then rolled back
azpgaad apply --spec @state.json                        # create and grant what's missing
azpgaad apply --spec @state.json --prune revoke --yes   # also revoke what the spec doesn't list
```

> The `pgaadauth_*` functions live in the `postgres` database, so the tool always runs them there regardless of which database you're working on.

### Parameters

- **List inputs**: parameters that take a singular value (e.g. `--name 'odd[name'`, never parsed) also take a plural form as a json array (e.g. `--names '["a","b"]'`), or `@file` / `@-` to read the array from a file or stdin. `[]` is a no-op.
- **Batches are atomic.** `GRANT … TO "a", "b"` and `DROP ROLE "a", "b"` are single statements, everything else in a command runs in one transaction.
- **Idempotency.**: `role create --if-not-exists`, `role drop --if-exists`, and `--if-exists` on every revoke-type command. Postgres already treats repeated grants as no-ops.
- **`--dry-run`**: on every command that changes something prints the SQL without running it. For `role create` and `role enable-oid` it runs the statements and rolls them back, so the server checks the object IDs without changing anything.
- **Guid parsing**: Object IDs are accepted in any .NET `Guid` format (`D`, `N`, `{B}`, `(P)`, any case) and sent to the server in lowercase hyphenated form.
- **`--echo`** writes each statement that changes something to stderr as it runs, as SQL with the values inlined and `BEGIN`/`COMMIT` around transactions (with `--dry-run`, the statements are marked as not run). No need to parse `.statements` out of the result.
- **`--debug`** shows every SQL statement (queries too) with its parameter values on stderr, with connection details but never credentials.
- **`PUBLIC`**: as a grantee (`--name PUBLIC`, any case) it means every role, as in SQL, e.g. `azpgaad db revoke --name PUBLIC --privilege CONNECT --database appdb`.
- **`--query`** applies a JMESPath expression to the output, exactly like `az --query`.
- **`--output`**: `tsv` (default) prints text: an object as an aligned `key: value` list (like PowerShell's `Format-List`, nested values as compact JSON), an array of objects as a table with a header row of field names (fields that are nested in any row are left out; select them with `--query`), and scalars bare. `-o json` is indented JSON and `-o jsonc` is compact JSON on one line.
- **`--yes`** confirmation is needed for `role drop`, `role revoke-all` and `apply --prune` (when it would revoke or drop something) but can be overridden with this flag. If no tty is attached and `--yes` is not provided the command exits with code `2`

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success, including no-ops, `--if-exists`/`--if-not-exists` skips and `--dry-run` |
| 1 | error (SQL, connection, …) |
| 2 | usage error (bad flags or JSON, missing `--yes` without a terminal) |
| 3 | not logged in, or an `--azure` token expired and no credential can refresh it |
| 4 | internal error (bug; stack trace on stderr) |

Diagnostics go to stderr; stdout carries only the result. Output formats: `-o tsv` (default) is text for reading; `-o json` is indented JSON and `-o jsonc` is compact JSON on one line (handy for passing into another command). To capture a value in a script (especially with `for /f` in cmd), select it with `--query`: a scalar, or an array of scalars (one per line), prints bare, with no header.

### Without a token file

For short-lived CI containers, skip `login` and set `PGAADSERVER` instead. Every command then gets its own Microsoft Entra token from `DefaultAzureCredential` and nothing is written to disk:

```sh
export PGAADSERVER=myserver            # required
export PGAADUSER=my-pipeline-identity  # optional: else looked up in Microsoft Graph by every command
azpgaad role list
```

Optional: `PGAADDATABASE` (default `postgres`), `PGAADSSLMODE` (default `verify-full`), `PGAADSSLROOTCERT` (default `system`, or a PEM file). A token file named by `--token-file` or `PGAADTOKENFILE` takes precedence. `login show` reports these settings with `source: environment (PGAADSERVER)`.

## Command reference

Every command also takes the global flags `--token-file F` (default `$PGAADTOKENFILE`), `-o tsv|json|jsonc`, `--query EXPR`, `--echo` and `--debug`. Flags written as `--name`/`--names` come in singular/plural pairs (one raw value, or a JSON array / `@file` / `@-`). Every command that changes something supports `--dry-run`.

### Setup and information

| Command | What it does |
|---|---|
| `azpgaad version` | Prints the version, commit, Go version, OS and architecture. Needs no token file. |
| `azpgaad login` | Authenticates (`--azure`, or `--pg-username` with the password from `PGPASSWORD`, `--pg-pass-env-var VAR` or a prompt), connects once to check, and writes the token file. Prints a `logging into server …` line on stderr first. Options: `--server`, `--port`, `--database`, `--sslmode`, `--sslrootcert`, `--username`. |
| `azpgaad login show` | Shows the token file's settings: server, port, database, user, method, sslmode, sslrootcert (`system` or `embedded`, with the certificate subjects) and, for `--azure`, the token's expiry as local time and UTC offset. Never shows the token or password, and doesn't contact the server. |
| `azpgaad server info` | Shows the server version (`version`, `versionNum`, `major`, `minor`, full `versionString`), the current and session user, the database, and the `pgaadauth` extension version. |
| `azpgaad db list` | Lists databases and their owners. `--with-schemas` adds each database's schemas (databases that can't be opened get an `error` field); `--all-schemas` includes system schemas. |
| `azpgaad schema list` | Lists the schemas in `--database` and their owners. System schemas (`pg_*`, `information_schema`, `cron`) only with `--all-schemas`. |

### Microsoft Entra principals and roles

| Command | What it does |
|---|---|
| `azpgaad principal list` | Lists the roles mapped to Microsoft Entra objects (`pgaadauth_list_principals`): name, type, object ID, tenant ID, `isMfa`, `isAdmin`. `--exclude-self` and `--exclude-name`/`--exclude-names` leave principals out, e.g. to find roles not in a desired list. Built-in principals (names starting with `aad_`) are left out unless `--include-builtin`. |
| `azpgaad role list` | Lists all roles with their memberships and Entra details (`aad` property is `null` for non-Entra roles). `--database D` adds which of `CONNECT`, `CREATE`, `TEMPORARY` each role has there. System roles only with `--all`. The `aad` details don't include `isMfa`; `principal list` has it. |
| `azpgaad role create` | Creates Entra roles from object IDs: `--name`, `--oid`, `--type user\|group\|service`, `--admin`, `--mfa`, or many at once with `--principals` (one transaction). The server validates every object ID. `--if-not-exists` skips roles that already exist with the same object ID. `--on-conflict relabel` handles a role whose object ID changed (e.g. a managed identity deleted and recreated under the same name) by updating the mapping, keeping the role's privileges; `--on-conflict recreate` drops and recreates it. |
| `azpgaad role enable-oid` | Maps existing roles to Entra objects by setting the `pgaadauth` security label (`--name`, `--oid`, `--type`, `--admin`, or `--principals`). The server validates the object IDs. |
| `azpgaad role drop` | Drops roles by `--name`/`--names` or by object ID (`--oid`/`--oids`), in one statement. `--if-exists` ignores missing roles. Explains when a role still owns objects or holds privileges. Asks for confirmation unless `--yes` is provided. |
| `azpgaad role grant` | Grants role membership: `--role`/`--roles` (e.g. `pg_read_all_data`) to `--name`/`--names`, in one statement. |
| `azpgaad role revoke` | Revokes role membership; `--if-exists` skips roles that don't exist. |
| `azpgaad role revoke-all` | Revokes every database and schema privilege on `--database` from the roles (what you do before dropping them). `--memberships` also revokes their role memberships (e.g. `pg_read_all_data`), except in Azure-managed `azure*` roles. Asks for confirmation unless `--yes`, and warns when `PUBLIC` can still connect. |

### Desired state

| Command | What it does |
|---|---|
| `azpgaad apply` | Brings Entra principals, their role memberships and their database privileges (`CONNECT`, `CREATE`, `TEMPORARY`) to the state in `--spec` (JSON, `@file` or `@-`), in **one transaction** on one connection, and prints the changes as a diff (`op` `+`/`-`/`~`, `principal`, `what`, `sql`). Without `--prune` it only adds, which makes it a batch grant for many principals. `--prune revoke` also revokes memberships and database privileges the spec doesn't list, from listed principals and from unlisted Entra principals; `--prune drop` drops the unlisted ones. Pruning never touches the logged-in user, Entra admins, built-in principals or `--exclude-prefix` matches, and `--managed-prefix` limits it to names with a prefix. `--on-conflict` works as for `role create`. `--dry-run` makes the changes and rolls them back, so the server checks everything. See `azpgaad apply --help` for the spec format. |

### Privileges

All take `--name`/`--names` (grantees; `PUBLIC` means every role), `--privilege`/`--privileges` and `--database`. Schema, table and default-privilege commands apply to every non-system schema unless `--schema`/`--schemas` narrows them. Revokes take `--if-exists` to skip missing roles, schemas and tables.

| Command | What it does |
|---|---|
| `azpgaad db grant` / `db revoke` | Grants or revokes `CONNECT`, `CREATE`, `TEMPORARY` (or `TEMP`) or `ALL` on the database. Grant defaults to `CONNECT`. |
| `azpgaad schema grant` / `schema revoke` | Grants or revokes `USAGE`, `CREATE` or `ALL` on schemas. |
| `azpgaad table grant` / `table revoke` | Grants or revokes `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` or `ALL` on all tables in the schemas, or on named tables with `--table`/`--tables`. |
| `azpgaad default-privileges grant` / `… revoke` | Sets the privileges that objects created later get (`ALTER DEFAULT PRIVILEGES`), `--on tables\|sequences\|functions`. `--for-role`/`--for-roles` names the roles that will create those objects; without it, only objects created by the logged-in user are affected. |
| `azpgaad privileges list` | Shows effective privileges per role, including those held through membership and `PUBLIC`: `--level db` (default), `schema`, `table` or `default`. Defaults to every non-system role plus `PUBLIC`, or `--name`/`--names`. |

### Ownership

| Command | What it does |
|---|---|
| `azpgaad owner list` | Lists the owners of `--database`, its non-system schemas, and their tables, views, materialized views, sequences, functions, procedures and aggregates. |
| `azpgaad owner reassign` | Makes `--to` the owner of the database and everything in its non-system schemas, in one transaction. Objects already owned by `--to` or by `azure*` roles are left alone. Temporarily grants the needed role memberships to the logged-in user and revokes them again at the end. Safe to re-run. |

`azpgaad completion bash|zsh|fish|powershell` prints a shell completion script.



## Development

Requires Go 1.21 or later; if yours is older than the version in `go.mod`, it downloads that version automatically.

```sh
go build ./cmd/azpgaad 
go test ./... 
```

`internal/cli/testdata/scenarios/*.txt` are CLI invocations (plus `!sql` setup/teardown lines). They're recorded against a real server and replayed byte-for-byte in tests. To re-record after a server or `pgaadauth` change:

```sh
azpgaad login --server <test-server> --azure --token-file ~/.azpgaad/test.json
export AZPGAAD_TEST_USER_OID="$(az ad signed-in-user show --query id --output tsv)"   # a real Entra user, for role creation
AZPGAAD_RECORD_TOKEN_FILE=~/.azpgaad/test.json go test ./internal/cli -run TestScenarios -record
git diff internal/cli/testdata
```

Emails, GUIDs and server host names returned by the server are replaced with placeholders before recordings are written.

See [Manage Microsoft Entra Roles in Azure Database for PostgreSQL flexible server](https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-entra-users) for the functions used by the relevant commands.

## LICENSE

Available under the [MIT](./LICENSE) License