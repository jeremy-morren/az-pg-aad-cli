package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg/recorder"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

func TestEnvLoginWithoutTokenFile(t *testing.T) {
	env := map[string]string{"PGAADSERVER": "myserver", "PGAADUSER": "ci-identity"}
	newApp := func(out, errb *bytes.Buffer) *App {
		a := testApp(out, errb, "")
		a.Getenv = func(k string) string { return env[k] }
		return a
	}

	var out, errb bytes.Buffer
	a := newApp(&out, &errb)
	cred := &fakeCred{exp: fixedNow.Add(time.Hour)}
	a.NewCredential = func() (azcore.TokenCredential, error) { return cred, nil }
	var got pg.ConnConfig
	replay := serverInfoReplay()
	a.OpenDB = func(cfg pg.ConnConfig) pg.DB { got = cfg; return replay }
	if code := a.Run([]string{"server", "info", "--query", "major"}); code != ExitOK || out.String() != "16\n" {
		t.Fatalf("exit %d out %q err %s", code, out.String(), errb.String())
	}
	if cred.calls != 1 || got.Host != "myserver.postgres.database.azure.com" || got.User != "ci-identity" ||
		got.SSLMode != "verify-full" || got.RootPEM != "" || got.Password == "" {
		t.Fatalf("calls %d, connection %+v", cred.calls, got)
	}

	// login show reports the environment settings; nothing needs a token file.
	out.Reset()
	if code := newApp(&out, &errb).Run([]string{"login", "show", "--output", "json"}); code != ExitOK {
		t.Fatalf("login show: exit %d: %s", code, errb.String())
	}
	var info loginInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil || info.Source != "environment (PGAADSERVER)" ||
		info.TokenFile != "" || info.Server != "myserver.postgres.database.azure.com" || info.User != "ci-identity" {
		t.Fatalf("login show: %v %s", err, out.String())
	}

	// A token file, when named, wins over PGAADSERVER.
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "pg", Password: "pw"}})
	env[profile.EnvVar] = tf
	out.Reset()
	if code := newApp(&out, &errb).Run([]string{"login", "show", "--query", "server"}); code != ExitOK || out.String() != "s.invalid\n" {
		t.Fatalf("token file should win: exit %d %q", code, out.String())
	}

	// No credential: not logged in (exit 3).
	delete(env, profile.EnvVar)
	errb.Reset()
	a = newApp(&out, &errb)
	a.NewCredential = func() (azcore.TokenCredential, error) { return &fakeCred{err: errors.New("no credential")}, nil }
	if code := a.Run([]string{"server", "info"}); code != ExitNotLoggedIn || !strings.Contains(errb.String(), "PGAADSERVER") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

func TestPublicGrantee(t *testing.T) {
	code, stdout, stderr := run(t, "", "", "db", "revoke", "--name", "PUBLIC", "--privilege", "CONNECT",
		"--database", "appdb", "--dry-run", "--query", "statements[0]")
	if want := `REVOKE CONNECT ON DATABASE "appdb" FROM PUBLIC` + "\n"; code != ExitOK || stdout != want {
		t.Fatalf("exit %d out %q err %s", code, stdout, stderr)
	}

	// Schemas named with --schema are looked up on the server; replay that.
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "pg", Password: "pw"}})
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tf)
	a.OpenDB = func(pg.ConnConfig) pg.DB {
		return recorder.NewReplay([]recorder.Entry{
			{DB: "d", Op: "connect"},
			{DB: "d", Op: "query", SQL: sqlSchemasNamed, Args: json.RawMessage(`[["s"]]`),
				Result: json.RawMessage(`{"columns":["nspname"],"rows":[["s"]]}`)},
		})
	}
	args := []string{"schema", "grant", "--names", `["public","app"]`, "--privilege", "USAGE", "--database", "d", "--schema", "s",
		"--dry-run", "--query", "statements[0]"}
	if code := a.Run(args); code != ExitOK || out.String() != `GRANT USAGE ON SCHEMA "s" TO PUBLIC, "app"`+"\n" {
		t.Fatalf("exit %d out %q err %s", code, out.String(), errb.String())
	}
	if got := pg.Grantees([]string{"Public", "PUBLIC", "app"}); got != `PUBLIC, PUBLIC, "app"` {
		t.Errorf("Grantees: %s", got)
	}
}

func TestEchoInline(t *testing.T) {
	got := pg.Inline(sqlCreatePrincipal, "it's", "0000", "user", true, false)
	want := `select pg_catalog.pgaadauth_create_principal_with_oid('it''s'::text, '0000'::text, 'user'::text, true::boolean, false::boolean)`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	var buf bytes.Buffer
	pg.EchoStatement(&buf, "", "select $1 = any($2) and $10 is null", "a", []string{"x", "y"}, 3, 4, 5, 6, 7, 8, 9, nil)
	if want := "select 'a' = any(ARRAY['x', 'y']::text[]) and NULL is null;\n"; buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

func TestEchoDryRun(t *testing.T) {
	code, stdout, stderr := run(t, "", "", "role", "grant", "--name", "a", "--role", "r", "--dry-run", "--echo", "--query", "statements[0]")
	if code != ExitOK || stdout != "GRANT \"r\" TO \"a\"\n" ||
		stderr != "-- [postgres] --dry-run: not run\nGRANT \"r\" TO \"a\";\n" {
		t.Fatalf("exit %d out %q err %q", code, stdout, stderr)
	}
}

func TestParseApplySpec(t *testing.T) {
	spec, err := parseApplySpec([]byte(`{"principals":[{"name":"a","oid":"{0E3A1B2C-4D5E-6F70-8192-A3B4C5D6E7F8}","type":"service",
		"roles":["r","r"],"databases":{"d":["temp","connect"],"e":["all"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p := spec.Principals[0]
	if p.OID != "0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8" || len(p.Roles) != 1 ||
		strings.Join(p.Databases["d"], ",") != "TEMPORARY,CONNECT" || strings.Join(p.Databases["e"], ",") != "CONNECT,CREATE,TEMPORARY" {
		t.Fatalf("%+v", p)
	}
	const oid = "0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	for _, bad := range []string{
		`{"principals":[{"name":"a","oid":"x","type":"user"}]}`,
		`{"principals":[{"name":"a","oid":"` + oid + `","type":"robot"}]}`,
		`{"principals":[{"name":"a","oid":"` + oid + `","type":"user","rolez":[]}]}`,
		`{"principals":[{"name":"a","oid":"` + oid + `","type":"user","databases":{"d":["SELECT"]}}]}`,
		`{"principals":[{"name":"a","oid":"` + oid + `","type":"user"},{"name":"a","oid":"` + oid + `","type":"user"}]}`,
		`{"principals":[{"oid":"` + oid + `","type":"user"}]}`,
	} {
		if _, err := parseApplySpec([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestPlanApply(t *testing.T) {
	const oid, other = "0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8", "11111111-1111-1111-1111-111111111111"
	spec, err := parseApplySpec([]byte(`{"principals":[
		{"name":"new","oid":"` + oid + `","type":"service","roles":["pg_read_all_data"],"databases":{"app":["CONNECT"]}},
		{"name":"keep","oid":"` + oid + `","type":"user","roles":["r1","r2"],"databases":{"app":["CONNECT"]}},
		{"name":"moved","oid":"` + oid + `","type":"service"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	str := func(s string) *string { return &s }
	state := func() *applyState {
		return &applyState{
			currentUser: "me",
			entra: map[string]entraPrincipal{
				"me": {Name: "me", IsAdmin: true}, "admin2": {Name: "admin2", IsAdmin: true},
				"keep": {Name: "keep"}, "moved": {Name: "moved"}, "gone": {Name: "gone"},
				"aad_builtin": {Name: "aad_builtin"}, "ext_x": {Name: "ext_x"},
			},
			entraNames: []string{"aad_builtin", "admin2", "ext_x", "gone", "keep", "me", "moved"},
			roles:      map[string]*string{"keep": str(oid), "moved": str(other)},
			memberOf:   map[string][]string{"keep": {"r1", "old"}, "gone": {"pg_read_all_data"}, "admin2": {"x"}, "aad_builtin": {"y"}},
			dbPrivs: map[string]map[string][]string{
				"keep":        {"app": {"CONNECT", "TEMPORARY"}, "other": {"CREATE"}},
				"gone":        {"app": {"CONNECT"}},
				"moved":       {"app": {"CONNECT"}},
				"aad_builtin": {"app": {"CONNECT"}},
			},
		}
	}
	plan := func(prune, conflict string) (string, error) {
		var out, errb bytes.Buffer
		changes, err := testApp(&out, &errb, "").planApply(spec, state(), prune, conflict, []string{"ext_"}, nil)
		var lines []string
		for _, c := range changes {
			lines = append(lines, c.Op+" "+c.Principal+" | "+c.SQL)
		}
		return strings.Join(lines, "\n"), err
	}

	if _, err := plan("", "error"); err == nil || !strings.Contains(err.Error(), `"moved"`) {
		t.Fatalf("object ID conflict should fail: %v", err)
	}

	got, err := plan("", "relabel")
	if err != nil {
		t.Fatal(err)
	}
	want := `+ new | select pg_catalog.pgaadauth_create_principal_with_oid('new'::text, '` + oid + `'::text, 'service'::text, false::boolean, false::boolean)
~ moved | SECURITY LABEL FOR "pgaadauth" ON ROLE "moved" IS 'aadauth,oid=` + oid + `,type=service'
+ new | GRANT "pg_read_all_data" TO "new"
+ new | GRANT CONNECT ON DATABASE "app" TO "new"
+ keep | GRANT "r2" TO "keep"`
	if got != want {
		t.Fatalf("no prune:\n%s\nwant:\n%s", got, want)
	}

	// Listed principals lose what the spec doesn't list (a relabelled one keeps nothing it
	// isn't given); unlisted ones lose everything. The logged-in user, admins, built-in
	// principals and --exclude-prefix matches are never touched.
	got, _ = plan("revoke", "relabel")
	wantPrune := want + `
- keep | REVOKE "old" FROM "keep"
- keep | REVOKE TEMPORARY ON DATABASE "app" FROM "keep"
- keep | REVOKE CREATE ON DATABASE "other" FROM "keep"
- moved | REVOKE CONNECT ON DATABASE "app" FROM "moved"
- gone | REVOKE "pg_read_all_data" FROM "gone"
- gone | REVOKE CONNECT ON DATABASE "app" FROM "gone"`
	if got != wantPrune {
		t.Fatalf("prune revoke:\n%s\nwant:\n%s", got, wantPrune)
	}

	// recreate: database privileges are revoked first (they'd block DROP ROLE), then the
	// role is dropped and created; unlisted principals are dropped.
	got, err = plan("drop", "recreate")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"~ moved | REVOKE CONNECT ON DATABASE \"app\" FROM \"moved\"\n~ moved | DROP ROLE \"moved\"\n~ moved | select pg_catalog.pgaadauth_create_principal_with_oid('moved'",
		"- gone | REVOKE CONNECT ON DATABASE \"app\" FROM \"gone\"\n- gone | DROP ROLE \"gone\"",
	} {
		if !strings.Contains(got, s) {
			t.Fatalf("prune drop: missing\n%s\nin\n%s", s, got)
		}
	}
	for _, s := range []string{`REVOKE "pg_read_all_data" FROM "gone"`, "admin2", "aad_builtin", "ext_x", `"me"`} {
		if strings.Contains(got, s) {
			t.Fatalf("prune drop: unexpected %s in\n%s", s, got)
		}
	}
}
