package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg/recorder"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

func run(t *testing.T, tokenFile, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tokenFile)
	a.Stdin = strings.NewReader(stdin)
	code = a.Run(args)
	return code, out.String(), errb.String()
}

func TestExitCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"version"}, ExitOK},
		{"unknown command", []string{"bogus"}, ExitUsage},
		{"unknown flag", []string{"version", "--bogus"}, ExitUsage},
		{"bad output", []string{"version", "-o", "yaml"}, ExitUsage},
		{"missing required flag", []string{"db", "grant", "--name", "a", "--privilege", "CONNECT"}, ExitUsage},
		{"singular and plural", []string{"role", "grant", "--name", "a", "--names", `["b"]`, "--role", "r", "--dry-run"}, ExitUsage},
		{"plural not JSON", []string{"role", "grant", "--names", "a", "--role", "r", "--dry-run"}, ExitUsage},
		{"plural not strings", []string{"role", "grant", "--names", "[1]", "--role", "r", "--dry-run"}, ExitUsage},
		{"bad privilege", []string{"db", "grant", "--name", "a", "--privilege", "DROP", "--database", "d", "--dry-run"}, ExitUsage},
		{"bad oid", []string{"role", "create", "--name", "a", "--oid", "x", "--type", "user"}, ExitUsage},
		{"bad type", []string{"role", "create", "--name", "a", "--oid", "00000000-0000-0000-0000-000000000000", "--type", "robot"}, ExitUsage},
		{"no confirm without tty", []string{"role", "drop", "--name", "a"}, ExitUsage},
		{"bad query", []string{"version", "--query", "[["}, ExitUsage},
		{"no token file", []string{"role", "list"}, ExitNotLoggedIn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tf := missing
			if c.name == "no token file" {
				tf = ""
			}
			code, _, stderr := run(t, tf, "", c.args...)
			if code != c.want {
				t.Errorf("exit %d, want %d; stderr: %s", code, c.want, stderr)
			}
		})
	}
}

func TestMissingTokenFileIsNotLoggedIn(t *testing.T) {
	code, _, stderr := run(t, filepath.Join(t.TempDir(), "nope.json"), "", "role", "list")
	if code != ExitNotLoggedIn || !strings.Contains(stderr, "azpgaad login") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestPanicIsInternalError(t *testing.T) {
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "pg"}})
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tf)
	a.OpenDB = func(pg.ConnConfig) pg.DB { panic("boom") }
	if code := a.Run([]string{"role", "list"}); code != ExitInternal {
		t.Fatalf("exit %d, want %d (Go's own panic exit code 2 would look like a usage error)", code, ExitInternal)
	}
	if !strings.Contains(errb.String(), "internal error: boom") {
		t.Fatal(errb.String())
	}
}

func TestListFlagsAndDryRun(t *testing.T) {
	dir := t.TempDir()
	namesFile := filepath.Join(dir, "names.json")
	os.WriteFile(namesFile, []byte(`["a","b","a"]`), 0o600)

	cases := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"singular is literal", "", []string{"role", "grant", "--name", `[odd"name`, "--role", "r"},
			`GRANT "r" TO "[odd""name"`},
		{"plural JSON, deduped", "", []string{"role", "grant", "--names", `["a","b","a"]`, "--roles", `["r1","r2"]`},
			`GRANT "r1", "r2" TO "a", "b"`},
		{"@file", "", []string{"role", "revoke", "--names", "@" + namesFile, "--role", "r"},
			`REVOKE "r" FROM "a", "b"`},
		{"@- stdin", `["x"]`, []string{"role", "grant", "--names", "@-", "--role", "r"},
			`GRANT "r" TO "x"`},
		{"privileges normalised", "", []string{"db", "grant", "--name", "a", "--privileges", `["temp","Connect","TEMPORARY"]`, "--database", "my db"},
			`GRANT TEMPORARY, CONNECT ON DATABASE "my db" TO "a"`},
		{"drop if exists", "", []string{"role", "drop", "--names", `["x","y"]`, "--if-exists"},
			`DROP ROLE IF EXISTS "x", "y"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := run(t, "", c.stdin, append(c.args, "--dry-run", "--output", "json")...)
			if code != ExitOK {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			var res stmtResult
			if err := json.Unmarshal([]byte(stdout), &res); err != nil {
				t.Fatalf("%v: %s", err, stdout)
			}
			if !res.DryRun || len(res.Statements) != 1 || res.Statements[0] != c.want {
				t.Fatalf("got %q, want %q", res.Statements, c.want)
			}
		})
	}
}

func TestEmptyArrayIsNoOp(t *testing.T) {
	code, stdout, stderr := run(t, "", "", "role", "grant", "--names", "[]", "--role", "r", "--output", "json")
	if code != ExitOK || !strings.Contains(stdout, `"statements": []`) {
		t.Fatalf("exit %d out %s err %s", code, stdout, stderr)
	}
}

func TestQueryAndTSV(t *testing.T) {
	code, stdout, _ := run(t, "", "", "version", "--query", "version", "-o", "tsv")
	if code != ExitOK || stdout != "test\n" {
		t.Fatalf("exit %d %q", code, stdout)
	}
	code, stdout, _ = run(t, "", "", "version", "--query", "[os, arch]", "-o", "json")
	if want := "[\n  \"" + runtime.GOOS + "\",\n  \"" + runtime.GOARCH + "\"\n]\n"; code != ExitOK || stdout != want {
		t.Fatalf("json should be indented like az -o json: exit %d %q", code, stdout)
	}
}

func TestWriteTSV(t *testing.T) {
	cases := []struct{ name, in, want string }{
		// Arrays: one row per element, scalar fields in document order, nested omitted.
		{"array", `[{"b":2,"a":"x","nested":{"k":1},"list":[1],"n":null,"t":true},["p",1.5,null],"s"]`,
			"2\tx\t\ttrue\np\t1.5\t\ns\n"},
		// Arrays of objects: a header row; a field nested in any row is left out of every
		// row, and a field missing from a row is empty there.
		{"table", `[{"name":"a","aad":null,"n":1},{"name":"b","aad":{"oid":"x"},"extra":true}]`,
			"name\tn\textra\na\t1\t\nb\t\ttrue\n"},
		{"scalar array", `["a","b"]`, "a\nb\n"},
		{"empty array", `[]`, ""},
		// Objects: an aligned property list, nested values as compact JSON, no trailing
		// spaces after an empty value.
		{"object", `{"server":"s.example.com","user":"alice","n":null,"principals":[{"name":"a"}],"ok":true}`,
			"server:     s.example.com\nuser:       alice\nn:\nprincipals: [{\"name\":\"a\"}]\nok:         true\n"},
		{"scalar", `"just text"`, "just text\n"},
		{"number", `16`, "16\n"},
		{"null", `null`, ""},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := writeTSV(&buf, []byte(c.in)); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if buf.String() != c.want {
			t.Errorf("%s: got %q want %q", c.name, buf.String(), c.want)
		}
	}
}

func TestDefaultOutputIsTSV(t *testing.T) {
	code, stdout, _ := run(t, "", "", "version")
	if code != ExitOK || !strings.HasPrefix(stdout, "version:   test\n") {
		t.Fatalf("default output should be a tsv property list: exit %d %q", code, stdout)
	}
}

func TestLoginShow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.json")
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	p := &profile.Profile{
		V: profile.Version, Server: "s.postgres.database.azure.com", Port: 5432, Database: "postgres",
		User: "alice@example.com", SSLMode: "verify-full", SSLRootCert: profile.RootCert{Mode: "system"},
		Auth: profile.Auth{Method: "azure", Token: "SECRET-TOKEN", Expires: exp},
	}
	if err := profile.Save(path, p); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, path, "", "login", "show")
	want := "source:      token file\n" +
		"tokenFile:   " + path + "\n" +
		"server:      s.postgres.database.azure.com\n" +
		"port:        5432\n" +
		"database:    postgres\n" +
		"user:        alice@example.com\n" +
		"method:      azure\n" +
		"sslmode:     verify-full\n" +
		"sslrootcert: system\n" +
		"expires:     " + exp.Local().Format("2006-01-02 15:04:05 -07:00") + "\n"
	if code != ExitOK || stdout != want {
		t.Fatalf("exit %d stderr %q\ngot:\n%s\nwant:\n%s", code, stderr, stdout, want)
	}
	if strings.Contains(stdout+stderr, "SECRET") {
		t.Fatal("login show must not print the token")
	}

	// Embedded CA: listed by subject; password auth has no expiry.
	p.SSLRootCert = profile.RootCert{Mode: "pem", PEM: testCAPEM(t, "Test Root CA")}
	p.Auth = profile.Auth{Method: "pg", Password: "SECRET-PW"}
	if err := profile.Save(path, p); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = run(t, path, "", "login", "show", "--output", "json")
	var got loginInfo
	if err := json.Unmarshal([]byte(stdout), &got); code != ExitOK || err != nil {
		t.Fatalf("exit %d %v %q", code, err, stdout)
	}
	if got.SSLRootCert != "embedded" || len(got.SSLRootCertSubjects) != 1 || got.SSLRootCertSubjects[0] != "CN=Test Root CA" ||
		got.Expires != "" || strings.Contains(stdout, "SECRET") {
		t.Fatalf("unexpected: %s", stdout)
	}

	code, _, stderr = run(t, filepath.Join(dir, "missing.json"), "", "login", "show")
	if code != ExitNotLoggedIn {
		t.Fatalf("missing token file: exit %d %q, want %d", code, stderr, ExitNotLoggedIn)
	}
}

func testCAPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestLoginLine(t *testing.T) {
	p := &profile.Profile{Server: "s.postgres.database.azure.com", Port: 5432, Database: "postgres", SSLMode: "verify-full", User: "admin"}
	want := "logging into server s.postgres.database.azure.com:5432 (database postgres, sslmode verify-full) as admin with a password (from $PGPASSWORD)"
	if got := loginLine(p, "a password (from $PGPASSWORD)"); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestShellSplit(t *testing.T) {
	got, err := shellSplit(`role grant --names '["a","b"]' --name "x \"y\"" plain`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"role", "grant", "--names", `["a","b"]`, "--name", `x "y"`, "plain"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", got)
	}
}

// --- token refresh ---

type fakeCred struct {
	calls int
	exp   time.Time
	err   error
}

func (f *fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: fakeJWT(map[string]any{"upn": "new@example.com"}), ExpiresOn: f.exp}, nil
}

func fakeJWT(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(b) + ".sig"
}

func writeProfile(t *testing.T, p *profile.Profile) string {
	t.Helper()
	p.V, p.Server, p.Port, p.Database, p.User, p.SSLMode = profile.Version, "s.invalid", 5432, "postgres", "u", "verify-full"
	p.SSLRootCert = profile.RootCert{Mode: "system"}
	path := filepath.Join(t.TempDir(), "token.json")
	if err := profile.Save(path, p); err != nil {
		t.Fatal(err)
	}
	return path
}

// serverInfoReplay serves one `server info`.
func serverInfoReplay() *recorder.Replay {
	return recorder.NewReplay([]recorder.Entry{
		{DB: "postgres", Op: "connect"},
		{DB: "postgres", Op: "query", SQL: sqlServerInfo, Result: json.RawMessage(
			`{"columns":["version","versionnum","versionstring","currentuser","sessionuser","database","pgaadauthversion"],` +
				`"rows":[["16.4",160004,"PostgreSQL 16.4","u","u","postgres","1.9"]]}`)},
	})
}

func TestTokenRefresh(t *testing.T) {
	cases := []struct {
		name        string
		left        time.Duration
		wantRefresh bool
	}{
		{"fresh token reused", 11 * time.Minute, false},
		{"inside 10 minute grace", 9 * time.Minute, true},
		{"expired", -time.Minute, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldExp := fixedNow.Add(c.left)
			tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "azure", Token: "old", Expires: oldExp}})
			cred := &fakeCred{exp: fixedNow.Add(time.Hour)}
			var out, errb bytes.Buffer
			a := testApp(&out, &errb, tf)
			a.NewCredential = func() (azcore.TokenCredential, error) { return cred, nil }
			var gotPassword string
			replay := serverInfoReplay()
			a.OpenDB = func(cfg pg.ConnConfig) pg.DB { gotPassword = cfg.Password; return replay }
			if code := a.Run([]string{"server", "info"}); code != ExitOK {
				t.Fatalf("exit %d: %s", code, errb.String())
			}
			p, err := profile.Load(tf)
			if err != nil {
				t.Fatal(err)
			}
			refreshed := cred.calls > 0
			if refreshed != c.wantRefresh {
				t.Fatalf("refreshed=%v want %v", refreshed, c.wantRefresh)
			}
			if c.wantRefresh {
				if p.Auth.Token == "old" || !p.Auth.Expires.Equal(fixedNow.Add(time.Hour)) || gotPassword != p.Auth.Token {
					t.Fatalf("token file not rewritten/used: %+v (password used %q)", p.Auth, gotPassword)
				}
			} else if p.Auth.Token != "old" || gotPassword != "old" {
				t.Fatalf("token should be reused: %+v", p.Auth)
			}
		})
	}
}

func TestTokenRefreshFailureIsNotLoggedIn(t *testing.T) {
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "azure", Token: "old", Expires: fixedNow.Add(-time.Hour)}})
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tf)
	a.NewCredential = func() (azcore.TokenCredential, error) { return &fakeCred{err: errors.New("no credential")}, nil }
	if code := a.Run([]string{"server", "info"}); code != ExitNotLoggedIn {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "run azpgaad login again") {
		t.Fatal(errb.String())
	}
}

func TestPgPasswordIsNeverRefreshed(t *testing.T) {
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "pg", Password: fakeJWT(map[string]any{"exp": 1})}})
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tf)
	a.NewCredential = func() (azcore.TokenCredential, error) { t.Fatal("credential used for pg auth"); return nil, nil }
	replay := serverInfoReplay()
	a.OpenDB = func(pg.ConnConfig) pg.DB { return replay }
	if code := a.Run([]string{"server", "info", "--query", "major", "-o", "tsv"}); code != ExitOK || out.String() != "16\n" {
		t.Fatalf("exit %d out %q err %s", code, out.String(), errb.String())
	}
}

func TestNormalizeOID(t *testing.T) {
	const want = "0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"
	for _, in := range []string{
		"0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8",          // D
		"0E3A1B2C-4D5E-6F70-8192-A3B4C5D6E7F8",          // D, upper case
		"0e3a1b2c4d5e6f708192a3b4c5d6e7f8",              // N
		"{0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8}",        // B
		"(0E3A1B2C-4D5E-6F70-8192-A3B4C5D6E7F8)",        // P
		"  0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8\t",      // whitespace
		"urn:uuid:0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8", // URN
	} {
		got, err := normalizeOID("oid", in)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "not-a-guid", "0e3a1b2c-4d5e-6f70-8192", "{0e3a1b2c4d5e6f708192a3b4c5d6e7f8}", "0e3a1b2c-4d5e-6f70-8192-a3b4c5d6e7fz"} {
		if _, err := normalizeOID("oid", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOIDFormatsReachSQL(t *testing.T) {
	// enable-oid --dry-run on a fresh token file would connect; use role drop's dry run
	// path instead, which normalises before resolving: a bad format is a usage error.
	code, _, stderr := run(t, "", "", "role", "drop", "--oid", "{not-a-guid}", "--yes")
	if code != ExitUsage || !strings.Contains(stderr, "not an object ID") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestColonSwitches(t *testing.T) {
	got := colonSwitches([]string{"role", "drop", "--yes:true", "--if-exists:FALSE", "--dry-run:1", "--name:x", "--", "--yes:true"})
	want := []string{"role", "drop", "--yes=true", "--if-exists=false", "--dry-run=1", "--name:x", "--", "--yes:true"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q", got)
	}
	// End to end: --dry-run:true behaves like --dry-run, --if-exists:false like its absence.
	code, stdout, stderr := run(t, "", "", "role", "drop", "--names", `["x"]`, "--dry-run:true", "--if-exists:false")
	if code != ExitOK || !strings.Contains(stdout, `"DROP ROLE \"x\""`) {
		t.Fatalf("exit %d out %s err %s", code, stdout, stderr)
	}
	code, stdout, _ = run(t, "", "", "role", "drop", "--names", `["x"]`, "--dry-run:TRUE", "--if-exists:true")
	if code != ExitOK || !strings.Contains(stdout, "IF EXISTS") {
		t.Fatalf("exit %d out %s", code, stdout)
	}
}

func TestDebugLogsStatementsAndParameters(t *testing.T) {
	tf := writeProfile(t, &profile.Profile{Auth: profile.Auth{Method: "pg", Password: "s3cret-password"}})
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, tf)
	replay := serverInfoReplay()
	a.OpenDB = func(pg.ConnConfig) pg.DB { return replay }
	if code := a.Run([]string{"server", "info", "--debug", "--query", "major", "-o", "tsv"}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	log := errb.String()
	for _, want := range []string{"[postgres] connect u@s.invalid:5432 sslmode=verify-full", "[postgres] query (1 rows", "current_setting('server_version_num')"} {
		if !strings.Contains(log, want) {
			t.Errorf("debug log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "s3cret-password") {
		t.Fatal("debug log contains the password")
	}
	if out.String() != "16\n" {
		t.Fatalf("stdout should only carry the result, got %q", out.String())
	}
}

func TestOutputFormats(t *testing.T) {
	// Encoded the way real output is (a.print), <, > and & stay escaped and the result is
	// valid JSON that decodes back to the original value.
	var out, errb bytes.Buffer
	a := testApp(&out, &errb, "")
	if err := a.print(map[string]any{"name": "a<b>&c"}); err != nil {
		t.Fatal(err)
	}
	esc := func(hex string) string { return "\\" + "u00" + hex }
	if want := "{\n  \"name\": \"a" + esc("3c") + "b" + esc("3e") + esc("26") + "c\"\n}\n"; out.String() != want {
		t.Fatalf("json:\n%q\nwant\n%q", out.String(), want)
	}
	var decoded map[string]string
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || decoded["name"] != "a<b>&c" {
		t.Fatalf("json output must decode back to the value: %v %v", decoded, err)
	}

	var buf bytes.Buffer
	if err := writeJSON(&buf, []byte(`{"name":"x","n":[1,true,null]}`), false); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"name\": \"x\",\n  \"n\": [\n    1,\n    true,\n    null\n  ]\n}\n"
	if buf.String() != want {
		t.Fatalf("json:\n%q\nwant\n%q", buf.String(), want)
	}

	// jsonc: the same JSON, compact on one line, no colour codes.
	buf.Reset()
	if err := writeJSON(&buf, []byte("{\n  \"k\": \"v\",\n  \"n\": [1, true, null]\n}"), true); err != nil {
		t.Fatal(err)
	}
	if want := "{\"k\":\"v\",\"n\":[1,true,null]}\n"; buf.String() != want {
		t.Fatalf("jsonc: %q, want %q", buf.String(), want)
	}

	code, stdout, _ := run(t, "", "", "version", "--query", "[os, arch]", "-o", "jsonc")
	if want := "[\"" + runtime.GOOS + "\",\"" + runtime.GOARCH + "\"]\n"; code != ExitOK || stdout != want {
		t.Fatalf("-o jsonc: exit %d %q, want %q", code, stdout, want)
	}
	if strings.Contains(stdout, "\x1b") {
		t.Fatalf("-o jsonc must not contain colour codes: %q", stdout)
	}
	if code, _, _ := run(t, "", "", "version", "-o", "yaml"); code != ExitUsage {
		t.Fatalf("-o yaml should be a usage error, got exit %d", code)
	}
}

func TestPgPasswordSources(t *testing.T) {
	newApp := func(env map[string]string, tty bool) *App {
		var out, errb bytes.Buffer
		a := testApp(&out, &errb, "")
		a.Getenv = func(k string) string { return env[k] }
		a.StdinIsTerminal = func() bool { return tty }
		a.ReadPassword = func() (string, error) { return "typed", nil }
		return a
	}
	cases := []struct {
		name     string
		env      map[string]string
		envVar   string
		explicit bool
		tty      bool
		want     string
		wantErr  string
	}{
		{"default PGPASSWORD set", map[string]string{"PGPASSWORD": "pw"}, "PGPASSWORD", false, false, "pw|from $PGPASSWORD", ""},
		{"default unset, terminal: prompt", nil, "PGPASSWORD", false, true, "typed|entered at the prompt", ""},
		{"default unset, no terminal", nil, "PGPASSWORD", false, false, "", "set PGPASSWORD or pass --pg-pass-env-var"},
		{"explicit variable set", map[string]string{"ADMIN_PW": "x"}, "ADMIN_PW", true, false, "x|from $ADMIN_PW", ""},
		{"explicit variable unset: error, no prompt", nil, "ADMIN_PW", true, true, "", "ADMIN_PW is not set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pw, src, err := newApp(c.env, c.tty).readPassword(c.envVar, c.explicit)
			got := pw + "|" + src
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q %v, want %q", got, err, c.want)
			}
		})
	}
}
