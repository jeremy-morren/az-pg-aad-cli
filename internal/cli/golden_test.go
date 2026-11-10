package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg/recorder"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

// Scenario tests: recorded against a real server, replayed offline.
//
// Each testdata/scenarios/<name>.txt is a list of CLI invocations (one per line, shell-like
// quoting) plus "!sql <database>: <statement>" lines for setup/teardown. Normal runs replay
// testdata/recordings/<name>.json offline and compare against testdata/golden/<name>.txt.
//
// Re-record against the real server (after `azpgaad login`):
//
//	AZPGAAD_RECORD_TOKEN_FILE=~/.azpgaad/test.json go test ./internal/cli -run TestScenarios -record
var record = flag.Bool("record", false, "re-record scenarios against the server in $AZPGAAD_RECORD_TOKEN_FILE")

// update rewrites only the golden output from the existing recordings (offline), for output
// format changes that don't change any SQL.
var update = flag.Bool("update", false, "rewrite golden output files from the existing recordings")

// fixedNow keeps output that depends on the clock stable.
var fixedNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestScenarios(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "scenarios", "*.txt"))
	if len(files) == 0 {
		t.Skip("no scenarios")
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		t.Run(name, func(t *testing.T) { runScenario(t, name, f) })
	}
}

func runScenario(t *testing.T, name, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// ${VAR} in a scenario is a real value (e.g. an object ID) that must not be committed:
	// taken from the environment when recording, replaced by a fixed placeholder on replay
	// (and in the recording, via the scrubber).
	vars := map[string]string{}
	placeholders := map[string]string{}
	src := os.Expand(string(raw), func(name string) string {
		if _, ok := placeholders[name]; !ok {
			placeholders[name] = fmt.Sprintf("aaaaaaaa-0000-0000-0000-%012d", len(placeholders)+1)
			if *record {
				v := os.Getenv(name)
				if v == "" {
					t.Fatalf("scenario uses ${%s}: set it when recording", name)
				}
				vars[name] = v
			}
		}
		if *record {
			return vars[name]
		}
		return placeholders[name]
	})
	recPath := filepath.Join("testdata", "recordings", name+".json")
	goldPath := filepath.Join("testdata", "golden", name+".txt")

	var (
		tokenFile string
		openDB    func(pg.ConnConfig) pg.DB
		finish    func() []recorder.Entry
		replay    *recorder.Replay
	)
	if *record {
		tokenFile, err = profile.ExpandHome(os.Getenv("AZPGAAD_RECORD_TOKEN_FILE"))
		if err != nil || tokenFile == "" {
			t.Fatal("-record needs AZPGAAD_RECORD_TOKEN_FILE (a token file from azpgaad login)")
		}
		var log []recorder.Entry
		var current *recorder.Recorder
		flush := func() {
			if current != nil {
				log = append(log, current.Entries...)
				current = nil
			}
		}
		openDB = func(cfg pg.ConnConfig) pg.DB {
			flush()
			current = recorder.New(pg.NewLive(cfg))
			return current
		}
		finish = func() []recorder.Entry { flush(); return log }
	} else {
		b, err := os.ReadFile(recPath)
		if err != nil {
			t.Fatalf("no recording (run with -record): %v", err)
		}
		var entries []recorder.Entry
		if err := json.Unmarshal(b, &entries); err != nil {
			t.Fatal(err)
		}
		replay = recorder.NewReplay(entries)
		openDB = func(pg.ConnConfig) pg.DB { return replay }
		tokenFile = filepath.Join(t.TempDir(), "token.json")
		fake := &profile.Profile{V: profile.Version, Server: "replay.invalid", Port: 5432, Database: "postgres",
			User: "replay", SSLMode: "verify-full", SSLRootCert: profile.RootCert{Mode: "system"},
			Auth: profile.Auth{Method: "pg", Password: "replay"}}
		if err := profile.Save(tokenFile, fake); err != nil {
			t.Fatal(err)
		}
	}

	var golden bytes.Buffer
	for _, line := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "!sql "); ok {
			db, stmt, _ := strings.Cut(rest, ":")
			err := rawSQL(openDB, tokenFile, strings.TrimSpace(db), strings.TrimSpace(stmt))
			fmt.Fprintf(&golden, "! %s\n", line[1:])
			if err != nil {
				fmt.Fprintf(&golden, "error: %v\n", err)
			}
			golden.WriteString("\n")
			continue
		}
		args, err := shellSplit(line)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		var stdout, stderr bytes.Buffer
		app := testApp(&stdout, &stderr, tokenFile)
		app.OpenDB = openDB
		code := app.Run(args)
		fmt.Fprintf(&golden, "$ azpgaad %s\nexit %d\n", line, code)
		if stdout.Len() > 0 {
			fmt.Fprintf(&golden, "--- stdout\n%s", stdout.String())
		}
		if stderr.Len() > 0 {
			fmt.Fprintf(&golden, "--- stderr\n%s", stderr.String())
		}
		golden.WriteString("\n")
		if replay != nil && replay.Mismatch != nil {
			t.Fatalf("%s\n%v\n(re-record with -record if the SQL changed on purpose)", line, replay.Mismatch)
		}
	}

	if *record {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // keep <> and & readable in recorded SQL
		enc.SetIndent("", "  ")
		_ = enc.Encode(finish())
		b := bytes.TrimRight(buf.Bytes(), "\n")
		scrub := newScrubber(string(raw))
		for name, v := range vars {
			scrub.seen[strings.ToLower(v)] = placeholders[name]
		}
		writeFile(t, recPath, []byte(scrub.apply(string(b))+"\n"))
		writeFile(t, goldPath, []byte(scrub.apply(golden.String())))
		return
	}
	if rest := replay.Remaining(); len(rest) > 0 {
		t.Errorf("recording has %d unused entries, starting with %s %q %s", len(rest), rest[0].Op, rest[0].DB, rest[0].SQL)
	}
	if *update {
		writeFile(t, goldPath, golden.Bytes())
		return
	}
	want, err := os.ReadFile(goldPath)
	if err != nil {
		t.Fatalf("no golden file (run with -record): %v", err)
	}
	if got := golden.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("output differs from %s\n--- got\n%s", goldPath, got)
	}
}

// scrubber replaces identifying values that come back from the server (UPNs/emails,
// object/tenant IDs, the server host name) with stable placeholders before recordings are
// written, because the repository is public. Values written in the scenario itself are
// kept. The same mapping is applied to the recording and the golden output, so replay
// stays consistent.
type scrubber struct {
	keep map[string]bool
	seen map[string]string
	n    map[string]int
}

var (
	reGUID  = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+#-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reHost  = regexp.MustCompile(`[A-Za-z0-9-]+\.postgres\.database\.azure\.com`)
)

func newScrubber(scenario string) *scrubber {
	s := &scrubber{keep: map[string]bool{}, seen: map[string]string{}, n: map[string]int{}}
	for _, re := range []*regexp.Regexp{reGUID, reEmail} {
		for _, m := range re.FindAllString(scenario, -1) {
			s.keep[strings.ToLower(m)] = true
		}
	}
	return s
}

func (s *scrubber) apply(text string) string {
	text = reHost.ReplaceAllString(text, "server.postgres.database.azure.com")
	text = reEmail.ReplaceAllStringFunc(text, func(m string) string { return s.replace("email", m) })
	return reGUID.ReplaceAllStringFunc(text, func(m string) string { return s.replace("guid", m) })
}

func (s *scrubber) replace(kind, m string) string {
	key := strings.ToLower(m)
	if s.keep[key] {
		return m
	}
	if r, ok := s.seen[key]; ok {
		return r
	}
	s.n[kind]++
	r := fmt.Sprintf("user%d@example.com", s.n[kind])
	if kind == "guid" {
		r = fmt.Sprintf("ffffffff-0000-0000-0000-%012d", s.n[kind])
	}
	s.seen[key] = r
	return r
}

// rawSQL runs a setup/teardown statement through the same (recorded or replayed) DB.
func rawSQL(openDB func(pg.ConnConfig) pg.DB, tokenFile, database, stmt string) error {
	p, err := profile.Load(tokenFile)
	if err != nil {
		return err
	}
	db := openDB(connConfig(p))
	defer db.Close()
	s, err := db.In(context.Background(), database)
	if err != nil {
		return err
	}
	return s.Exec(context.Background(), stmt)
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// testApp is an App with no terminal, a fixed clock and the given token file.
func testApp(stdout, stderr *bytes.Buffer, tokenFile string) *App {
	a := New("test")
	a.Stdin = strings.NewReader("")
	a.Stdout, a.Stderr = stdout, stderr
	a.Getenv = func(k string) string {
		if k == profile.EnvVar {
			return tokenFile
		}
		return ""
	}
	a.Now = func() time.Time { return fixedNow }
	a.StdinIsTerminal = func() bool { return false }
	a.StdoutIsTerminal = func() bool { return false }
	a.Commit = "test"
	if *record {
		a.Now = time.Now
	}
	return a
}

// shellSplit splits a scenario line like a POSIX shell would for simple cases:
// whitespace-separated words, '…' literal, "…" with \" and \\ escapes.
func shellSplit(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("unterminated '")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated \"")
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		args = append(args, cur.String())
	}
	return args, nil
}
