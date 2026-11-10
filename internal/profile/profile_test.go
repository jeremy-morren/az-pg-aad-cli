package profile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestResolvePath(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if p, err := ResolvePath("flag.json", env("env.json")); err != nil || p != "flag.json" {
		t.Fatalf("flag should win: %q %v", p, err)
	}
	if p, err := ResolvePath("", env("env.json")); err != nil || p != "env.json" {
		t.Fatalf("env: %q %v", p, err)
	}
	if _, err := ResolvePath("", env("")); !errors.Is(err, ErrNoPath) {
		t.Fatalf("want ErrNoPath, got %v", err)
	}
	home, _ := os.UserHomeDir()
	for _, in := range []string{"~/a/t.json", `~\a\t.json`} {
		p, err := ResolvePath("", env(in))
		if err != nil || p != filepath.Join(home, "a", "t.json") && p != filepath.Join(home, `\a\t.json`) {
			t.Fatalf("%s -> %q %v", in, p, err)
		}
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "token.json")
	in := &Profile{V: Version, Server: "s", Port: 5432, Database: "postgres", User: "u", SSLMode: "verify-full",
		SSLRootCert: RootCert{Mode: "pem", PEM: "-----BEGIN CERTIFICATE-----\n…"},
		Auth:        Auth{Method: "azure", Token: "t", Expires: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Auth != in.Auth || out.SSLRootCert != in.SSLRootCert || out.Server != "s" {
		t.Fatalf("round trip: %+v", out)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	// overwrite in place, no temp files left behind
	in.Auth.Token = "t2"
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file")
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"v":99}`), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("wrong version accepted")
	}
}
