// Package profile reads and writes the token file: a self-contained JSON description of
// how to connect (server, TLS trust, credentials) produced by `azpgaad login`.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnvVar names the environment variable holding the token file path.
const EnvVar = "PGAADTOKENFILE"

// Version is the current token file format version.
const Version = 1

// Profile is the token file contents.
type Profile struct {
	V           int      `json:"v"`
	Server      string   `json:"server"`
	Port        int      `json:"port"`
	Database    string   `json:"database"`
	User        string   `json:"user"`
	SSLMode     string   `json:"sslmode"`
	SSLRootCert RootCert `json:"sslrootcert"`
	Auth        Auth     `json:"auth"`
}

// RootCert says which CAs to trust.
type RootCert struct {
	Mode string `json:"mode"`          // "system" or "pem"
	PEM  string `json:"pem,omitempty"` // when Mode == "pem"
}

// Auth holds the credentials.
type Auth struct {
	Method   string    `json:"method"`             // "azure" or "pg"
	Password string    `json:"password,omitempty"` // method "pg"
	Token    string    `json:"token,omitempty"`    // method "azure"
	Expires  time.Time `json:"expires,omitempty"`  // method "azure"
}

// ErrNoPath means neither --token-file nor PGAADTOKENFILE was given.
var ErrNoPath = errors.New("no token file: pass --token-file or set " + EnvVar)

// ResolvePath returns the token file path: flag, else $PGAADTOKENFILE. A leading ~ is
// expanded here because cmd and PowerShell don't expand it inside variable values.
func ResolvePath(flag string, getenv func(string) string) (string, error) {
	p := flag
	if p == "" {
		p = getenv(EnvVar)
	}
	if p == "" {
		return "", ErrNoPath
	}
	return ExpandHome(p)
}

// ExpandHome expands a leading ~ or ~/ (also ~\ on Windows).
func ExpandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %q: %w", p, err)
	}
	return filepath.Join(home, p[1:]), nil
}

// Load reads and validates a token file.
func Load(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("token file %s does not exist: run azpgaad login", path)
		}
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("token file %s is not valid: %w", path, err)
	}
	if p.V != Version {
		return nil, fmt.Errorf("token file %s has version %d, expected %d: run azpgaad login again", path, p.V, Version)
	}
	return &p, nil
}

// Save writes the token file atomically (temp file in the same directory, then rename),
// creating the directory if needed. Mode 0600 on Unix; on Windows the file inherits the
// directory's ACL.
func Save(path string, p *Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".azpgaad-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	// CreateTemp already uses 0600 on Unix; Chmod is a no-op/unsupported on Windows.
	_ = f.Chmod(0o600)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
