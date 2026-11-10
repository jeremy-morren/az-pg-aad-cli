package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/auth"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
	"github.com/jeremy-morren/az-pg-aad-cli/internal/profile"
)

// aadDatabase is where the pgaadauth functions and security label provider live.
const aadDatabase = "postgres"

// tokenPath resolves --token-file / $PGAADTOKENFILE.
func (a *App) tokenPath() (string, error) {
	p, err := profile.ResolvePath(a.globals.tokenFile, a.Getenv)
	if err != nil {
		return "", notLoggedIn(err)
	}
	return p, nil
}

// session returns a session for database, loading the token file and connecting on first
// use. An --azure token within the grace period of expiry is refreshed and written back.
func (a *App) session(ctx context.Context, database string) (pg.Session, error) {
	if a.db == nil {
		if err := a.open(ctx); err != nil {
			return nil, err
		}
	}
	if database == "" {
		database = a.prof.Database
	}
	return a.db.In(ctx, database)
}

func (a *App) open(ctx context.Context) error {
	path, err := a.tokenPath()
	if err != nil {
		return err
	}
	p, err := profile.Load(path)
	if err != nil {
		return notLoggedIn(err)
	}
	if p.Auth.Method == "azure" && auth.NeedsRefresh(p.Auth.Expires, a.Now()) {
		cred, err := a.NewCredential()
		var tok auth.Token
		if err == nil {
			tok, err = auth.GetToken(ctx, cred, auth.DatabaseScope, a.Now())
		}
		if err != nil {
			return notLoggedIn(fmt.Errorf("token in %s expires at %s and could not be refreshed (%v): run azpgaad login again",
				path, p.Auth.Expires.Format("2006-01-02T15:04:05Z07:00"), err))
		}
		p.Auth.Token, p.Auth.Expires = tok.Value, tok.Expires
		if err := profile.Save(path, p); err != nil {
			return fmt.Errorf("save refreshed token to %s: %w", path, err)
		}
	}
	a.prof = p
	a.db = a.openDB(p)
	return nil
}

func connConfig(p *profile.Profile) pg.ConnConfig {
	cfg := pg.ConnConfig{Host: p.Server, Port: p.Port, User: p.User, SSLMode: p.SSLMode}
	if p.SSLRootCert.Mode == "pem" {
		cfg.RootPEM = p.SSLRootCert.PEM
	}
	switch p.Auth.Method {
	case "azure":
		cfg.Password = p.Auth.Token
	default:
		cfg.Password = p.Auth.Password
	}
	return cfg
}

// existingRoles splits names into roles that exist and the rest (reported as "role:<name>").
// PUBLIC always exists.
func (a *App) existingRoles(ctx context.Context, names []string) (existing, skipped []string, err error) {
	if len(names) == 0 {
		return names, nil, nil
	}
	s, err := a.session(ctx, aadDatabase)
	if err != nil {
		return nil, nil, err
	}
	var found []string
	if err := queryInto(ctx, s, &found, sqlRolesNamed, names); err != nil {
		return nil, nil, err
	}
	for _, n := range names {
		if contains(found, n) || strings.EqualFold(n, "public") {
			existing = append(existing, n)
		} else {
			skipped = append(skipped, "role:"+n)
		}
	}
	return existing, skipped, nil
}

// queryInto runs sql and stores the result in out (see pg.Rows.Decode).
func queryInto(ctx context.Context, ex pg.Executor, out any, sql string, args ...any) error {
	r, err := ex.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	return r.Decode(out)
}

// stmtResult is what mutating commands print.
type stmtResult struct {
	DryRun     bool     `json:"dryRun"`
	Database   string   `json:"database"`
	Statements []string `json:"statements"`
	// Skipped lists inputs left out by --if-exists because they don't exist.
	Skipped []string `json:"skipped,omitempty"`
}

// execStatements runs stmts in one transaction in database (or prints them for --dry-run).
func (a *App) execStatements(ctx context.Context, database string, stmts []string, dryRun bool, skipped ...string) error {
	res := stmtResult{DryRun: dryRun, Database: database, Statements: stmts, Skipped: skipped}
	if res.Statements == nil {
		res.Statements = []string{}
	}
	if dryRun || len(stmts) == 0 {
		return a.print(res)
	}
	s, err := a.session(ctx, database)
	if err != nil {
		return err
	}
	err = s.Tx(ctx, func(ex pg.Executor) error {
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
	return a.print(res)
}

// openDB opens the database described by p, logging every statement with --debug.
func (a *App) openDB(p *profile.Profile) pg.DB {
	db := a.OpenDB(connConfig(p))
	if a.globals.debug {
		db = pg.NewDebug(db, a.Stderr, fmt.Sprintf("%s@%s:%d sslmode=%s", p.User, p.Server, p.Port, p.SSLMode))
	}
	return db
}
