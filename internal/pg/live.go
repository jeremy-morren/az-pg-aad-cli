package pg

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Live is a DB backed by real connections, one per database, opened on first use.
type Live struct {
	cfg   ConnConfig
	conns map[string]*pgx.Conn
}

// NewLive returns a DB that connects lazily using cfg.
func NewLive(cfg ConnConfig) *Live {
	return &Live{cfg: cfg, conns: map[string]*pgx.Conn{}}
}

// ParseConfig builds the pgx config for database, including the TLS trust settings.
func (l *Live) ParseConfig(database string) (*pgx.ConnConfig, error) {
	cc, err := pgx.ParseConfig(l.cfg.ConnString(database))
	if err != nil {
		return nil, err
	}
	cc.User = l.cfg.User
	cc.Password = l.cfg.Password // fallbacks (allow/prefer) share the main config's credentials
	if l.cfg.RootPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(l.cfg.RootPEM)) {
			return nil, errors.New("sslrootcert: no certificates found in PEM data")
		}
		// pgx's verify-ca callback reads RootCAs from this same *tls.Config at handshake
		// time, so setting it here covers verify-ca, verify-full and require-as-verify-ca.
		if cc.TLSConfig != nil {
			cc.TLSConfig.RootCAs = pool
		}
		for _, fb := range cc.Fallbacks {
			if fb.TLSConfig != nil {
				fb.TLSConfig.RootCAs = pool
			}
		}
	}
	// No RootPEM: RootCAs stays nil, so Go uses the platform verifier (on Windows the
	// CryptoAPI chain engine Schannel uses, including AutoRoot). Never replace it with a
	// loaded pool: that would switch to Go's own verifier and lose AutoRoot.
	return cc, nil
}

// In returns a session for database, connecting if needed.
func (l *Live) In(ctx context.Context, database string) (Session, error) {
	if c, ok := l.conns[database]; ok {
		return liveSession{c}, nil
	}
	cc, err := l.ParseConfig(database)
	if err != nil {
		return nil, err
	}
	c, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		if e := AsError(err); e != nil {
			return nil, fmt.Errorf("connect to database %q: %w", database, e)
		}
		var unknownCA x509.UnknownAuthorityError
		if errors.As(err, &unknownCA) || strings.Contains(err.Error(), "certificate signed by unknown authority") {
			hint := "the server's certificate isn't trusted by this machine's trust store: install the ca-certificates package (or the OS equivalent), or log in again with --sslrootcert <pem-file>"
			if l.cfg.RootPEM != "" {
				hint = "the server's certificate isn't signed by a CA in the --sslrootcert file given at login"
			}
			return nil, fmt.Errorf("connect to database %q: %w\nhint: %s", database, err, hint)
		}
		return nil, fmt.Errorf("connect to database %q: %w", database, err)
	}
	l.conns[database] = c
	return liveSession{c}, nil
}

// Close closes every open connection.
func (l *Live) Close() {
	for _, c := range l.conns {
		_ = c.Close(context.Background())
	}
}

type liveSession struct{ c *pgx.Conn }

func (s liveSession) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return query(ctx, s.c, sql, args...)
}

func (s liveSession) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := s.c.Exec(ctx, sql, args...)
	return normalize(err)
}

func (s liveSession) Tx(ctx context.Context, fn func(Executor) error) error {
	tx, err := s.c.Begin(ctx)
	if err != nil {
		return normalize(err)
	}
	if err := fn(liveTx{tx}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return normalize(tx.Commit(ctx))
}

type liveTx struct{ tx pgx.Tx }

func (t liveTx) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return query(ctx, t.tx, sql, args...)
}

func (t liveTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return normalize(err)
}

type rowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// query reads the whole result set. pgx decodes each value to its Go type (text -> string,
// int4 -> int32, bool, text[] -> []any, NULL -> nil, ...), which is then JSON-encoded.
func query(ctx context.Context, q rowsQuerier, sql string, args ...any) (*Rows, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, normalize(err)
	}
	defer rows.Close()
	out := &Rows{Columns: []string{}, Rows: [][]json.RawMessage{}}
	for _, fd := range rows.FieldDescriptions() {
		out.Columns = append(out.Columns, fd.Name)
	}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, normalize(err)
		}
		row := make([]json.RawMessage, len(vals))
		for i, v := range vals {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("encode column %s: %w", out.Columns[i], err)
			}
			row[i] = b
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, normalize(err)
	}
	return out, nil
}
