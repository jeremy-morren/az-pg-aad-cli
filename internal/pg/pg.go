// Package pg is the only place that talks to Postgres.
//
// Queries return ordinary result sets (columns and rows). Each value is held as JSON
// (pgx decodes it, then it's JSON-encoded), which keeps one generic path for live
// results, recordings and replay, and lets results be mapped onto Go structs by column
// name (Rows.Decode) without per-query scanning code.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Rows is a complete result set.
type Rows struct {
	Columns []string            `json:"columns"`
	Rows    [][]json.RawMessage `json:"rows"`
}

// Executor runs statements against one database.
type Executor interface {
	// Query runs sql and returns all rows.
	Query(ctx context.Context, sql string, args ...any) (*Rows, error)
	// Exec runs a statement that returns no rows.
	Exec(ctx context.Context, sql string, args ...any) error
}

// Session is an Executor for one database that can also open a transaction.
type Session interface {
	Executor
	// Tx runs fn in a transaction: committed if fn returns nil, rolled back otherwise.
	Tx(ctx context.Context, fn func(Executor) error) error
}

// DB hands out sessions per database. Roles are cluster-wide, but pgaadauth lives in
// the postgres database and schema-level objects live in each database, so commands
// address databases explicitly.
type DB interface {
	In(ctx context.Context, database string) (Session, error)
	Close()
}

// Error is a Postgres error reduced to the fields we show and record.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

func (e *Error) Error() string {
	s := e.Message + " (SQLSTATE " + e.Code + ")"
	if e.Detail != "" {
		s += "\nDETAIL: " + e.Detail
	}
	if e.Hint != "" {
		s += "\nHINT: " + e.Hint
	}
	return s
}

// AsError converts a pgx error to *Error, or returns nil if err isn't a server error.
func AsError(err error) *Error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return &Error{Code: pe.Code, Message: pe.Message, Detail: pe.Detail, Hint: pe.Hint}
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// normalize turns server errors into *Error so live and replayed errors look identical.
func normalize(err error) error {
	if err == nil {
		return nil
	}
	if e := AsError(err); e != nil {
		return e
	}
	return err
}

// Ident quotes an identifier (role, schema, table, database name).
func Ident(name string) string { return pgx.Identifier{name}.Sanitize() }

// Idents quotes and comma-joins identifiers.
func Idents(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = Ident(n)
	}
	return strings.Join(q, ", ")
}

// Grantee is a role in a GRANT/REVOKE grantee list: PUBLIC (any case) is the keyword
// meaning every role, anything else a quoted role name. (Ident("PUBLIC") would name a
// role called "PUBLIC".)
func Grantee(name string) string {
	if strings.EqualFold(name, "public") {
		return "PUBLIC"
	}
	return Ident(name)
}

// Grantees is Grantee for a comma-joined list.
func Grantees(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = Grantee(n)
	}
	return strings.Join(q, ", ")
}

// Literal quotes a string literal (for the few statements that can't take parameters).
func Literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// ConnConfig is everything needed to open a connection, minus the database name.
type ConnConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	SSLMode  string
	// RootPEM, when non-empty, is the only set of trusted CAs (libpq sslrootcert=<file>).
	// When empty the platform verifier is used (Windows CryptoAPI, macOS Security
	// framework, Linux system bundle).
	RootPEM string
}

// ConnString builds the libpq-style connection string for database. Every setting that
// libpq environment variables could otherwise inject is set explicitly, so PGSSLROOTCERT,
// PGSERVICE etc. in the caller's environment can't change the connection.
func (c ConnConfig) ConnString(database string) string {
	mode := c.SSLMode
	if mode == "require" && c.RootPEM != "" {
		// libpq: require + a root certificate behaves like verify-ca. pgx only does this
		// when given a file path, and we hold the PEM in memory.
		mode = "verify-ca"
	}
	kv := []string{
		"host=" + quoteConn(c.Host),
		fmt.Sprintf("port=%d", c.Port),
		"dbname=" + quoteConn(database),
		"sslmode=" + quoteConn(mode),
		"sslrootcert=''", "sslcert=''", "sslkey=''", "sslpassword=''", "sslnegotiation=''",
		// No "service" key: pgx reads the service file whenever the key is present, even
		// empty. (A PGSERVICE environment variable therefore still applies.)
		"passfile=''", "target_session_attrs=any",
		"application_name=azpgaad",
		"connect_timeout=30",
	}
	return strings.Join(kv, " ")
}

func quoteConn(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// ValidSSLModes are the libpq sslmode values.
var ValidSSLModes = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
