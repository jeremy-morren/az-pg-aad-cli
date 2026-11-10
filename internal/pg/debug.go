package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Debug wraps a DB and logs every statement, with its parameter values, to w (stderr in
// the CLI). Credentials are never logged: they aren't statement parameters.
type Debug struct {
	inner    DB
	w        io.Writer
	describe string // connection description for "connect" lines
	sessions map[string]Session
}

// NewDebug wraps inner. describe is shown on connect (e.g. "user@host:5432").
func NewDebug(inner DB, w io.Writer, describe string) *Debug {
	return &Debug{inner: inner, w: w, describe: describe, sessions: map[string]Session{}}
}

func (d *Debug) logf(database, format string, args ...any) {
	fmt.Fprintf(d.w, "azpgaad: debug: [%s] %s\n", database, fmt.Sprintf(format, args...))
}

// statement prints sql (indented) and its parameters as $1 = <json>, ...
func (d *Debug) statement(sql string, args []any) {
	for _, line := range strings.Split(strings.TrimSpace(sql), "\n") {
		fmt.Fprintf(d.w, "    %s\n", line)
	}
	for i, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			b = []byte(fmt.Sprintf("%v", a))
		}
		fmt.Fprintf(d.w, "    $%d = %s\n", i+1, b)
	}
}

func (d *Debug) In(ctx context.Context, database string) (Session, error) {
	if s, ok := d.sessions[database]; ok {
		return s, nil
	}
	start := time.Now()
	s, err := d.inner.In(ctx, database)
	if err != nil {
		d.logf(database, "connect %s failed (%s): %v", d.describe, since(start), err)
		return nil, err
	}
	d.logf(database, "connect %s (%s)", d.describe, since(start))
	ds := &debugSession{d: d, db: database, s: s}
	d.sessions[database] = ds
	return ds, nil
}

func (d *Debug) Close() { d.inner.Close() }

type debugSession struct {
	d  *Debug
	db string
	s  Session
}

func (s *debugSession) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return debugQuery(s.d, s.db, s.s, ctx, sql, args)
}

func (s *debugSession) Exec(ctx context.Context, sql string, args ...any) error {
	return debugExec(s.d, s.db, s.s, ctx, sql, args)
}

func (s *debugSession) Tx(ctx context.Context, fn func(Executor) error) error {
	s.d.logf(s.db, "begin")
	var fnErr error
	err := s.s.Tx(ctx, func(ex Executor) error {
		fnErr = fn(debugExecutor{d: s.d, db: s.db, ex: ex})
		return fnErr
	})
	switch {
	case fnErr != nil:
		s.d.logf(s.db, "rollback")
	case err != nil:
		s.d.logf(s.db, "commit failed: %v", err)
	default:
		s.d.logf(s.db, "commit")
	}
	return err
}

type debugExecutor struct {
	d  *Debug
	db string
	ex Executor
}

func (x debugExecutor) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return debugQuery(x.d, x.db, x.ex, ctx, sql, args)
}

func (x debugExecutor) Exec(ctx context.Context, sql string, args ...any) error {
	return debugExec(x.d, x.db, x.ex, ctx, sql, args)
}

func debugQuery(d *Debug, db string, ex Executor, ctx context.Context, sql string, args []any) (*Rows, error) {
	start := time.Now()
	rows, err := ex.Query(ctx, sql, args...)
	if err != nil {
		d.logf(db, "query failed (%s): %v", since(start), err)
	} else {
		d.logf(db, "query (%d rows, %s)", len(rows.Rows), since(start))
	}
	d.statement(sql, args)
	return rows, err
}

func debugExec(d *Debug, db string, ex Executor, ctx context.Context, sql string, args []any) error {
	start := time.Now()
	err := ex.Exec(ctx, sql, args...)
	if err != nil {
		d.logf(db, "exec failed (%s): %v", since(start), err)
	} else {
		d.logf(db, "exec (%s)", since(start))
	}
	d.statement(sql, args)
	return err
}

func since(t time.Time) string { return time.Since(t).Round(time.Millisecond).String() }
