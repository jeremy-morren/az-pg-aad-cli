package pg

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Echo wraps a DB and writes every statement that is executed (Exec, not queries) to w as
// SQL, with parameters inlined as literals, plus BEGIN/COMMIT/ROLLBACK around
// transactions: a transcript of what changed, readable and runnable.
type Echo struct {
	inner DB
	w     io.Writer
}

// NewEcho wraps inner.
func NewEcho(inner DB, w io.Writer) *Echo { return &Echo{inner: inner, w: w} }

func (e *Echo) In(ctx context.Context, database string) (Session, error) {
	s, err := e.inner.In(ctx, database)
	if err != nil {
		return nil, err
	}
	return echoSession{e: e, db: database, s: s}, nil
}

func (e *Echo) Close() { e.inner.Close() }

type echoSession struct {
	e  *Echo
	db string
	s  Session
}

func (s echoSession) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return s.s.Query(ctx, sql, args...)
}

func (s echoSession) Exec(ctx context.Context, sql string, args ...any) error {
	EchoStatement(s.e.w, s.db, sql, args...)
	return s.s.Exec(ctx, sql, args...)
}

func (s echoSession) Tx(ctx context.Context, fn func(Executor) error) error {
	fmt.Fprintf(s.e.w, "-- [%s]\nBEGIN;\n", s.db)
	var fnErr error
	err := s.s.Tx(ctx, func(ex Executor) error {
		fnErr = fn(echoExecutor{e: s.e, ex: ex})
		return fnErr
	})
	if err != nil {
		fmt.Fprintln(s.e.w, "ROLLBACK;")
	} else {
		fmt.Fprintln(s.e.w, "COMMIT;")
	}
	return err
}

type echoExecutor struct {
	e  *Echo
	ex Executor
}

func (x echoExecutor) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	return x.ex.Query(ctx, sql, args...)
}

func (x echoExecutor) Exec(ctx context.Context, sql string, args ...any) error {
	EchoStatement(x.e.w, "", sql, args...)
	return x.ex.Exec(ctx, sql, args...)
}

// EchoStatement writes sql, with its $N parameters replaced by literals, as one statement
// ending in ";". database, if not empty, is noted in a comment line first.
func EchoStatement(w io.Writer, database, sql string, args ...any) {
	if database != "" {
		fmt.Fprintf(w, "-- [%s]\n", database)
	}
	fmt.Fprintf(w, "%s;\n", Inline(sql, args...))
}

// Inline replaces the $1..$N placeholders in sql with SQL literals for args. It is for
// display only; statements are always executed with real parameters.
func Inline(sql string, args ...any) string {
	s := strings.TrimSpace(sql)
	for i := len(args); i >= 1; i-- { // $10 before $1
		s = strings.ReplaceAll(s, "$"+strconv.Itoa(i), literalOf(args[i-1]))
	}
	return s
}

func literalOf(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case string:
		return Literal(t)
	case *string:
		if t == nil {
			return "NULL"
		}
		return Literal(*t)
	case bool:
		return strconv.FormatBool(t)
	case []string:
		q := make([]string, len(t))
		for i, x := range t {
			q[i] = Literal(x)
		}
		return "ARRAY[" + strings.Join(q, ", ") + "]::text[]"
	default:
		return fmt.Sprint(t)
	}
}
