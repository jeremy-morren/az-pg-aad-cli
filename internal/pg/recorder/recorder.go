// Package recorder records every database interaction of a CLI run, and replays a
// recording as a fake database. Recordings are regenerated against the real server with
// `go test ./... -record`; normal test runs replay them offline.
package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

// Entry is one database interaction.
type Entry struct {
	DB     string          `json:"db"`
	Op     string          `json:"op"` // connect | query | exec | begin | commit | rollback
	SQL    string          `json:"sql,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *pg.Error       `json:"error,omitempty"`
	// Failure holds non-server errors (e.g. connection failures), as text.
	Failure string `json:"failure,omitempty"`
}

func errOf(e Entry) error {
	if e.Error != nil {
		return e.Error
	}
	if e.Failure != "" {
		return errors.New(e.Failure)
	}
	return nil
}

func setErr(e *Entry, err error) {
	if err == nil {
		return
	}
	// Only a bare server error is stored structurally; wrapped errors (e.g. "connect to
	// database …: …") are stored as text so replay reproduces the exact message.
	if pe, ok := err.(*pg.Error); ok {
		e.Error = pe
		return
	}
	e.Failure = err.Error()
}

func argsJSON(args []any) json.RawMessage {
	if len(args) == 0 {
		return nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		b, _ = json.Marshal(fmt.Sprint(args))
	}
	return b
}

// Recorder wraps a real DB and logs every interaction.
type Recorder struct {
	inner    pg.DB
	Entries  []Entry
	sessions map[string]pg.Session
}

// New wraps inner.
func New(inner pg.DB) *Recorder {
	return &Recorder{inner: inner, sessions: map[string]pg.Session{}}
}

func (r *Recorder) In(ctx context.Context, database string) (pg.Session, error) {
	if s, ok := r.sessions[database]; ok {
		return s, nil
	}
	s, err := r.inner.In(ctx, database)
	e := Entry{DB: database, Op: "connect"}
	setErr(&e, err)
	r.Entries = append(r.Entries, e)
	if err != nil {
		return nil, err
	}
	rs := &recSession{r: r, db: database, s: s}
	r.sessions[database] = rs
	return rs, nil
}

func (r *Recorder) Close() { r.inner.Close() }

type recSession struct {
	r  *Recorder
	db string
	s  pg.Session
}

func (s *recSession) Query(ctx context.Context, sql string, args ...any) (*pg.Rows, error) {
	return recQuery(s.r, s.db, s.s, ctx, sql, args)
}

func (s *recSession) Exec(ctx context.Context, sql string, args ...any) error {
	return recExec(s.r, s.db, s.s, ctx, sql, args)
}

func (s *recSession) Tx(ctx context.Context, fn func(pg.Executor) error) error {
	s.r.Entries = append(s.r.Entries, Entry{DB: s.db, Op: "begin"})
	var fnErr error
	err := s.s.Tx(ctx, func(ex pg.Executor) error {
		fnErr = fn(recExecutor{r: s.r, db: s.db, ex: ex})
		return fnErr
	})
	if fnErr != nil {
		s.r.Entries = append(s.r.Entries, Entry{DB: s.db, Op: "rollback"})
	} else {
		e := Entry{DB: s.db, Op: "commit"}
		setErr(&e, err)
		s.r.Entries = append(s.r.Entries, e)
	}
	return err
}

type recExecutor struct {
	r  *Recorder
	db string
	ex pg.Executor
}

func (x recExecutor) Query(ctx context.Context, sql string, args ...any) (*pg.Rows, error) {
	return recQuery(x.r, x.db, x.ex, ctx, sql, args)
}

func (x recExecutor) Exec(ctx context.Context, sql string, args ...any) error {
	return recExec(x.r, x.db, x.ex, ctx, sql, args)
}

func recQuery(r *Recorder, db string, ex pg.Executor, ctx context.Context, sql string, args []any) (*pg.Rows, error) {
	res, err := ex.Query(ctx, sql, args...)
	e := Entry{DB: db, Op: "query", SQL: sql, Args: argsJSON(args)}
	if err == nil {
		b, _ := json.Marshal(res)
		e.Result = b
	}
	setErr(&e, err)
	r.Entries = append(r.Entries, e)
	return res, err
}

func recExec(r *Recorder, db string, ex pg.Executor, ctx context.Context, sql string, args []any) error {
	err := ex.Exec(ctx, sql, args...)
	e := Entry{DB: db, Op: "exec", SQL: sql, Args: argsJSON(args)}
	setErr(&e, err)
	r.Entries = append(r.Entries, e)
	return err
}

// compact removes insignificant whitespace but keeps key order, so replayed results are
// byte-identical to what the server returned.
func compact(b json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if json.Compact(&buf, b) != nil {
		return b
	}
	return buf.Bytes()
}

// Replay is a fake DB that serves a recording, failing on any deviation.
type Replay struct {
	entries  []Entry
	pos      int
	sessions map[string]pg.Session // mirrors the per-run session caching of Live/Recorder
	// Mismatch is set to the first deviation from the recording.
	Mismatch error
}

// NewReplay serves entries in order.
func NewReplay(entries []Entry) *Replay {
	return &Replay{entries: entries, sessions: map[string]pg.Session{}}
}

// Remaining reports entries that were recorded but never requested.
func (p *Replay) Remaining() []Entry { return p.entries[p.pos:] }

func (p *Replay) next(want Entry) (Entry, error) {
	if p.Mismatch != nil {
		return Entry{}, p.Mismatch
	}
	if p.pos >= len(p.entries) {
		p.Mismatch = fmt.Errorf("replay: unexpected %s on %q (recording exhausted):\n%s", want.Op, want.DB, want.SQL)
		return Entry{}, p.Mismatch
	}
	got := p.entries[p.pos]
	if got.DB != want.DB || got.Op != want.Op || got.SQL != want.SQL || string(compact(got.Args)) != string(compact(want.Args)) {
		p.Mismatch = fmt.Errorf("replay: entry %d mismatch\nrecorded: %s %q %s %s\nactual:   %s %q %s %s",
			p.pos, got.Op, got.DB, got.SQL, got.Args, want.Op, want.DB, want.SQL, want.Args)
		return Entry{}, p.Mismatch
	}
	p.pos++
	return got, nil
}

func (p *Replay) In(_ context.Context, database string) (pg.Session, error) {
	if s, ok := p.sessions[database]; ok {
		return s, nil
	}
	e, err := p.next(Entry{DB: database, Op: "connect"})
	if err != nil {
		return nil, err
	}
	if err := errOf(e); err != nil {
		return nil, err
	}
	s := &repSession{p: p, db: database}
	p.sessions[database] = s
	return s, nil
}

// Close ends one CLI run: the next run reconnects, as it would against a real server.
func (p *Replay) Close() { p.sessions = map[string]pg.Session{} }

type repSession struct {
	p  *Replay
	db string
}

func (s *repSession) Query(_ context.Context, sql string, args ...any) (*pg.Rows, error) {
	e, err := s.p.next(Entry{DB: s.db, Op: "query", SQL: sql, Args: argsJSON(args)})
	if err != nil {
		return nil, err
	}
	if err := errOf(e); err != nil {
		return nil, err
	}
	var rows pg.Rows
	if err := json.Unmarshal(e.Result, &rows); err != nil {
		return nil, fmt.Errorf("replay: bad recorded result: %w", err)
	}
	return &rows, nil
}

func (s *repSession) Exec(_ context.Context, sql string, args ...any) error {
	e, err := s.p.next(Entry{DB: s.db, Op: "exec", SQL: sql, Args: argsJSON(args)})
	if err != nil {
		return err
	}
	return errOf(e)
}

func (s *repSession) Tx(ctx context.Context, fn func(pg.Executor) error) error {
	if _, err := s.p.next(Entry{DB: s.db, Op: "begin"}); err != nil {
		return err
	}
	if fnErr := fn(s); fnErr != nil {
		if _, err := s.p.next(Entry{DB: s.db, Op: "rollback"}); err != nil {
			return err
		}
		return fnErr
	}
	e, err := s.p.next(Entry{DB: s.db, Op: "commit"})
	if err != nil {
		return err
	}
	return errOf(e)
}
