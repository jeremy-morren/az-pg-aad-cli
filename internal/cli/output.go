package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jmespath/go-jmespath"
)

// print writes v in the selected format, after applying --query.
func (a *App) print(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return a.printJSON(b)
}

// printJSON is print for an already-encoded JSON value.
func (a *App) printJSON(b []byte) error {
	if q := a.globals.query; q != "" {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		res, err := jmespath.Search(q, v)
		if err != nil {
			return usageErrorf("--query %q: %v", q, err)
		}
		if b, err = json.Marshal(res); err != nil {
			return err
		}
	}
	if a.globals.output == "tsv" {
		return writeTSV(a.Stdout, b)
	}
	// Without --query, b is printed as produced, keeping struct/server field order.
	return writeJSON(a.Stdout, b, a.globals.output == "jsonc")
}

// writeJSON prints b as standard JSON exactly as encoding/json produced it (including its
// HTML escaping of <, > and &): indented by two spaces for -o json, or compact on a single
// line for -o jsonc (handy for passing into another command's list flag). Key order is
// preserved (az sorts keys; here they follow the tool's own field order).
func writeJSON(w io.Writer, b []byte, compact bool) error {
	var buf bytes.Buffer
	var err error
	if compact {
		err = json.Compact(&buf, b)
	} else {
		err = json.Indent(&buf, b, "", "  ")
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, buf.String())
	return err
}

// writeTSV prints b (a JSON value) as text:
//   - an object as a property list, one "key: value" line per field in the tool's field
//     order (sorted with --query), values aligned in one column, nested values as compact
//     JSON - like PowerShell's Format-List;
//   - an array of objects as a table: a header line of field names, then one
//     tab-separated line per object (see tsvTable);
//   - any other array as one line per element (an array element's scalars tab-separated);
//   - a scalar as its bare value (a string unquoted); null as nothing.
func writeTSV(w io.Writer, b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	var lines []string
	switch b[0] {
	case 'n':
		return nil
	case '{':
		keys, vals, err := objectFields(b)
		if err != nil {
			return err
		}
		width := 0
		for _, k := range keys {
			width = max(width, len(k)+1)
		}
		for i, k := range keys {
			v, ok := tsvScalar(vals[i])
			if !ok {
				var c bytes.Buffer
				if err := json.Compact(&c, vals[i]); err != nil {
					return err
				}
				v = c.String()
			}
			lines = append(lines, strings.TrimRight(fmt.Sprintf("%-*s %s", width, k+":", v), " "))
		}
	case '[':
		var els []json.RawMessage
		if err := json.Unmarshal(b, &els); err != nil {
			return err
		}
		if rows, ok, err := tsvTable(els); err != nil {
			return err
		} else if ok {
			lines = rows
			break
		}
		for _, el := range els {
			row, err := tsvRow(el)
			if err != nil {
				return err
			}
			lines = append(lines, row)
		}
	default:
		v, _ := tsvScalar(b)
		lines = append(lines, v)
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// tsvTable renders a non-empty array of objects as a header line of field names and one
// tab-separated line per object. The columns are the fields in order of first appearance,
// leaving out any field that holds an object or array in some element (so every row has
// the same columns; select nested values with --query). ok is false if any element isn't
// an object.
func tsvTable(els []json.RawMessage) (lines []string, ok bool, err error) {
	if len(els) == 0 {
		return nil, false, nil
	}
	type object map[string]json.RawMessage
	objs := make([]object, len(els))
	var cols []string
	seen, nested := map[string]bool{}, map[string]bool{}
	for i, el := range els {
		if el = bytes.TrimSpace(el); len(el) == 0 || el[0] != '{' {
			return nil, false, nil
		}
		keys, vals, err := objectFields(el)
		if err != nil {
			return nil, false, err
		}
		objs[i] = object{}
		for j, k := range keys {
			objs[i][k] = vals[j]
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
			if _, scalar := tsvScalar(vals[j]); !scalar {
				nested[k] = true
			}
		}
	}
	var header []string
	for _, k := range cols {
		if !nested[k] {
			header = append(header, k)
		}
	}
	if len(header) == 0 {
		return nil, true, nil
	}
	lines = append(lines, strings.Join(header, "\t"))
	for _, o := range objs {
		cells := make([]string, len(header))
		for i, k := range header {
			cells[i], _ = tsvScalar(o[k])
		}
		lines = append(lines, strings.Join(cells, "\t"))
	}
	return lines, true, nil
}

// tsvRow is one array element as a line: its scalar values (an object's in field order)
// joined by tabs.
func tsvRow(b json.RawMessage) (string, error) {
	var vals []json.RawMessage
	switch b[0] {
	case '{':
		var err error
		if _, vals, err = objectFields(b); err != nil {
			return "", err
		}
	case '[':
		if err := json.Unmarshal(b, &vals); err != nil {
			return "", err
		}
	default:
		v, _ := tsvScalar(b)
		return v, nil
	}
	var cells []string
	for _, v := range vals {
		if c, ok := tsvScalar(v); ok {
			cells = append(cells, c)
		}
	}
	return strings.Join(cells, "\t"), nil
}

// objectFields decodes a JSON object into its keys, in document order, and raw values.
func objectFields(b []byte) (keys []string, vals []json.RawMessage, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil { // {
		return nil, nil, err
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		keys, vals = append(keys, t.(string)), append(vals, v)
	}
	return keys, vals, nil
}

// tsvScalar is a scalar JSON value as text (null as empty, strings unquoted, numbers and
// booleans as written); ok is false for an object or array.
func tsvScalar(b json.RawMessage) (string, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return "", true
	}
	switch b[0] {
	case '{', '[':
		return "", false
	case 'n':
		return "", true
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return string(b), true
		}
		return s, true
	default:
		return string(b), true
	}
}

// formatTime shows t like a .NET DateTimeOffset: local date and time, then the UTC offset
// (2030-01-02 14:04:05 +11:00).
func formatTime(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 -07:00") }

// shellQuote quotes s for a POSIX shell when it contains anything beyond letters, digits
// and _ . - (for commands suggested in messages).
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
