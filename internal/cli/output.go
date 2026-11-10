package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

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
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		return writeTSV(a.Stdout, v)
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

// writeTSV follows az -o tsv: one line per array element, object fields in sorted key
// order, nested objects and arrays omitted (select them with --query), null as empty.
func writeTSV(w io.Writer, v any) error {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		for _, el := range t {
			if _, err := fmt.Fprintln(w, tsvRow(el)); err != nil {
				return err
			}
		}
		return nil
	default:
		_, err := fmt.Fprintln(w, tsvRow(t))
		return err
	}
}

func tsvRow(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var cells []string
		for _, k := range keys {
			if c, ok := tsvScalar(t[k]); ok {
				cells = append(cells, c)
			}
		}
		return strings.Join(cells, "\t")
	case []any:
		var cells []string
		for _, el := range t {
			if c, ok := tsvScalar(el); ok {
				cells = append(cells, c)
			}
		}
		return strings.Join(cells, "\t")
	default:
		c, _ := tsvScalar(t)
		return c
	}
}

func tsvScalar(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false // nested object or array
	}
}
