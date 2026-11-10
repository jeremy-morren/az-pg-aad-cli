package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// listFlag is a singular/plural flag pair: --name (one raw value, never parsed) and
// --names (a JSON array of strings, or @file / @- to read that JSON from a file / stdin).
type listFlag struct {
	singular, plural string
	one              string
	many             string
}

func (a *App) addList(cmd *cobra.Command, singular, plural, what string, required bool) *listFlag {
	l := &listFlag{singular: singular, plural: plural}
	cmd.Flags().StringVar(&l.one, singular, "", "one "+what+" (taken literally)")
	cmd.Flags().StringVar(&l.many, plural, "", what+"s as a JSON array of strings, or @file / @- to read the array from a file / stdin")
	cmd.MarkFlagsMutuallyExclusive(singular, plural)
	if required {
		cmd.MarkFlagsOneRequired(singular, plural)
	}
	return l
}

// values returns the list, and whether either flag was given.
func (a *App) listValues(cmd *cobra.Command, l *listFlag) ([]string, bool, error) {
	if cmd.Flags().Changed(l.singular) {
		return []string{l.one}, true, nil
	}
	if !cmd.Flags().Changed(l.plural) {
		return nil, false, nil
	}
	raw, err := a.readArg(l.many)
	if err != nil {
		return nil, true, usageErrorf("--%s: %v", l.plural, err)
	}
	vals, err := parseStringArray(raw)
	if err != nil {
		return nil, true, usageErrorf("--%s: %v", l.plural, err)
	}
	return vals, true, nil
}

// readArg resolves @file and @- (stdin) references; other values are returned as-is.
func (a *App) readArg(v string) ([]byte, error) {
	switch {
	case v == "@-":
		return io.ReadAll(a.stdin)
	case strings.HasPrefix(v, "@"):
		return os.ReadFile(v[1:])
	default:
		return []byte(v), nil
	}
}

func parseStringArray(b []byte) ([]string, error) {
	var vals []string
	if err := json.Unmarshal(b, &vals); err != nil {
		return nil, fmt.Errorf("expected a JSON array of strings, e.g. [\"a\",\"b\"]: %v", err)
	}
	if vals == nil {
		return nil, fmt.Errorf("expected a JSON array of strings, got null")
	}
	return vals, nil
}

// dedupe keeps the first occurrence of each value, preserving order.
func dedupe(vals []string) []string {
	seen := map[string]bool{}
	out := vals[:0:0]
	for _, v := range vals {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
