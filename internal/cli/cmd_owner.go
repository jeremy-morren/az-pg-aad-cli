package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremy-morren/az-pg-aad-cli/internal/pg"
)

type ownedObject struct {
	Type   string  `json:"type"`
	Schema *string `json:"schema"`
	Name   string  `json:"name"`
	Args   *string `json:"args"`
	Owner  string  `json:"owner"`
}

func (a *App) owners(ctx context.Context, database string) ([]ownedObject, error) {
	s, err := a.session(ctx, database)
	if err != nil {
		return nil, err
	}
	var out []ownedObject
	err = queryInto(ctx, s, &out, sqlOwners)
	return out, err
}

func (a *App) ownerCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "owner", Short: "Object ownership"}
	var database string
	list := &cobra.Command{
		Use:   "list",
		Short: "Owners of the database, its schemas, tables, views, sequences and routines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := a.owners(cmd.Context(), database)
			if err != nil {
				return err
			}
			return a.print(out)
		},
	}
	list.Flags().StringVar(&database, "database", "", "database (required)")
	_ = list.MarkFlagRequired("database")
	cmd.AddCommand(list, a.ownerReassignCommand())
	return cmd
}

// alterStatement returns the ALTER … OWNER TO statement for o.
func alterStatement(o ownedObject, to string) string {
	target := pg.Ident(to)
	schema := ""
	if o.Schema != nil {
		schema = *o.Schema
	}
	args := ""
	if o.Args != nil {
		args = *o.Args
	}
	switch o.Type {
	case "database":
		return fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", pg.Ident(o.Name), target)
	case "schema":
		return fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", pg.Ident(o.Name), target)
	case "table":
		return fmt.Sprintf("ALTER TABLE %s OWNER TO %s", qualified(schema, o.Name), target)
	case "foreign table":
		return fmt.Sprintf("ALTER FOREIGN TABLE %s OWNER TO %s", qualified(schema, o.Name), target)
	case "view":
		return fmt.Sprintf("ALTER VIEW %s OWNER TO %s", qualified(schema, o.Name), target)
	case "materialized view":
		return fmt.Sprintf("ALTER MATERIALIZED VIEW %s OWNER TO %s", qualified(schema, o.Name), target)
	case "sequence":
		return fmt.Sprintf("ALTER SEQUENCE %s OWNER TO %s", qualified(schema, o.Name), target)
	case "aggregate":
		return fmt.Sprintf("ALTER AGGREGATE %s(%s) OWNER TO %s", qualified(schema, o.Name), args, target)
	default: // function, procedure
		return fmt.Sprintf("ALTER ROUTINE %s(%s) OWNER TO %s", qualified(schema, o.Name), args, target)
	}
}

func (a *App) ownerReassignCommand() *cobra.Command {
	var database, to string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "reassign",
		Short: "Make one role own the database and everything in its non-system schemas",
		Long: `Reassigns, in one transaction, the database, its non-system schemas, and their
tables, views, materialized views, sequences, functions, procedures and aggregates to
--to. Objects already owned by --to or by azure* roles are left alone.

Azure administrators aren't superusers: changing an owner requires membership of both the
old and the new owner. Missing memberships are granted to the current user at the start
of the transaction and revoked at the end.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			objs, err := a.owners(ctx, database)
			if err != nil {
				return err
			}
			var todo []ownedObject
			counts := map[string]map[string]int{}
			owners := map[string]bool{to: true}
			for _, o := range objs {
				if o.Owner == to || strings.HasPrefix(o.Owner, "azure") {
					continue
				}
				todo = append(todo, o)
				owners[o.Owner] = true
				key := "(database)"
				if o.Schema != nil {
					key = *o.Schema
				}
				if counts[key] == nil {
					counts[key] = map[string]int{}
				}
				counts[key][o.Type]++
			}
			var stmts []string
			if len(todo) > 0 {
				roleList := make([]string, 0, len(owners))
				for r := range owners {
					roleList = append(roleList, r)
				}
				sort.Strings(roleList)
				s, err := a.session(ctx, database)
				if err != nil {
					return err
				}
				var memberRows []struct {
					Role   string `json:"role"`
					Member bool   `json:"member"`
				}
				if err := queryInto(ctx, s, &memberRows, sqlMembership, roleList); err != nil {
					return err
				}
				member := map[string]bool{}
				for _, m := range memberRows {
					member[m.Role] = m.Member
				}
				var temp []string
				for _, r := range roleList {
					isMember, exists := member[r]
					if !exists {
						return fmt.Errorf("role %q does not exist", r)
					}
					if !isMember && !strings.HasPrefix(r, "azure") {
						temp = append(temp, r)
					}
				}
				for _, r := range temp {
					stmts = append(stmts, fmt.Sprintf("GRANT %s TO CURRENT_USER", pg.Ident(r)))
				}
				for _, o := range todo {
					stmts = append(stmts, alterStatement(o, to))
				}
				for _, r := range temp {
					stmts = append(stmts, fmt.Sprintf("REVOKE %s FROM CURRENT_USER", pg.Ident(r)))
				}
			}
			if !dryRun && len(stmts) > 0 {
				if err := a.runStatements(ctx, database, stmts); err != nil {
					return err
				}
			}
			if stmts == nil {
				stmts = []string{}
			}
			return a.print(struct {
				DryRun     bool                      `json:"dryRun"`
				Database   string                    `json:"database"`
				To         string                    `json:"to"`
				Reassigned map[string]map[string]int `json:"reassigned"`
				Statements []string                  `json:"statements"`
			}{dryRun, database, to, counts, stmts})
		},
	}
	cmd.Flags().StringVar(&database, "database", "", "database (required)")
	cmd.Flags().StringVar(&to, "to", "", "new owner role (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the SQL without running it")
	_ = cmd.MarkFlagRequired("database")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// runStatements runs stmts in one transaction without printing.
func (a *App) runStatements(ctx context.Context, database string, stmts []string) error {
	s, err := a.session(ctx, database)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(ex pg.Executor) error {
		for _, st := range stmts {
			if err := ex.Exec(ctx, st); err != nil {
				return fmt.Errorf("%s: %w", st, err)
			}
		}
		return nil
	})
}
