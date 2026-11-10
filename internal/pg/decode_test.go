package pg

import (
	"encoding/json"
	"strings"
	"testing"
)

func rows(cols []string, data ...string) *Rows {
	r := &Rows{Columns: cols}
	for _, d := range data {
		var row []json.RawMessage
		if err := json.Unmarshal([]byte(d), &row); err != nil {
			panic(err)
		}
		r.Rows = append(r.Rows, row)
	}
	return r
}

func TestDecode(t *testing.T) {
	type principal struct {
		Name     string   `json:"name"`
		ObjectID *string  `json:"objectId"`
		IsAdmin  bool     `json:"isAdmin"`
		Roles    []string `json:"roles"`
	}
	r := rows([]string{"name", "objectid", "isadmin", "roles"},
		`["a","11111111-0000-0000-0000-000000000000",true,["x","y"]]`,
		`["b",null,false,null]`)

	var list []principal
	if err := r.Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "a" || *list[0].ObjectID != "11111111-0000-0000-0000-000000000000" ||
		!list[0].IsAdmin || len(list[0].Roles) != 2 || list[1].ObjectID != nil || list[1].Roles != nil {
		t.Fatalf("slice of structs (case-insensitive column match, NULLs): %+v", list)
	}

	var names []string
	if err := r.Decode(&names); err != nil || len(names) != 2 || names[1] != "b" {
		t.Fatalf("first column: %v %v", names, err)
	}

	var one principal
	if err := r.Decode(&one); err == nil {
		t.Fatal("two rows into a struct should fail")
	}
	if err := rows(r.Columns, `["c",null,true,[]]`).Decode(&one); err != nil || one.Name != "c" || !one.IsAdmin {
		t.Fatalf("single row: %+v %v", one, err)
	}

	var b bool
	if err := rows([]string{"x"}, `[true]`).Decode(&b); err != nil || !b {
		t.Fatalf("scalar: %v %v", b, err)
	}
	empty := rows([]string{"name"})
	var none []principal
	if err := empty.Decode(&none); err != nil || none == nil || len(none) != 0 {
		t.Fatalf("empty result should decode to an empty, non-nil slice: %#v %v", none, err)
	}
}

func TestDebugShowsParameters(t *testing.T) {
	var buf strings.Builder
	d := &Debug{w: &buf}
	d.statement("select 1\nwhere x = $1 and y = any($2)", []any{true, []string{"a", "b"}})
	want := "    select 1\n    where x = $1 and y = any($2)\n    $1 = true\n    $2 = [\"a\",\"b\"]\n"
	if buf.String() != want {
		t.Fatalf("got %q", buf.String())
	}
}
