package pg

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Decode stores the result in out, mapping columns to json-tagged fields by name
// (case-insensitive, so column `objectid` fills `json:"objectId"`):
//
//	*[]struct (or *[]map) one element per row
//	*struct (or *map)     the single row (an error unless there is exactly one)
//	*[]scalar             the first column of every row
//	*scalar               the single value of a one-row, one-column result
//
// NULL leaves pointer, slice and map fields nil.
func (r *Rows) Decode(out any) error {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errors.New("Decode needs a non-nil pointer")
	}
	t := v.Elem().Type()
	isRow := func(t reflect.Type) bool { return t.Kind() == reflect.Struct || t.Kind() == reflect.Map }
	var doc any
	switch {
	case t.Kind() == reflect.Slice && isRow(t.Elem()):
		objs := make([]map[string]json.RawMessage, 0, len(r.Rows))
		for _, row := range r.Rows {
			objs = append(objs, r.object(row))
		}
		doc = objs
	case t.Kind() == reflect.Slice:
		col := make([]json.RawMessage, 0, len(r.Rows))
		for _, row := range r.Rows {
			col = append(col, row[0])
		}
		doc = col
	case len(r.Rows) != 1:
		return fmt.Errorf("expected 1 row, got %d", len(r.Rows))
	case isRow(t):
		doc = r.object(r.Rows[0])
	default:
		doc = r.Rows[0][0]
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode result (%s): %w", strings.Join(r.Columns, ", "), err)
	}
	return nil
}

func (r *Rows) object(row []json.RawMessage) map[string]json.RawMessage {
	obj := make(map[string]json.RawMessage, len(row))
	for i, v := range row {
		obj[r.Columns[i]] = v
	}
	return obj
}
