package configs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Diff lists the changes that turn a into b, in deterministic (key-sorted) order.
// Arrays are compared index by index, so a trailing insert shows as one "add".
func Diff(a, b api.ConfigSpec) ([]api.SpecChange, error) {
	var ga, gb any
	if err := toGeneric(a, &ga); err != nil {
		return nil, err
	}
	if err := toGeneric(b, &gb); err != nil {
		return nil, err
	}
	out := []api.SpecChange{}
	diffValue("", ga, gb, &out)
	return out, nil
}

func toGeneric(v any, dst *any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(dst)
}

func diffValue(path string, a, b any, out *[]api.SpecChange) {
	switch av := a.(type) {
	case map[string]any:
		if bv, ok := b.(map[string]any); ok {
			keys := make([]string, 0, len(av)+len(bv))
			for k := range av {
				keys = append(keys, k)
			}
			for k := range bv {
				if _, dup := av[k]; !dup {
					keys = append(keys, k)
				}
			}
			slices.Sort(keys)
			for _, k := range keys {
				p := k
				if path != "" {
					p = path + "." + k
				}
				x, inA := av[k]
				y, inB := bv[k]
				switch {
				case !inA:
					*out = append(*out, api.SpecChange{Path: p, Op: "add", New: y})
				case !inB:
					*out = append(*out, api.SpecChange{Path: p, Op: "remove", Old: x})
				default:
					diffValue(p, x, y, out)
				}
			}
			return
		}
	case []any:
		if bv, ok := b.([]any); ok {
			for i := range max(len(av), len(bv)) {
				p := fmt.Sprintf("%s[%d]", path, i)
				switch {
				case i >= len(av):
					*out = append(*out, api.SpecChange{Path: p, Op: "add", New: bv[i]})
				case i >= len(bv):
					*out = append(*out, api.SpecChange{Path: p, Op: "remove", Old: av[i]})
				default:
					diffValue(p, av[i], bv[i], out)
				}
			}
			return
		}
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, api.SpecChange{Path: path, Op: "replace", Old: a, New: b})
	}
}
