// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"errors"
	"reflect"
	"testing"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

func svc(boot bool, needs, after, wants []string) *unit.Service {
	return &unit.Service{Boot: boot, Needs: needs, After: after, Wants: wants}
}

func TestPlanEmpty(t *testing.T) {
	waves, err := Plan(nil)
	if waves != nil || !errors.Is(err, fail.E("empty")) {
		t.Fatalf("%v %v", waves, err)
	}
	waves, err = Plan(map[string]*unit.Service{})
	if waves != nil || !errors.Is(err, fail.E("empty")) {
		t.Fatalf("%v %v", waves, err)
	}
}

func TestPlanZeroBoot(t *testing.T) {
	waves, err := Plan(map[string]*unit.Service{
		"job": svc(false, nil, nil, nil),
	})
	if err != nil || waves == nil || len(waves) != 0 {
		t.Fatalf("%#v %v", waves, err)
	}
}

func TestPlanWaves(t *testing.T) {
	waves, err := Plan(map[string]*unit.Service{
		"b": svc(true, nil, nil, nil),
		"a": svc(true, nil, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a", "b"}}) {
		t.Fatalf("%#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"a": svc(true, nil, nil, nil),
		"b": svc(true, []string{"a"}, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}, {"b"}}) {
		t.Fatalf("%#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"helper": svc(true, nil, nil, nil),
		"agent":  svc(true, nil, nil, []string{"helper"}),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"helper"}, {"agent"}}) {
		t.Fatalf("%#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"a": svc(true, nil, []string{"b"}, nil),
		"b": svc(false, nil, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}}) {
		t.Fatalf("%#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"a": svc(true, nil, nil, []string{"gone"}),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}}) {
		t.Fatalf("%#v %v", waves, err)
	}
}

func TestPlanErrors(t *testing.T) {
	cases := []struct {
		svcs  map[string]*unit.Service
		token string
	}{
		{map[string]*unit.Service{"a": svc(true, []string{"a"}, nil, nil)}, "cycle"},
		{map[string]*unit.Service{
			"a": svc(false, []string{"b"}, nil, nil),
			"b": svc(false, []string{"a"}, nil, nil),
		}, "cycle"},
		{map[string]*unit.Service{"a": svc(true, []string{"gone"}, nil, nil)}, "missing_needs"},
		{map[string]*unit.Service{"a": svc(true, nil, []string{"gone"}, nil)}, "missing_after"},
		{map[string]*unit.Service{
			"a": svc(true, []string{"b"}, nil, nil),
			"b": svc(false, nil, nil, nil),
		}, "boot_needs"},
		{map[string]*unit.Service{"a": svc(true, []string{""}, nil, nil)}, "edge_empty"},
		{map[string]*unit.Service{"a": svc(true, nil, []string{""}, nil)}, "edge_empty"},
		{map[string]*unit.Service{"a": svc(true, nil, nil, []string{""})}, "edge_empty"},
		{map[string]*unit.Service{"a": svc(true, nil, []string{"a"}, nil)}, "cycle"},
		{map[string]*unit.Service{"a": svc(true, nil, nil, []string{"a"})}, "cycle"},
		{map[string]*unit.Service{
			"a": svc(true, nil, nil, []string{"b"}),
			"b": svc(true, nil, nil, []string{"a"}),
		}, "cycle"},
		{map[string]*unit.Service{
			"ok": svc(true, nil, nil, nil),
			"a":  svc(false, []string{"b"}, nil, nil),
			"b":  svc(false, []string{"a"}, nil, nil),
		}, "cycle"},
	}
	for _, tc := range cases {
		_, err := Plan(tc.svcs)
		if !errors.Is(err, fail.E(tc.token)) {
			t.Fatalf("%s: got %v", tc.token, err)
		}
	}
}

func TestPlanShapes(t *testing.T) {
	waves, err := Plan(map[string]*unit.Service{
		"a": svc(true, nil, nil, nil),
		"b": svc(true, []string{"a"}, nil, nil),
		"c": svc(true, []string{"a"}, nil, nil),
		"d": svc(true, []string{"b", "c"}, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}, {"b", "c"}, {"d"}}) {
		t.Fatalf("diamond %#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"a": svc(true, nil, nil, nil),
		"b": svc(true, []string{"a"}, nil, nil),
		"c": svc(true, []string{"b"}, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}, {"b"}, {"c"}}) {
		t.Fatalf("chain %#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"agent": svc(true, nil, nil, []string{"job"}),
		"job":   svc(false, nil, nil, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"agent"}}) {
		t.Fatalf("wants %#v %v", waves, err)
	}

	waves, err = Plan(map[string]*unit.Service{
		"a": svc(true, nil, nil, nil),
		"b": svc(true, nil, []string{"a"}, nil),
	})
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"a"}, {"b"}}) {
		t.Fatalf("after %#v %v", waves, err)
	}
}
