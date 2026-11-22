// Package graph plans the boot waves of a static catalog.
// needs, after, and wants are the only edges. A cycle is a boot error.
package graph

import (
	"sort"

	"github.com/afterdarksys/sahinit/internal/fail"
	"github.com/afterdarksys/sahinit/internal/unit"
)

// Plan returns boot waves. Names inside a wave are sorted.
// The full catalog is cycle-checked, including services that are not booted.
// A wants edge whose target is absent is ignored. needs and after must resolve.
func Plan(svcs map[string]*unit.Service) ([][]string, error) {
	if len(svcs) == 0 {
		return nil, fail.E("empty")
	}
	full := make(map[string][]string, len(svcs))
	bootDeps := make(map[string][]string, len(svcs))
	for name := range svcs {
		full[name] = nil
	}
	for name, svc := range svcs {
		for _, dep := range svc.Needs {
			if dep == "" {
				return nil, fail.E("edge_empty")
			}
			target, ok := svcs[dep]
			if !ok {
				return nil, fail.E("missing_needs")
			}
			if svc.Boot && !target.Boot {
				return nil, fail.E("boot_needs")
			}
			full[name] = append(full[name], dep)
			if svc.Boot && target.Boot {
				bootDeps[name] = append(bootDeps[name], dep)
			}
		}
		for _, dep := range svc.After {
			if dep == "" {
				return nil, fail.E("edge_empty")
			}
			target, ok := svcs[dep]
			if !ok {
				return nil, fail.E("missing_after")
			}
			full[name] = append(full[name], dep)
			if svc.Boot && target.Boot {
				bootDeps[name] = append(bootDeps[name], dep)
			}
		}
		for _, dep := range svc.Wants {
			if dep == "" {
				return nil, fail.E("edge_empty")
			}
			target, ok := svcs[dep]
			if !ok {
				continue
			}
			full[name] = append(full[name], dep)
			if svc.Boot && target.Boot {
				bootDeps[name] = append(bootDeps[name], dep)
			}
		}
	}
	if err := cycles(full); err != nil {
		return nil, err
	}
	memo := map[string]int{}
	var level func(string) int
	level = func(name string) int {
		if v, ok := memo[name]; ok {
			return v
		}
		maxDep := -1
		for _, dep := range bootDeps[name] {
			if lv := level(dep); lv > maxDep {
				maxDep = lv
			}
		}
		if maxDep < 0 {
			memo[name] = 0
			return 0
		}
		memo[name] = maxDep + 1
		return memo[name]
	}
	var boots []string
	maxLevel := 0
	for name, svc := range svcs {
		if !svc.Boot {
			continue
		}
		boots = append(boots, name)
		if lv := level(name); lv > maxLevel {
			maxLevel = lv
		}
	}
	waves := make([][]string, maxLevel+1)
	for _, name := range boots {
		lv := memo[name]
		waves[lv] = append(waves[lv], name)
	}
	out := make([][]string, 0, len(waves))
	for _, wave := range waves {
		if len(wave) == 0 {
			continue
		}
		sort.Strings(wave)
		out = append(out, wave)
	}
	return out, nil
}

func cycles(deps map[string][]string) error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(deps))
	var visit func(string) error
	visit = func(name string) error {
		switch color[name] {
		case gray:
			return fail.E("cycle")
		case black:
			return nil
		}
		color[name] = gray
		for _, dep := range deps[name] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		color[name] = black
		return nil
	}
	for name := range deps {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}
