package graph

import (
	"github.com/afterdarksys/sahinit/internal/unit"
	"reflect"
	"testing"
)

func TestShutdownIncludesManualServices(t *testing.T) {
	catalog := map[string]*unit.Service{
		"db":     {Name: "db", Boot: true},
		"api":    {Name: "api", Boot: true, Needs: []string{"db"}},
		"manual": {Name: "manual", After: []string{"api"}},
	}
	waves, err := ShutdownPlan(catalog)
	if err != nil || !reflect.DeepEqual(waves, [][]string{{"manual"}, {"api"}, {"db"}}) {
		t.Fatalf("%v %v", waves, err)
	}
	if catalog["manual"].Boot {
		t.Fatal("mutated catalog")
	}
}
