package unit

import "testing"

func TestExecutionStrict(t *testing.T) {
	base := `{"name":"test","exec":["/bin/true"],"type":"simple","ready":"exec","execution":`
	for _, raw := range []string{
		`{"uid":1}`, `{"gid":1}`, `{"groups":[]}`, `{"uid":null,"gid":1}`,
		`{"uid":-1,"gid":1}`, `{"uid":4294967295,"gid":1}`, `{"uid":1,"gid":1,"groups":[2,2]}`,
		`{"directory":"relative"}`, `{"directory":"/tmp/../etc"}`, `{"directory":null}`,
		`{"environment":["X=1","X=2"]}`, `{"environment":["SAHINIT_READY_FD=9"]}`,
		`{"environment":["1X=x"]}`, `{"environment":["X"]}`, `{"uid":1,"uid":2,"gid":1}`,
		`{"unknown":true}`, `null`,
	} {
		if _, err := Parse([]byte(base+raw+`}`), "test"); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	s, err := Parse([]byte(base+`{"uid":1000,"gid":1001,"groups":[1002],"directory":"/tmp","environment":["PATH=/bin","APP=hello=world"]}}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if *s.Execution.UID != 1000 || *s.Execution.GID != 1001 || len(s.Execution.Env()) != 2 {
		t.Fatalf("bad execution: %+v", s.Execution)
	}
}
