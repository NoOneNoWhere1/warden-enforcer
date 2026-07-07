package seccomp

import (
	"encoding/json"
	"slices"
	"testing"
)

// ── Default profile (ledger: seccomp::*) ─────────────────────────────────────

func TestDefaultProfileDefaultActionIsAllow(t *testing.T) {
	if p := DefaultProfile(); p.DefaultAction != ActionAllow {
		t.Fatalf("default_action = %q, want %q", p.DefaultAction, ActionAllow)
	}
}

func TestDefaultProfileDeniesPtrace(t *testing.T) {
	if !DefaultProfile().Denies("ptrace") {
		t.Fatal("default profile must deny ptrace")
	}
}

func TestDefaultProfileDeniesMount(t *testing.T) {
	if !DefaultProfile().Denies("mount") {
		t.Fatal("default profile must deny mount")
	}
}

func TestDefaultProfileDeniesUnshare(t *testing.T) {
	if !DefaultProfile().Denies("unshare") {
		t.Fatal("default profile must deny unshare")
	}
}

func TestDefaultProfileDeniesSetns(t *testing.T) {
	if !DefaultProfile().Denies("setns") {
		t.Fatal("default profile must deny setns")
	}
}

func TestDefaultProfileHasSocketRawRuleWithArgConstraint(t *testing.T) {
	p := DefaultProfile()
	var socketRule *SyscallRule
	for i := range p.Syscalls {
		if slices.Contains(p.Syscalls[i].Names, "socket") {
			socketRule = &p.Syscalls[i]
			break
		}
	}
	if socketRule == nil {
		t.Fatal("expected a deny rule covering socket()")
	}
	if len(socketRule.Args) == 0 {
		t.Fatal("socket deny rule must include argument constraints (SOCK_RAW = 3)")
	}
	for _, arg := range socketRule.Args {
		if arg.Index == 1 && arg.Value == 3 {
			return
		}
	}
	t.Fatal("socket rule must target arg index 1 (type) == 3 (SOCK_RAW)")
}

func TestAllDenyRulesUseErrnoNotKill(t *testing.T) {
	for _, rule := range DefaultProfile().Syscalls {
		if rule.Action != ActionErrno {
			t.Fatalf("deny rule for %v must use SCMP_ACT_ERRNO so the MCP layer can emit a breach event before the process exits", rule.Names)
		}
	}
}

// ── Serialization ────────────────────────────────────────────────────────────

func TestProfileSerializesToValidJSON(t *testing.T) {
	if _, err := json.Marshal(DefaultProfile()); err != nil {
		t.Fatal(err)
	}
}

func TestSerializedProfileHasNonEmptySyscallsArray(t *testing.T) {
	raw, err := json.Marshal(DefaultProfile())
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	syscalls, ok := v["syscalls"].([]any)
	if !ok {
		t.Fatal("syscalls must be an array")
	}
	if len(syscalls) == 0 {
		t.Fatal("syscalls array must not be empty")
	}
}
