// Package seccomp mirrors enforcer/src/seccomp.rs: an OCI-compatible
// seccomp profile builder for Warden agent sandboxes.
//
// Applying the profile requires the runsc/gVisor integration and its
// opencontainers/runtime-spec dependency; plain structs keep this package
// free of that dependency.
package seccomp

type Action string

const (
	ActionAllow Action = "SCMP_ACT_ALLOW"
	// ActionErrno returns errno to the calling process rather than killing
	// it. Killing on every probe attempt would make breach detection noisy
	// and prevent the MCP layer from emitting a proper breach event.
	ActionErrno Action = "SCMP_ACT_ERRNO"
)

type SyscallArg struct {
	Index uint32 `json:"index"`
	Value uint64 `json:"value"`
	Op    string `json:"op"`
}

type SyscallRule struct {
	Names    []string     `json:"names"`
	Action   Action       `json:"action"`
	ErrnoRet *int32       `json:"errno_ret,omitempty"`
	Args     []SyscallArg `json:"args,omitempty"`
}

// Profile is an OCI-compatible seccomp profile for Warden agent sandboxes.
// Default action is allow; specific syscalls are denied via Syscalls rules.
type Profile struct {
	DefaultAction Action        `json:"default_action"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

// DefaultProfile returns the enforcer's default seccomp profile.
// Blocks privilege escalation and raw network access.
// Safe to call on any platform; application is Linux-only.
func DefaultProfile() Profile {
	eperm := int32(1)
	return Profile{
		DefaultAction: ActionAllow,
		Syscalls: []SyscallRule{
			// Prevent namespace escape and privilege escalation.
			{
				Names:    []string{"ptrace", "mount", "unshare", "setns"},
				Action:   ActionErrno,
				ErrnoRet: &eperm,
			},
			// Block raw socket creation (SOCK_RAW = 3 at arg index 1).
			// Only the raw type is blocked; TCP/UDP sockets are unaffected.
			{
				Names:    []string{"socket"},
				Action:   ActionErrno,
				ErrnoRet: &eperm,
				Args: []SyscallArg{{
					Index: 1,
					Value: 3, // SOCK_RAW
					Op:    "SCMP_CMP_EQ",
				}},
			},
		},
	}
}

// Denies reports whether syscall appears in any deny rule in this profile.
func (p Profile) Denies(syscall string) bool {
	for _, rule := range p.Syscalls {
		for _, name := range rule.Names {
			if name == syscall {
				return true
			}
		}
	}
	return false
}
