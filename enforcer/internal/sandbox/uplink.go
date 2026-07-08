// Uplink subnet math and index allocation for LinuxSandbox. Kept out of
// backend_linux.go (no build tag) so the logic unit-tests on any OS.
package sandbox

import (
	"errors"
	"fmt"
)

// maxUplinks is the number of /30 subnets in the uplink pool 10.200.0.0/16.
// Pool is hardcoded — parameterize when a deployment needs another.
const maxUplinks = 16384

// uplinkSubnet returns the addresses for uplink index idx, the idx-th /30 of
// 10.200.0.0/16: the host-side veth address and namespace-side address (both
// /30), and the bare host IP used as the namespace default gateway.
func uplinkSubnet(idx int) (hostCIDR, nsCIDR, gateway string) {
	base := idx * 4
	oct3, oct4 := base>>8, base&0xff
	gateway = fmt.Sprintf("10.200.%d.%d", oct3, oct4+1)
	return gateway + "/30", fmt.Sprintf("10.200.%d.%d/30", oct3, oct4+2), gateway
}

// uplinkAllocator hands out uplink subnet indices. Deliberately not safe for
// concurrent use on its own: every call path runs under the api package's
// single AppState lock — no second lock in this package.
type uplinkAllocator struct {
	bySession map[string]int
	used      map[int]bool
}

func newUplinkAllocator() *uplinkAllocator {
	return &uplinkAllocator{bySession: map[string]int{}, used: map[int]bool{}}
}

// alloc reserves the lowest free index for sessionID.
// O(n) lowest-free scan; bitmap if concurrent sessions exceed ~1k.
func (a *uplinkAllocator) alloc(sessionID string) (int, error) {
	for i := 0; i < maxUplinks; i++ {
		if !a.used[i] {
			a.used[i] = true
			a.bySession[sessionID] = i
			return i, nil
		}
	}
	return 0, errors.New("uplink pool exhausted (16384 active sessions)")
}

// free releases sessionID's index. No-op for sessions never allocated.
func (a *uplinkAllocator) free(sessionID string) {
	if idx, ok := a.bySession[sessionID]; ok {
		delete(a.used, idx)
		delete(a.bySession, sessionID)
	}
}
