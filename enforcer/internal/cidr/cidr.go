// Package cidr mirrors enforcer/src/cidr.rs: parse a CIDR string, test
// containment, and re-serialize. Re-serialization output feeds nft daddr
// tokens, so String() must match Rust Display byte-for-byte (pinned by
// testdata/reserialization.json, captured from the Rust implementation).
package cidr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Cidr struct {
	addr      netip.Addr
	prefixLen uint8
}

// Parse parses a CIDR string such as "10.0.0.0/24" or "fd00::/48".
// It returns an error if the string is malformed or the prefix length
// exceeds the address family maximum (32 for IPv4, 128 for IPv6).
func Parse(s string) (Cidr, error) {
	addrStr, prefixStr, found := strings.Cut(s, "/")
	if !found {
		return Cidr{}, fmt.Errorf("missing '/' in CIDR: %q", s)
	}
	if addrStr == "" {
		return Cidr{}, fmt.Errorf("missing address in CIDR: %q", s)
	}
	// PARITY: Rust's IpAddr::parse rejects zone IDs (fe80::1%eth0);
	// netip.ParseAddr accepts them, so reject explicitly.
	if strings.Contains(addrStr, "%") {
		return Cidr{}, fmt.Errorf("invalid address %q: zone ID not allowed", addrStr)
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return Cidr{}, fmt.Errorf("invalid address %q: %v", addrStr, err)
	}

	// PARITY: Rust parses the prefix as u8, which permits one leading '+'
	// ("10.0.0.0/+24" is accepted); strconv.ParseUint rejects signs.
	prefix64, err := strconv.ParseUint(strings.TrimPrefix(prefixStr, "+"), 10, 8)
	if err != nil {
		return Cidr{}, fmt.Errorf("invalid prefix length %q: %v", prefixStr, err)
	}
	prefixLen := uint8(prefix64)

	maxPrefix := uint8(128)
	if addr.Is4() {
		maxPrefix = 32
	}
	if prefixLen > maxPrefix {
		return Cidr{}, fmt.Errorf("prefix length %d exceeds maximum %d", prefixLen, maxPrefix)
	}

	return Cidr{addr: addr, prefixLen: prefixLen}, nil
}

// Contains returns true if ip falls within this CIDR block.
// Cross-family comparisons (IPv6 address against an IPv4 block, including
// 4-in-6 mapped forms) are false, mirroring Rust's match on (V4, V6).
func (c Cidr) Contains(ip netip.Addr) bool {
	if c.addr.Is4() != ip.Is4() {
		return false
	}
	if c.addr.Is4() {
		a, b := c.addr.As4(), ip.As4()
		return maskedEqual(a[:], b[:], c.prefixLen)
	}
	a, b := c.addr.As16(), ip.As16()
	return maskedEqual(a[:], b[:], c.prefixLen)
}

// maskedEqual compares the leading prefixLen bits of a and b. A zero prefix
// matches everything, mirroring Rust's checked_shl(...).unwrap_or(0) mask.
func maskedEqual(a, b []byte, prefixLen uint8) bool {
	full := int(prefixLen / 8)
	for i := 0; i < full; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	rem := prefixLen % 8
	if rem == 0 {
		return true
	}
	shift := 8 - rem
	return a[full]>>shift == b[full]>>shift
}

func (c Cidr) Addr() netip.Addr {
	return c.addr
}

func (c Cidr) PrefixLen() uint8 {
	return c.prefixLen
}

func (c Cidr) String() string {
	return c.addr.String() + "/" + strconv.Itoa(int(c.prefixLen))
}
