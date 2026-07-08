// Drop carries the packet facts of one kernel-dropped egress attempt from a
// session's nflog listener to the single consumer that signs breach events.
// Facts only, by design: no key, no credential, and no shared state may
// travel with — or be reachable from — a Drop.
package sandbox

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"
)

type Drop struct {
	SessionID string
	SrcIP     netip.Addr
	DstIP     netip.Addr
	DstPort   uint16 // 0 when the protocol has no ports (e.g. ICMP)
	Proto     string // "tcp", "udp", "icmp", "icmpv6", or protocol number
	At        time.Time
}

// parseDropPayload extracts packet facts from a raw IP packet as delivered
// by NFLOG (network-layer payload, no link header). Returns ok=false for
// anything that does not parse as IPv4/IPv6 — a malformed packet is not a
// breach signal we can attribute, and the kernel already dropped it.
func parseDropPayload(p []byte) (src, dst netip.Addr, port uint16, proto string, ok bool) {
	if len(p) < 1 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
		port, proto = l4Facts(p[9], p[ihl:])
		ok = true
	case 6:
		if len(p) < 40 {
			return
		}
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
		port, proto = l4Facts(p[6], p[40:])
		ok = true
	}
	return
}

// l4Facts names the protocol and pulls the destination port for TCP/UDP,
// whose headers both carry it at bytes 2..4.
func l4Facts(protoNum byte, l4 []byte) (uint16, string) {
	switch protoNum {
	case 6, 17:
		name := "tcp"
		if protoNum == 17 {
			name = "udp"
		}
		if len(l4) >= 4 {
			return binary.BigEndian.Uint16(l4[2:4]), name
		}
		return 0, name
	case 1:
		return 0, "icmp"
	case 58:
		return 0, "icmpv6"
	default:
		return 0, strconv.Itoa(int(protoNum))
	}
}
