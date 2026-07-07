package sandbox

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4Packet builds a minimal IPv4 header (+ optional L4 bytes) for parse tests.
func ipv4Packet(proto byte, src, dst [4]byte, l4 []byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // version 4, IHL 5
	p[9] = proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return append(p, l4...)
}

// ipv6Packet builds a minimal IPv6 header (+ optional L4 bytes).
func ipv6Packet(next byte, src, dst [16]byte, l4 []byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x60 // version 6
	p[6] = next
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	return append(p, l4...)
}

// tcpUDPHeader carries only what l4Facts reads: dst port at bytes 2..4.
func tcpUDPHeader(dstPort uint16) []byte {
	l4 := make([]byte, 4)
	binary.BigEndian.PutUint16(l4[2:4], dstPort)
	return l4
}

func TestParseIPv4TCPDrop(t *testing.T) {
	p := ipv4Packet(6, [4]byte{192, 168, 250, 2}, [4]byte{10, 99, 88, 1}, tcpUDPHeader(443))
	src, dst, port, proto, ok := parseDropPayload(p)
	if !ok {
		t.Fatal("well-formed IPv4 TCP packet must parse")
	}
	if src != netip.MustParseAddr("192.168.250.2") || dst != netip.MustParseAddr("10.99.88.1") {
		t.Fatalf("wrong addrs: %s → %s", src, dst)
	}
	if port != 443 || proto != "tcp" {
		t.Fatalf("wrong l4 facts: port=%d proto=%s", port, proto)
	}
}

func TestParseIPv4UDPDrop(t *testing.T) {
	p := ipv4Packet(17, [4]byte{192, 168, 250, 2}, [4]byte{8, 8, 8, 8}, tcpUDPHeader(53))
	_, dst, port, proto, ok := parseDropPayload(p)
	if !ok || dst != netip.MustParseAddr("8.8.8.8") || port != 53 || proto != "udp" {
		t.Fatalf("udp parse: ok=%v dst=%s port=%d proto=%s", ok, dst, port, proto)
	}
}

func TestParseIPv4ICMPDropHasNoPort(t *testing.T) {
	p := ipv4Packet(1, [4]byte{192, 168, 250, 2}, [4]byte{169, 254, 169, 254}, nil)
	_, dst, port, proto, ok := parseDropPayload(p)
	if !ok || dst != netip.MustParseAddr("169.254.169.254") || port != 0 || proto != "icmp" {
		t.Fatalf("icmp parse: ok=%v dst=%s port=%d proto=%s", ok, dst, port, proto)
	}
}

func TestParseIPv6TCPDrop(t *testing.T) {
	dst16 := netip.MustParseAddr("2001:db8::7").As16()
	p := ipv6Packet(6, netip.MustParseAddr("fd00::2").As16(), dst16, tcpUDPHeader(8080))
	_, dst, port, proto, ok := parseDropPayload(p)
	if !ok || dst != netip.MustParseAddr("2001:db8::7") || port != 8080 || proto != "tcp" {
		t.Fatalf("ipv6 parse: ok=%v dst=%s port=%d proto=%s", ok, dst, port, proto)
	}
}

func TestParseGarbageIsNotOK(t *testing.T) {
	for _, p := range [][]byte{nil, {}, {0x50, 1, 2}, ipv4Packet(6, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, nil)[:12]} {
		if _, _, _, _, ok := parseDropPayload(p); ok {
			t.Fatalf("garbage payload %v must not parse", p)
		}
	}
}

func TestParseUnknownProtoNumberIsNamed(t *testing.T) {
	p := ipv4Packet(132, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, nil) // SCTP
	_, _, port, proto, ok := parseDropPayload(p)
	if !ok || port != 0 || proto != "132" {
		t.Fatalf("unknown proto: ok=%v port=%d proto=%s", ok, port, proto)
	}
}
