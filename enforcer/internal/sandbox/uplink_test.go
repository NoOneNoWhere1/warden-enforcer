package sandbox

import "testing"

func TestUplinkSubnet(t *testing.T) {
	cases := []struct {
		idx                    int
		hostCIDR, nsCIDR, gate string
	}{
		{0, "10.200.0.1/30", "10.200.0.2/30", "10.200.0.1"},
		{1, "10.200.0.5/30", "10.200.0.6/30", "10.200.0.5"},
		{63, "10.200.0.253/30", "10.200.0.254/30", "10.200.0.253"},          // last /30 in third octet 0
		{64, "10.200.1.1/30", "10.200.1.2/30", "10.200.1.1"},                // rolls into third octet 1
		{16383, "10.200.255.253/30", "10.200.255.254/30", "10.200.255.253"}, // last index in the pool
	}
	for _, c := range cases {
		host, ns, gw := uplinkSubnet(c.idx)
		if host != c.hostCIDR || ns != c.nsCIDR || gw != c.gate {
			t.Errorf("uplinkSubnet(%d) = (%s, %s, %s), want (%s, %s, %s)",
				c.idx, host, ns, gw, c.hostCIDR, c.nsCIDR, c.gate)
		}
	}
}

func TestAllocatorHandsOutLowestFreeIndex(t *testing.T) {
	a := newUplinkAllocator()
	for want := 0; want < 3; want++ {
		idx, err := a.alloc("s" + string(rune('a'+want)))
		if err != nil || idx != want {
			t.Fatalf("alloc #%d = (%d, %v), want (%d, nil)", want, idx, err, want)
		}
	}
}

func TestAllocatorReusesFreedIndex(t *testing.T) {
	a := newUplinkAllocator()
	_, _ = a.alloc("sa")
	_, _ = a.alloc("sb")
	a.free("sa")
	idx, err := a.alloc("sc")
	if err != nil || idx != 0 {
		t.Fatalf("alloc after free = (%d, %v), want (0, nil)", idx, err)
	}
}

func TestAllocatorFreeUnknownSessionIsNoop(t *testing.T) {
	a := newUplinkAllocator()
	a.free("never-allocated")
	if idx, err := a.alloc("sa"); err != nil || idx != 0 {
		t.Fatalf("alloc = (%d, %v), want (0, nil)", idx, err)
	}
}

func TestAllocatorExhaustion(t *testing.T) {
	a := newUplinkAllocator()
	for i := 0; i < maxUplinks; i++ {
		a.used[i] = true
	}
	if _, err := a.alloc("sa"); err == nil {
		t.Fatal("alloc on a full pool must error, got nil")
	}
}
