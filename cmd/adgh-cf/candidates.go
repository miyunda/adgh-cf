package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

var reserved = func() []netip.Prefix {
	blocks := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
	result := make([]netip.Prefix, 0, len(blocks))
	for _, block := range blocks {
		result = append(result, netip.MustParsePrefix(block))
	}
	return result
}()

func publicIPv4(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return false
	}
	for _, block := range reserved {
		if block.Contains(a) {
			return false
		}
	}
	return true
}

func sampleCandidates(text string, count, offset int) ([]string, error) {
	var ranges []netip.Prefix
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(line, "/") {
			p, err = netip.ParsePrefix(line)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(line)
			p = netip.PrefixFrom(a, 32)
		}
		if err != nil || !p.IsValid() || !p.Addr().Is4() || p.Bits() < 12 || p != p.Masked() {
			return nil, fmt.Errorf("invalid public IPv4 or canonical CIDR: %s", line)
		}
		for _, block := range reserved {
			if p.Overlaps(block) {
				return nil, fmt.Errorf("candidate overlaps reserved addresses: %s", line)
			}
		}
		ranges = append(ranges, p)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("candidate file is empty")
	}
	result := []string{}
	seen := map[string]bool{}
	// Bounded sampling; offset rotates the tested addresses without enumerating subnets.
	for round := 0; len(result) < count && round < count*2; round++ {
		for _, p := range ranges {
			a := p.Addr().As4()
			start := uint64(binary.BigEndian.Uint32(a[:]))
			size := uint64(1) << (32 - p.Bits())
			usable := size
			first := uint64(0)
			if size > 2 {
				usable = size - 2
				first = 1
			}
			value := uint32(start + first + (uint64(offset+round)*7919+17)%usable)
			var raw [4]byte
			binary.BigEndian.PutUint32(raw[:], value)
			ip := netip.AddrFrom4(raw).String()
			if !seen[ip] {
				seen[ip] = true
				result = append(result, ip)
			}
			if len(result) == count {
				break
			}
		}
	}
	return result, nil
}
