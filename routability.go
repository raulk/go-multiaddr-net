package manet

import (
	"fmt"
	"net"

	ma "github.com/multiformats/go-multiaddr"
	mamask "github.com/whyrusleeping/multiaddr-filter"
)

const (
	RoutabilityPublic = iota
	RoutabilityPrivate
	RoutabilityLinkLocal
	RoutabilitySelf
	RoutabilitySpecialPurpose
	RoutabilityError
)

// Reference: https://tools.ietf.org/html/rfc6890
var table = map[string]int{
	/* ~~~ IPv4 ~~~*/

	// "This host on this network"
	"/ip4/0.0.0.0/ipcidr/8": RoutabilitySpecialPurpose,

	// IETF Protocol Assignments.
	"/ip4/192.0.0.0/ipcidr/24": RoutabilitySpecialPurpose,

	// DS-Lite.
	"/ip4/192.0.0.0/ipcidr/26": RoutabilitySpecialPurpose,

	// Documentation (TEST-NET-1)
	"/ip4/192.0.2.0/ipcidr/24": RoutabilitySpecialPurpose,

	// Documentation (TEST-NET-2)
	"/ip4/198.51.100.0/ipcidr/24": RoutabilitySpecialPurpose,

	// Documentation (TEST-NET-3).
	"/ip4/203.0.113.0/ipcidr/24": RoutabilitySpecialPurpose,

	// IPv4 Multicast.
	"/ip4/224.0.0.0/ipcidr/4": RoutabilitySpecialPurpose,

	// Reserved for Future Use.
	"/ip4/240.0.0.0/ipcidr/4": RoutabilitySpecialPurpose,

	// Limited Broadcast.
	"/ip4/255.255.255.255/ipcidr/32": RoutabilitySpecialPurpose,

	// 6to4 Relay Anycast
	"/ip4/192.88.99.0/ipcidr/24": RoutabilitySpecialPurpose,

	// Network Interconnect Device Benchmark Testing.
	"/ip4/198.18.0.0/ipcidr/15": RoutabilitySpecialPurpose,

	// Private-Use Networks.
	"/ip4/10.0.0.0/ipcidr/8": RoutabilityPrivate,

	// Private-Use Networks.
	"/ip4/172.16.0.0/ipcidr/12": RoutabilityPrivate,

	// Private-Use Networks.
	"/ip4/192.168.0.0/ipcidr/16": RoutabilityPrivate,

	// Shared address space.
	"/ip4/100.64.0.0/ipcidr/10": RoutabilityPrivate,

	// Link-local.
	"/ip4/169.254.0.0/ipcidr/16": RoutabilityLinkLocal,

	// Localhost.
	"/ip4/127.0.0.0/ipcidr/8": RoutabilitySelf,

	/* ~~~ IPv6 ~~~ */

	"/ip6/::1/ipcidr/128": RoutabilitySelf,

	// Unspecified Address
	"/ip6/::/ipcidr/128": RoutabilitySpecialPurpose,

	// TODO IPv4-IPv6 Translat.
	// "/ip6/64:ff9b::/ipcidr/96": ,

	// TODO IPv4-mapped Address
	// "/ip6/::ffff:0:0/ipcidr/96": ,

	// Discard-Only Address Block
	"/ip6/100::/ipcidr/64": RoutabilitySpecialPurpose,

	// IETF Protocol Assignments
	"/ip6/2001::/ipcidr/23": RoutabilitySpecialPurpose,

	// TEREDO
	"/ip6/2001::/ipcidr/32": RoutabilitySpecialPurpose,

	// Benchmarking
	"/ip6/2001:2::/ipcidr/48": RoutabilitySpecialPurpose,

	// Documentation
	"/ip6/2001:db8::/ipcidr/32": RoutabilitySpecialPurpose,

	// ORCHID
	"/ip6/2001:10::/ipcidr/28": RoutabilitySpecialPurpose,

	// TODO 6to4
	// "/ip6/2002::/ipcidr/16": ,

	// Private networks.
	"/ip6/fd00::/ipcidr/8": RoutabilityPrivate,

	// Unique-Local
	"/ip6/fc00::/ipcidr/7": RoutabilityPrivate,

	// Linked-Scoped Unicast
	"/ip6/fe80::/ipcidr/10": RoutabilityLinkLocal,

	// IPv6 Multicast.
	"/ip6/ff00::/ipcidr/8": RoutabilitySpecialPurpose,
}

var masks map[*net.IPNet]int

var segments map[int][]*net.IPNet

func init() {
	masks = make(map[*net.IPNet]int, len(table))
	segments = make(map[int][]*net.IPNet)

	for mask, seg := range table {
		m, err := mamask.NewMask(mask)
		if err != nil {
			panic("error while initializing routability table: " + err.Error())
		}
		masks[m] = seg
		segments[seg] = append(segments[seg], m)
	}
}

func Routability(addr ma.Multiaddr) int {
	ip, err := toNetIP(addr)
	if err != nil {
		return RoutabilityError
	}
	for mask, seg := range masks {
		if mask.Contains(ip) {
			return seg
		}
	}
	return RoutabilityPublic
}

func IsRoutable(addr ma.Multiaddr, segment int) bool {
	masks, ok := segments[segment]
	if !ok {
		return false
	}
	ip, err := toNetIP(addr)
	if err != nil {
		return false
	}
	for _, m := range masks {
		if m.Contains(ip) {
			return true
		}
	}
	return segment == RoutabilityPublic
}

func toNetIP(addr ma.Multiaddr) (net.IP, error) {
	maddr := ma.Split(addr)
	naddr, err := ToNetAddr(maddr[0])
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(naddr.String())
	if ip == nil {
		return nil, fmt.Errorf("could not extract IP addr from multiaddr: %s", addr.String())
	}
	return ip, nil
}
