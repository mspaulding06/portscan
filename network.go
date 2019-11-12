package portscan

import "net"

// ResolveHost will look up IP address of a host
// Assuming only ever a single address for the sake of the
// assignment.
// TODO: Return full list to scan all IPs
func ResolveHost(hostOrIP string) string {
	addrs, err := net.LookupHost(hostOrIP)
	if err != nil {
		return ""
	}
	return addrs[0]
}
