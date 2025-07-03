package swnat

import (
	"fmt"
	"net"
)

// String returns the string representation of an IPv4 address
func (ip IPv4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// Equal checks if two IPv4 addresses are equal
func (ip IPv4) Equal(other IPv4) bool {
	return ip[0] == other[0] && ip[1] == other[1] && ip[2] == other[2] && ip[3] == other[3]
}

// IsZero checks if the IPv4 address is zero
func (ip IPv4) IsZero() bool {
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0
}

// ParseIPv4 parses a string representation of an IPv4 address
func ParseIPv4(s string) (IPv4, error) {
	netIP := net.ParseIP(s)
	if netIP == nil {
		return IPv4{}, fmt.Errorf("invalid IP address: %s", s)
	}

	ipv4 := netIP.To4()
	if ipv4 == nil {
		return IPv4{}, fmt.Errorf("not an IPv4 address: %s", s)
	}

	var ip IPv4
	copy(ip[:], ipv4)
	return ip, nil
}

// String returns the string representation of an IPv6 address
func (ip IPv6) String() string {
	return net.IP(ip[:]).String()
}

// Equal checks if two IPv6 addresses are equal
func (ip IPv6) Equal(other IPv6) bool {
	for i := 0; i < 16; i++ {
		if ip[i] != other[i] {
			return false
		}
	}
	return true
}

// IsZero checks if the IPv6 address is zero
func (ip IPv6) IsZero() bool {
	for i := 0; i < 16; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}

// ParseIPv6 parses a string representation of an IPv6 address
func ParseIPv6(s string) (IPv6, error) {
	netIP := net.ParseIP(s)
	if netIP == nil {
		return IPv6{}, fmt.Errorf("invalid IP address: %s", s)
	}

	ipv6 := netIP.To16()
	if ipv6 == nil {
		return IPv6{}, fmt.Errorf("invalid IPv6 address: %s", s)
	}

	// Check if it's actually an IPv4 address
	if ipv4 := netIP.To4(); ipv4 != nil {
		return IPv6{}, fmt.Errorf("not an IPv6 address: %s", s)
	}

	var ip IPv6
	copy(ip[:], ipv6)
	return ip, nil
}
