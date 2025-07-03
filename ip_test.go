package swnat

import (
	"bytes"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    IPv4
		wantErr bool
	}{
		{
			name:  "valid IP",
			input: "192.168.1.1",
			want:  IPv4{192, 168, 1, 1},
		},
		{
			name:  "localhost",
			input: "127.0.0.1",
			want:  IPv4{127, 0, 0, 1},
		},
		{
			name:  "broadcast",
			input: "255.255.255.255",
			want:  IPv4{255, 255, 255, 255},
		},
		{
			name:  "zero IP",
			input: "0.0.0.0",
			want:  IPv4{0, 0, 0, 0},
		},
		{
			name:    "invalid format - too few octets",
			input:   "192.168.1",
			wantErr: true,
		},
		{
			name:    "invalid format - too many octets",
			input:   "192.168.1.1.1",
			wantErr: true,
		},
		{
			name:    "invalid octet - negative",
			input:   "192.-1.1.1",
			wantErr: true,
		},
		{
			name:    "invalid octet - too large",
			input:   "192.256.1.1",
			wantErr: true,
		},
		{
			name:    "invalid octet - not a number",
			input:   "192.abc.1.1",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv4(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv4() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseIPv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIPv6(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    IPv6
		wantErr bool
	}{
		{
			name:  "loopback",
			input: "::1",
			want:  IPv6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name:  "zero address",
			input: "::",
			want:  IPv6{},
		},
		{
			name:  "full address",
			input: "2001:db8:85a3:0:0:8a2e:370:7334",
			want:  IPv6{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
		},
		{
			name:  "compressed address",
			input: "2001:db8::8a2e:370:7334",
			want:  IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
		},
		{
			name:  "link-local",
			input: "fe80::1",
			want:  IPv6{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name:    "invalid - too many colons",
			input:   ":::1",
			wantErr: true,
		},
		{
			name:    "invalid - too many groups",
			input:   "2001:db8:85a3:0:0:8a2e:370:7334:extra",
			wantErr: true,
		},
		{
			name:    "invalid - bad hex",
			input:   "2001:xyz8::1",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv6(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv6() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got[:], tt.want[:]) {
				t.Errorf("ParseIPv6() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv4String(t *testing.T) {
	tests := []struct {
		name string
		ip   IPv4
		want string
	}{
		{
			name: "standard IP",
			ip:   IPv4{192, 168, 1, 1},
			want: "192.168.1.1",
		},
		{
			name: "zero IP",
			ip:   IPv4{0, 0, 0, 0},
			want: "0.0.0.0",
		},
		{
			name: "broadcast",
			ip:   IPv4{255, 255, 255, 255},
			want: "255.255.255.255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ip.String(); got != tt.want {
				t.Errorf("IPv4.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv6String(t *testing.T) {
	tests := []struct {
		name string
		ip   IPv6
		want string
	}{
		{
			name: "loopback",
			ip:   IPv6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "::1",
		},
		{
			name: "zero address",
			ip:   IPv6{},
			want: "::",
		},
		{
			name: "full address",
			ip:   IPv6{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
			want: "2001:db8:85a3::8a2e:370:7334",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ip.String(); got != tt.want {
				t.Errorf("IPv6.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv4IsZero(t *testing.T) {
	tests := []struct {
		name string
		ip   IPv4
		want bool
	}{
		{
			name: "zero IP",
			ip:   IPv4{0, 0, 0, 0},
			want: true,
		},
		{
			name: "non-zero IP",
			ip:   IPv4{192, 168, 1, 1},
			want: false,
		},
		{
			name: "partial zero",
			ip:   IPv4{0, 0, 0, 1},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ip.IsZero(); got != tt.want {
				t.Errorf("IPv4.IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv6IsZero(t *testing.T) {
	tests := []struct {
		name string
		ip   IPv6
		want bool
	}{
		{
			name: "zero IP",
			ip:   IPv6{},
			want: true,
		},
		{
			name: "loopback",
			ip:   IPv6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ip.IsZero(); got != tt.want {
				t.Errorf("IPv6.IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv4Equal(t *testing.T) {
	ip1 := IPv4{192, 168, 1, 1}
	ip2 := IPv4{192, 168, 1, 1}
	ip3 := IPv4{192, 168, 1, 2}

	if !ip1.Equal(ip2) {
		t.Error("Equal IPs should be equal")
	}
	if ip1.Equal(ip3) {
		t.Error("Different IPs should not be equal")
	}
}

func TestIPv6Equal(t *testing.T) {
	ip1 := IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ip2 := IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ip3 := IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	if !ip1.Equal(ip2) {
		t.Error("Equal IPs should be equal")
	}
	if ip1.Equal(ip3) {
		t.Error("Different IPs should not be equal")
	}
}