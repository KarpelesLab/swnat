package swnat

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4Header(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		want    *IPv4Header
		wantErr bool
	}{
		{
			name: "valid IPv4 packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x3c, // Version/IHL, TOS, Total Length
				0x1c, 0x46, 0x40, 0x00, // ID, Flags/Fragment
				0x40, 0x06, 0xb1, 0xe6, // TTL, Protocol, Checksum
				0xc0, 0xa8, 0x00, 0x01, // Source IP
				0xc0, 0xa8, 0x00, 0x02, // Dest IP
			},
			want: &IPv4Header{
				Version:        4,
				IHL:            5,
				TypeOfService:  0,
				TotalLength:    60,
				Identification: 0x1c46,
				Flags:          0x40 >> 5,
				TTL:            64,
				Protocol:       6,
				Checksum:       0xb1e6,
				SourceIP:       IPv4{192, 168, 0, 1},
				DestinationIP:  IPv4{192, 168, 0, 2},
			},
		},
		{
			name:    "packet too short",
			packet:  []byte{0x45, 0x00},
			wantErr: true,
		},
		{
			name:    "invalid version",
			packet:  append([]byte{0x65}, make([]byte, 19)...), // Version 6
			wantErr: true,
		},
		{
			name:    "invalid header length",
			packet:  append([]byte{0x44}, make([]byte, 19)...), // IHL = 4 (16 bytes)
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv4Header(tt.packet)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPv4Header() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Version != tt.want.Version {
					t.Errorf("Version = %v, want %v", got.Version, tt.want.Version)
				}
				if got.Protocol != tt.want.Protocol {
					t.Errorf("Protocol = %v, want %v", got.Protocol, tt.want.Protocol)
				}
				if !got.SourceIP.Equal(tt.want.SourceIP) {
					t.Errorf("SourceIP = %v, want %v", got.SourceIP, tt.want.SourceIP)
				}
				if !got.DestinationIP.Equal(tt.want.DestinationIP) {
					t.Errorf("DestinationIP = %v, want %v", got.DestinationIP, tt.want.DestinationIP)
				}
			}
		})
	}
}

func TestParseTCPHeader(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		offset  int
		want    *TCPHeader
		wantErr bool
	}{
		{
			name: "valid TCP header",
			packet: []byte{
				0x00, 0x50, 0x00, 0x80, // Source Port, Dest Port
				0x00, 0x00, 0x00, 0x01, // Sequence Number
				0x00, 0x00, 0x00, 0x02, // Acknowledgment Number
				0x50, 0x18, 0x00, 0x20, // Data Offset/Flags, Window
				0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Pointer
			},
			offset: 0,
			want: &TCPHeader{
				SourcePort:      80,
				DestinationPort: 128,
				Sequence:        1,
				Acknowledgment:  2,
				DataOffset:      5,
				Flags:           0x18,
				Window:          32,
				Checksum:        0,
				Urgent:          0,
			},
		},
		{
			name:    "packet too short",
			packet:  []byte{0x00, 0x50},
			offset:  0,
			wantErr: true,
		},
		{
			name:    "invalid offset",
			packet:  make([]byte, 20),
			offset:  15,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTCPHeader(tt.packet, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTCPHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.SourcePort != tt.want.SourcePort {
					t.Errorf("SourcePort = %v, want %v", got.SourcePort, tt.want.SourcePort)
				}
				if got.DestinationPort != tt.want.DestinationPort {
					t.Errorf("DestinationPort = %v, want %v", got.DestinationPort, tt.want.DestinationPort)
				}
				if got.Flags != tt.want.Flags {
					t.Errorf("Flags = %v, want %v", got.Flags, tt.want.Flags)
				}
			}
		})
	}
}

func TestParseUDPHeader(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		offset  int
		want    *UDPHeader
		wantErr bool
	}{
		{
			name: "valid UDP header",
			packet: []byte{
				0x00, 0x35, 0x00, 0x50, // Source Port, Dest Port
				0x00, 0x08, 0x00, 0x00, // Length, Checksum
			},
			offset: 0,
			want: &UDPHeader{
				SourcePort:      53,
				DestinationPort: 80,
				Length:          8,
				Checksum:        0,
			},
		},
		{
			name:    "packet too short",
			packet:  []byte{0x00, 0x35},
			offset:  0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUDPHeader(tt.packet, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUDPHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.SourcePort != tt.want.SourcePort {
					t.Errorf("SourcePort = %v, want %v", got.SourcePort, tt.want.SourcePort)
				}
				if got.DestinationPort != tt.want.DestinationPort {
					t.Errorf("DestinationPort = %v, want %v", got.DestinationPort, tt.want.DestinationPort)
				}
			}
		})
	}
}

func TestParseICMPHeader(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		offset  int
		want    *ICMPHeader
		wantErr bool
	}{
		{
			name: "echo request",
			packet: []byte{
				0x08, 0x00, 0x00, 0x00, // Type, Code, Checksum
				0x00, 0x01, 0x00, 0x02, // ID, Sequence
			},
			offset: 0,
			want: &ICMPHeader{
				Type:     8,
				Code:     0,
				Checksum: 0,
				ID:       1,
				Sequence: 2,
			},
		},
		{
			name:    "packet too short",
			packet:  []byte{0x08},
			offset:  0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseICMPHeader(tt.packet, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseICMPHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Type != tt.want.Type {
					t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
				}
				if got.ID != tt.want.ID {
					t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
				}
			}
		})
	}
}

func TestCalculateIPv4Checksum(t *testing.T) {
	// Test with a known IPv4 header
	header := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, // Checksum set to 0
		0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0x02,
	}

	checksum := calculateIPv4Checksum(header)
	
	// Set the checksum
	binary.BigEndian.PutUint16(header[10:12], checksum)
	
	// Verify checksum is correct by recomputing (should be 0)
	verify := calculateIPv4Checksum(header)
	if verify != 0 {
		t.Errorf("Checksum verification failed: got %x, want 0", verify)
	}
}

func TestIPv4HeaderMarshal(t *testing.T) {
	h := &IPv4Header{
		Version:        4,
		IHL:            5,
		TypeOfService:  0,
		TotalLength:    40,
		Identification: 0x1234,
		Flags:          2,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       ProtocolTCP,
		SourceIP:       IPv4{10, 0, 0, 1},
		DestinationIP:  IPv4{10, 0, 0, 2},
	}
	
	packet := make([]byte, 40)
	h.Marshal(packet)
	
	// Parse it back
	parsed, err := ParseIPv4Header(packet)
	if err != nil {
		t.Fatalf("Failed to parse marshaled header: %v", err)
	}
	
	// Verify fields
	if parsed.Version != h.Version {
		t.Errorf("Version mismatch: got %d, want %d", parsed.Version, h.Version)
	}
	if parsed.Protocol != h.Protocol {
		t.Errorf("Protocol mismatch: got %d, want %d", parsed.Protocol, h.Protocol)
	}
	if !parsed.SourceIP.Equal(h.SourceIP) {
		t.Errorf("SourceIP mismatch: got %v, want %v", parsed.SourceIP, h.SourceIP)
	}
	if !parsed.DestinationIP.Equal(h.DestinationIP) {
		t.Errorf("DestinationIP mismatch: got %v, want %v", parsed.DestinationIP, h.DestinationIP)
	}
}

func TestTCPHeaderMarshal(t *testing.T) {
	h := &TCPHeader{
		SourcePort:      80,
		DestinationPort: 443,
		Sequence:        0x12345678,
		Acknowledgment:  0x87654321,
		DataOffset:      5,
		Flags:           TCPFlagSYN | TCPFlagACK,
		Window:          8192,
		Checksum:        0,
		Urgent:          0,
	}
	
	packet := make([]byte, 20)
	h.Marshal(packet, 0)
	
	// Parse it back
	parsed, err := ParseTCPHeader(packet, 0)
	if err != nil {
		t.Fatalf("Failed to parse marshaled header: %v", err)
	}
	
	// Verify fields
	if parsed.SourcePort != h.SourcePort {
		t.Errorf("SourcePort mismatch: got %d, want %d", parsed.SourcePort, h.SourcePort)
	}
	if parsed.DestinationPort != h.DestinationPort {
		t.Errorf("DestinationPort mismatch: got %d, want %d", parsed.DestinationPort, h.DestinationPort)
	}
	if parsed.Flags != h.Flags {
		t.Errorf("Flags mismatch: got %d, want %d", parsed.Flags, h.Flags)
	}
}

func TestUDPHeaderMarshal(t *testing.T) {
	h := &UDPHeader{
		SourcePort:      53,
		DestinationPort: 12345,
		Length:          100,
		Checksum:        0,
	}
	
	packet := make([]byte, 8)
	h.Marshal(packet, 0)
	
	// Parse it back
	parsed, err := ParseUDPHeader(packet, 0)
	if err != nil {
		t.Fatalf("Failed to parse marshaled header: %v", err)
	}
	
	// Verify fields
	if parsed.SourcePort != h.SourcePort {
		t.Errorf("SourcePort mismatch: got %d, want %d", parsed.SourcePort, h.SourcePort)
	}
	if parsed.Length != h.Length {
		t.Errorf("Length mismatch: got %d, want %d", parsed.Length, h.Length)
	}
}