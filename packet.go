package swnat

import (
	"encoding/binary"
	"fmt"
)

const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SourceIP       IPv4
	DestinationIP  IPv4
}

func ParseIPv4Header(packet []byte) (*IPv4Header, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	h := &IPv4Header{}
	h.Version = packet[0] >> 4
	h.IHL = packet[0] & 0x0F

	if h.Version != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}

	headerLen := int(h.IHL) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return nil, fmt.Errorf("invalid header length")
	}

	h.TypeOfService = packet[1]
	h.TotalLength = binary.BigEndian.Uint16(packet[2:4])
	h.Identification = binary.BigEndian.Uint16(packet[4:6])
	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	h.Flags = uint8(flagsAndOffset >> 13)
	h.FragmentOffset = flagsAndOffset & 0x1FFF
	h.TTL = packet[8]
	h.Protocol = packet[9]
	h.Checksum = binary.BigEndian.Uint16(packet[10:12])
	copy(h.SourceIP[:], packet[12:16])
	copy(h.DestinationIP[:], packet[16:20])

	return h, nil
}

func (h *IPv4Header) Marshal(packet []byte) {
	packet[0] = (h.Version << 4) | h.IHL
	packet[1] = h.TypeOfService
	binary.BigEndian.PutUint16(packet[2:4], h.TotalLength)
	binary.BigEndian.PutUint16(packet[4:6], h.Identification)
	binary.BigEndian.PutUint16(packet[6:8], (uint16(h.Flags)<<13)|h.FragmentOffset)
	packet[8] = h.TTL
	packet[9] = h.Protocol
	binary.BigEndian.PutUint16(packet[10:12], 0) // Clear checksum for calculation
	copy(packet[12:16], h.SourceIP[:])
	copy(packet[16:20], h.DestinationIP[:])

	// Calculate and set checksum
	h.Checksum = calculateIPv4Checksum(packet[:h.IHL*4])
	binary.BigEndian.PutUint16(packet[10:12], h.Checksum)
}

func calculateIPv4Checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
		} else {
			sum += uint32(header[i]) << 8
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

type TCPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Sequence        uint32
	Acknowledgment  uint32
	DataOffset      uint8
	Flags           uint8
	Window          uint16
	Checksum        uint16
	Urgent          uint16
}

func ParseTCPHeader(packet []byte, offset int) (*TCPHeader, error) {
	if len(packet) < offset+20 {
		return nil, fmt.Errorf("packet too short for TCP header")
	}

	h := &TCPHeader{}
	h.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
	h.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	h.Sequence = binary.BigEndian.Uint32(packet[offset+4 : offset+8])
	h.Acknowledgment = binary.BigEndian.Uint32(packet[offset+8 : offset+12])
	h.DataOffset = packet[offset+12] >> 4
	h.Flags = packet[offset+13]
	h.Window = binary.BigEndian.Uint16(packet[offset+14 : offset+16])
	h.Checksum = binary.BigEndian.Uint16(packet[offset+16 : offset+18])
	h.Urgent = binary.BigEndian.Uint16(packet[offset+18 : offset+20])

	return h, nil
}

func (h *TCPHeader) Marshal(packet []byte, offset int) {
	binary.BigEndian.PutUint16(packet[offset:offset+2], h.SourcePort)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], h.DestinationPort)
	binary.BigEndian.PutUint32(packet[offset+4:offset+8], h.Sequence)
	binary.BigEndian.PutUint32(packet[offset+8:offset+12], h.Acknowledgment)
	packet[offset+12] = h.DataOffset << 4
	packet[offset+13] = h.Flags
	binary.BigEndian.PutUint16(packet[offset+14:offset+16], h.Window)
	binary.BigEndian.PutUint16(packet[offset+16:offset+18], h.Checksum)
	binary.BigEndian.PutUint16(packet[offset+18:offset+20], h.Urgent)
}

type UDPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

func ParseUDPHeader(packet []byte, offset int) (*UDPHeader, error) {
	if len(packet) < offset+8 {
		return nil, fmt.Errorf("packet too short for UDP header")
	}

	h := &UDPHeader{}
	h.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
	h.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	h.Length = binary.BigEndian.Uint16(packet[offset+4 : offset+6])
	h.Checksum = binary.BigEndian.Uint16(packet[offset+6 : offset+8])

	return h, nil
}

func (h *UDPHeader) Marshal(packet []byte, offset int) {
	binary.BigEndian.PutUint16(packet[offset:offset+2], h.SourcePort)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], h.DestinationPort)
	binary.BigEndian.PutUint16(packet[offset+4:offset+6], h.Length)
	binary.BigEndian.PutUint16(packet[offset+6:offset+8], h.Checksum)
}

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Sequence uint16
}

func ParseICMPHeader(packet []byte, offset int) (*ICMPHeader, error) {
	if len(packet) < offset+8 {
		return nil, fmt.Errorf("packet too short for ICMP header")
	}

	h := &ICMPHeader{}
	h.Type = packet[offset]
	h.Code = packet[offset+1]
	h.Checksum = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	h.ID = binary.BigEndian.Uint16(packet[offset+4 : offset+6])
	h.Sequence = binary.BigEndian.Uint16(packet[offset+6 : offset+8])

	return h, nil
}

func (h *ICMPHeader) Marshal(packet []byte, offset int) {
	packet[offset] = h.Type
	packet[offset+1] = h.Code
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], h.Checksum)
	binary.BigEndian.PutUint16(packet[offset+4:offset+6], h.ID)
	binary.BigEndian.PutUint16(packet[offset+6:offset+8], h.Sequence)
}

func calculateTCPChecksum(srcIP, dstIP IPv4, tcpData []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[9] = ProtocolTCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpData)))

	sum := uint32(0)
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	for i := 0; i < len(tcpData); i += 2 {
		if i+1 < len(tcpData) {
			sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
		} else {
			sum += uint32(tcpData[i]) << 8
		}
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func calculateUDPChecksum(srcIP, dstIP IPv4, udpData []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[9] = ProtocolUDP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	sum := uint32(0)
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	for i := 0; i < len(udpData); i += 2 {
		if i+1 < len(udpData) {
			sum += uint32(binary.BigEndian.Uint16(udpData[i : i+2]))
		} else {
			sum += uint32(udpData[i]) << 8
		}
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func calculateICMPChecksum(icmpData []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(icmpData); i += 2 {
		if i+1 < len(icmpData) {
			sum += uint32(binary.BigEndian.Uint16(icmpData[i : i+2]))
		} else {
			sum += uint32(icmpData[i]) << 8
		}
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}
