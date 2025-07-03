package swnat

import (
	"encoding/binary"
)

// Test helper functions for creating and manipulating packets

// CreateIPv4TCPPacket creates a test IPv4 packet with TCP header
func CreateIPv4TCPPacket(srcIP, dstIP IPv4, srcPort, dstPort uint16, flags uint8) []byte {
	packet := make([]byte, 40) // 20 byte IP + 20 byte TCP
	
	// IPv4 header
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(packet[2:4], 40) // Total length
	packet[8] = 64  // TTL
	packet[9] = ProtocolTCP
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	
	// TCP header
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	packet[32] = 0x50 // Data offset (5 * 4 = 20 bytes)
	packet[33] = flags
	
	// Calculate checksums
	ipChecksum := calculateIPv4Checksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], tcpChecksum)
	
	return packet
}

// CreateIPv4UDPPacket creates a test IPv4 packet with UDP header
func CreateIPv4UDPPacket(srcIP, dstIP IPv4, srcPort, dstPort uint16, data []byte) []byte {
	totalLen := 20 + 8 + len(data)
	packet := make([]byte, totalLen)
	
	// IPv4 header
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64  // TTL
	packet[9] = ProtocolUDP
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	
	// UDP header
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(data)))
	
	// Data
	if len(data) > 0 {
		copy(packet[28:], data)
	}
	
	// Calculate checksums
	ipChecksum := calculateIPv4Checksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	
	udpChecksum := calculateUDPChecksum(srcIP, dstIP, packet[20:])
	binary.BigEndian.PutUint16(packet[26:28], udpChecksum)
	
	return packet
}

// CreateIPv4ICMPPacket creates a test IPv4 packet with ICMP header
func CreateIPv4ICMPPacket(srcIP, dstIP IPv4, icmpType, code uint8, id, seq uint16) []byte {
	packet := make([]byte, 28) // 20 byte IP + 8 byte ICMP
	
	// IPv4 header
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(packet[2:4], 28)
	packet[8] = 64  // TTL
	packet[9] = ProtocolICMP
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	
	// ICMP header
	packet[20] = icmpType
	packet[21] = code
	binary.BigEndian.PutUint16(packet[24:26], id)
	binary.BigEndian.PutUint16(packet[26:28], seq)
	
	// Calculate checksums
	ipChecksum := calculateIPv4Checksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	
	icmpChecksum := calculateICMPChecksum(packet[20:])
	binary.BigEndian.PutUint16(packet[22:24], icmpChecksum)
	
	return packet
}

// Test helper to verify checksums
func VerifyIPv4Checksum(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	return calculateIPv4Checksum(packet[:20]) == 0
}

func VerifyTCPChecksum(packet []byte) bool {
	if len(packet) < 40 {
		return false
	}
	srcIP := IPv4{packet[12], packet[13], packet[14], packet[15]}
	dstIP := IPv4{packet[16], packet[17], packet[18], packet[19]}
	tcpLen := len(packet) - 20
	return calculateTCPChecksum(srcIP, dstIP, packet[20:20+tcpLen]) == 0
}

func VerifyUDPChecksum(packet []byte) bool {
	if len(packet) < 28 {
		return false
	}
	srcIP := IPv4{packet[12], packet[13], packet[14], packet[15]}
	dstIP := IPv4{packet[16], packet[17], packet[18], packet[19]}
	udpLen := len(packet) - 20
	return calculateUDPChecksum(srcIP, dstIP, packet[20:20+udpLen]) == 0
}