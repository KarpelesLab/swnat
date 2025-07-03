package swnat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

type Table[IP comparable] struct {
	TCP  Pair[IP]
	UDP  Pair[IP]
	ICMP Pair[IP]

	externalIP  IP
	portCounter uint32
	nextPort    uint32
	maxPort     uint32
}

func NewIPv4() NAT {
	t := &Table[IPv4]{
		nextPort: 49152,
		maxPort:  65535,
	}
	t.TCP.init()
	t.UDP.init()
	t.ICMP.init()
	return t
}

// SetExternalIP sets the external IP address that will be used for outbound NAT translations
func (t *Table[IP]) SetExternalIP(ip IP) {
	t.externalIP = ip
}

// GetExternalIP returns the current external IP address
func (t *Table[IP]) GetExternalIP() IP {
	return t.externalIP
}

func (t *Table[IP]) allocatePort() uint16 {
	for attempts := 0; attempts < 1000; attempts++ {
		port := atomic.AddUint32(&t.portCounter, 1)
		port = (port % (t.maxPort - t.nextPort)) + t.nextPort
		if port <= t.maxPort {
			return uint16(port)
		}
	}
	// Fallback to random port
	var b [2]byte
	rand.Read(b[:])
	return uint16(binary.BigEndian.Uint16(b[:])%(uint16(t.maxPort-t.nextPort))) + uint16(t.nextPort)
}

func (t *Table[IP]) HandleOutboundPacket(packet []byte, namespace uintptr) error {
	// For now, assume IPv4
	ipHeader, err := ParseIPv4Header(packet)
	if err != nil {
		return fmt.Errorf("failed to parse IP header: %w", err)
	}

	headerLen := int(ipHeader.IHL) * 4
	now := uint32(time.Now().Unix())

	switch ipHeader.Protocol {
	case ProtocolTCP:
		return t.handleOutboundTCP(packet, ipHeader, headerLen, namespace, now)
	case ProtocolUDP:
		return t.handleOutboundUDP(packet, ipHeader, headerLen, namespace, now)
	case ProtocolICMP:
		return t.handleOutboundICMP(packet, ipHeader, headerLen, namespace, now)
	default:
		// Unsupported protocol, drop the packet
		return ErrDropPacket
	}
}

func (t *Table[IP]) handleOutboundTCP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now uint32) error {
	tcpHeader, err := ParseTCPHeader(packet, ipHeaderLen)
	if err != nil {
		return fmt.Errorf("failed to parse TCP header: %w", err)
	}

	// Create internal key for lookup
	internalKey := InternalKey[IP]{
		SrcIP:     any(ipHeader.SourceIP).(IP),
		DstIP:     any(ipHeader.DestinationIP).(IP),
		SrcPort:   tcpHeader.SourcePort,
		DstPort:   tcpHeader.DestinationPort,
		Namespace: namespace,
	}

	// Check if connection already exists
	conn := t.TCP.lookupOutbound(internalKey)
	if conn == nil {
		// Create new connection
		outsidePort := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:       now,
			Protocol:       ProtocolTCP,
			Namespace:      namespace,
			LocalSrcIP:     any(ipHeader.SourceIP).(IP),
			LocalSrcPort:   tcpHeader.SourcePort,
			LocalDstIp:     any(ipHeader.DestinationIP).(IP),
			LocalDstPort:   tcpHeader.DestinationPort,
			OutsideSrcIP:   t.externalIP,
			OutsideSrcPort: outsidePort,
			OutsideDstIP:   any(ipHeader.DestinationIP).(IP),
			OutsideDstPort: tcpHeader.DestinationPort,
		}
		t.TCP.addConnection(conn)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	tcpHeader.SourcePort = conn.OutsideSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	tcpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate TCP checksum
	tcpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcpData[16:18], 0) // Clear checksum
	checksum := calculateTCPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], checksum)

	return nil
}

func (t *Table[IP]) handleOutboundUDP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now uint32) error {
	udpHeader, err := ParseUDPHeader(packet, ipHeaderLen)
	if err != nil {
		return fmt.Errorf("failed to parse UDP header: %w", err)
	}

	// Create internal key for lookup
	internalKey := InternalKey[IP]{
		SrcIP:     any(ipHeader.SourceIP).(IP),
		DstIP:     any(ipHeader.DestinationIP).(IP),
		SrcPort:   udpHeader.SourcePort,
		DstPort:   udpHeader.DestinationPort,
		Namespace: namespace,
	}

	// Check if connection already exists
	conn := t.UDP.lookupOutbound(internalKey)
	if conn == nil {
		// Create new connection
		outsidePort := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:       now,
			Protocol:       ProtocolUDP,
			Namespace:      namespace,
			LocalSrcIP:     any(ipHeader.SourceIP).(IP),
			LocalSrcPort:   udpHeader.SourcePort,
			LocalDstIp:     any(ipHeader.DestinationIP).(IP),
			LocalDstPort:   udpHeader.DestinationPort,
			OutsideSrcIP:   t.externalIP,
			OutsideSrcPort: outsidePort,
			OutsideDstIP:   any(ipHeader.DestinationIP).(IP),
			OutsideDstPort: udpHeader.DestinationPort,
		}
		t.UDP.addConnection(conn)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	udpHeader.SourcePort = conn.OutsideSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	udpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate UDP checksum
	udpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(udpData[6:8], 0) // Clear checksum
	checksum := calculateUDPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, udpData)
	binary.BigEndian.PutUint16(udpData[6:8], checksum)

	return nil
}

func (t *Table[IP]) handleOutboundICMP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now uint32) error {
	icmpHeader, err := ParseICMPHeader(packet, ipHeaderLen)
	if err != nil {
		return fmt.Errorf("failed to parse ICMP header: %w", err)
	}

	// For ICMP, we use ID as port
	internalKey := InternalKey[IP]{
		SrcIP:     any(ipHeader.SourceIP).(IP),
		DstIP:     any(ipHeader.DestinationIP).(IP),
		SrcPort:   icmpHeader.ID,
		DstPort:   0,
		Namespace: namespace,
	}

	// Check if connection already exists
	conn := t.ICMP.lookupOutbound(internalKey)
	if conn == nil {
		// Create new connection with new ID
		outsideID := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:       now,
			Protocol:       ProtocolICMP,
			Namespace:      namespace,
			LocalSrcIP:     any(ipHeader.SourceIP).(IP),
			LocalSrcPort:   icmpHeader.ID,
			LocalDstIp:     any(ipHeader.DestinationIP).(IP),
			LocalDstPort:   0,
			OutsideSrcIP:   t.externalIP,
			OutsideSrcPort: outsideID,
			OutsideDstIP:   any(ipHeader.DestinationIP).(IP),
			OutsideDstPort: 0,
		}
		t.ICMP.addConnection(conn)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	icmpHeader.ID = conn.OutsideSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	icmpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate ICMP checksum
	icmpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(icmpData[2:4], 0) // Clear checksum
	checksum := calculateICMPChecksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], checksum)

	return nil
}

func (t *Table[IP]) HandleInboundPacket(packet []byte) (uintptr, error) {
	// For now, assume IPv4
	ipHeader, err := ParseIPv4Header(packet)
	if err != nil {
		return 0, fmt.Errorf("failed to parse IP header: %w", err)
	}

	headerLen := int(ipHeader.IHL) * 4
	now := uint32(time.Now().Unix())

	switch ipHeader.Protocol {
	case ProtocolTCP:
		return t.handleInboundTCP(packet, ipHeader, headerLen, now)
	case ProtocolUDP:
		return t.handleInboundUDP(packet, ipHeader, headerLen, now)
	case ProtocolICMP:
		return t.handleInboundICMP(packet, ipHeader, headerLen, now)
	default:
		// Unsupported protocol, drop the packet
		return 0, ErrDropPacket
	}
}

func (t *Table[IP]) handleInboundTCP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now uint32) (uintptr, error) {
	tcpHeader, err := ParseTCPHeader(packet, ipHeaderLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse TCP header: %w", err)
	}

	// Create external key for lookup
	externalKey := ExternalKey[IP]{
		SrcIP:   any(ipHeader.SourceIP).(IP),
		DstIP:   any(ipHeader.DestinationIP).(IP),
		SrcPort: tcpHeader.SourcePort,
		DstPort: tcpHeader.DestinationPort,
	}

	// Look up connection
	conn := t.TCP.lookupInbound(externalKey)
	if conn == nil {
		// No matching connection, drop packet
		return 0, ErrDropPacket
	}

	// Update last seen
	conn.LastSeen = now

	// Rewrite packet to restore original addresses
	ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
	tcpHeader.DestinationPort = conn.LocalSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	tcpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate TCP checksum
	tcpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcpData[16:18], 0) // Clear checksum
	checksum := calculateTCPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], checksum)

	return conn.Namespace, nil
}

func (t *Table[IP]) handleInboundUDP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now uint32) (uintptr, error) {
	udpHeader, err := ParseUDPHeader(packet, ipHeaderLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse UDP header: %w", err)
	}

	// Create external key for lookup
	externalKey := ExternalKey[IP]{
		SrcIP:   any(ipHeader.SourceIP).(IP),
		DstIP:   any(ipHeader.DestinationIP).(IP),
		SrcPort: udpHeader.SourcePort,
		DstPort: udpHeader.DestinationPort,
	}

	// Look up connection
	conn := t.UDP.lookupInbound(externalKey)
	if conn == nil {
		// No matching connection, drop packet
		return 0, ErrDropPacket
	}

	// Update last seen
	conn.LastSeen = now

	// Rewrite packet to restore original addresses
	ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
	udpHeader.DestinationPort = conn.LocalSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	udpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate UDP checksum
	udpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(udpData[6:8], 0) // Clear checksum
	checksum := calculateUDPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, udpData)
	binary.BigEndian.PutUint16(udpData[6:8], checksum)

	return conn.Namespace, nil
}

func (t *Table[IP]) handleInboundICMP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now uint32) (uintptr, error) {
	icmpHeader, err := ParseICMPHeader(packet, ipHeaderLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse ICMP header: %w", err)
	}

	// For ICMP echo replies, we match on ID
	externalKey := ExternalKey[IP]{
		SrcIP:   any(ipHeader.SourceIP).(IP),
		DstIP:   any(ipHeader.DestinationIP).(IP),
		SrcPort: 0,
		DstPort: icmpHeader.ID,
	}

	// Look up connection
	conn := t.ICMP.lookupInbound(externalKey)
	if conn == nil {
		// No matching connection, drop packet
		return 0, ErrDropPacket
	}

	// Update last seen
	conn.LastSeen = now

	// Rewrite packet to restore original addresses and ID
	ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
	icmpHeader.ID = conn.LocalSrcPort

	// Update headers in packet
	ipHeader.Marshal(packet)
	icmpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate ICMP checksum
	icmpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(icmpData[2:4], 0) // Clear checksum
	checksum := calculateICMPChecksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], checksum)

	return conn.Namespace, nil
}
