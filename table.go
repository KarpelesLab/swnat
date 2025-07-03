package swnat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
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

	// Now is a function that returns the current time in Unix seconds.
	// Defaults to time.Now().Unix() but can be overridden for performance.
	Now func() int64

	// MaxConnPerNamespace is the maximum number of connections allowed per namespace.
	// When this limit is reached, oldest connections will be removed.
	// Defaults to 200.
	MaxConnPerNamespace int

	// Protocol-specific timeouts in seconds
	TCPTimeout  int64
	UDPTimeout  int64
	ICMPTimeout int64
}

func NewIPv4(externalIP net.IP) NAT {
	t := &Table[IPv4]{
		nextPort:            49152,
		maxPort:             65535,
		Now:                 func() int64 { return time.Now().Unix() },
		MaxConnPerNamespace: 200,
		TCPTimeout:          86400, // 24 hours
		UDPTimeout:          180,   // 3 minutes
		ICMPTimeout:         30,    // 30 seconds
	}

	// Convert net.IP to IPv4
	if ip4 := externalIP.To4(); ip4 != nil {
		copy(t.externalIP[:], ip4)
	} else {
		panic("NewIPv4: provided IP is not a valid IPv4 address")
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
	now := t.Now()

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

func (t *Table[IP]) handleOutboundTCP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now int64) error {
	tcpHeader, err := ParseTCPHeader(packet, ipHeaderLen)
	if err != nil {
		return fmt.Errorf("failed to parse TCP header: %w", err)
	}

	// Check drop rules
	if t.TCP.checkDropRule(tcpHeader.DestinationPort) {
		return ErrDropPacket
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
		// Check redirect rules
		targetDstIP := any(ipHeader.DestinationIP).(IP)
		targetDstPort := tcpHeader.DestinationPort
		redirectDstIP, redirectDstPort, shouldRedirect := t.TCP.checkRedirectRule(targetDstIP, targetDstPort)

		if shouldRedirect {
			targetDstIP = redirectDstIP
			targetDstPort = redirectDstPort
		}

		// Create new connection
		outsidePort := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:           now,
			Protocol:           ProtocolTCP,
			Namespace:          namespace,
			LocalSrcIP:         any(ipHeader.SourceIP).(IP),
			LocalSrcPort:       tcpHeader.SourcePort,
			LocalDstIp:         any(ipHeader.DestinationIP).(IP),
			LocalDstPort:       tcpHeader.DestinationPort,
			OutsideSrcIP:       t.externalIP,
			OutsideSrcPort:     outsidePort,
			OutsideDstIP:       targetDstIP,
			OutsideDstPort:     targetDstPort,
			RewriteDestination: shouldRedirect,
		}
		t.TCP.addConnection(conn, t.MaxConnPerNamespace)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	tcpHeader.SourcePort = conn.OutsideSrcPort

	// If destination should be rewritten, do it
	if conn.RewriteDestination {
		ipHeader.DestinationIP = any(conn.OutsideDstIP).(IPv4)
		tcpHeader.DestinationPort = conn.OutsideDstPort
	}

	// Update headers in packet
	ipHeader.Marshal(packet)
	tcpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate TCP checksum
	tcpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcpData[16:18], 0) // Clear checksum
	checksum := calculateTCPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], checksum)

	// Check if this is a connection termination (FIN or RST)
	if tcpHeader.Flags&(TCPFlagFIN|TCPFlagRST) != 0 {
		// Mark connection for immediate removal on next cleanup
		conn.PendingSweep = true
	}

	return nil
}

func (t *Table[IP]) handleOutboundUDP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now int64) error {
	udpHeader, err := ParseUDPHeader(packet, ipHeaderLen)
	if err != nil {
		return fmt.Errorf("failed to parse UDP header: %w", err)
	}

	// Check drop rules
	if t.UDP.checkDropRule(udpHeader.DestinationPort) {
		return ErrDropPacket
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
		// Check redirect rules
		targetDstIP := any(ipHeader.DestinationIP).(IP)
		targetDstPort := udpHeader.DestinationPort
		redirectDstIP, redirectDstPort, shouldRedirect := t.UDP.checkRedirectRule(targetDstIP, targetDstPort)

		if shouldRedirect {
			targetDstIP = redirectDstIP
			targetDstPort = redirectDstPort
		}

		// Create new connection
		outsidePort := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:           now,
			Protocol:           ProtocolUDP,
			Namespace:          namespace,
			LocalSrcIP:         any(ipHeader.SourceIP).(IP),
			LocalSrcPort:       udpHeader.SourcePort,
			LocalDstIp:         any(ipHeader.DestinationIP).(IP),
			LocalDstPort:       udpHeader.DestinationPort,
			OutsideSrcIP:       t.externalIP,
			OutsideSrcPort:     outsidePort,
			OutsideDstIP:       targetDstIP,
			OutsideDstPort:     targetDstPort,
			RewriteDestination: shouldRedirect,
		}
		t.UDP.addConnection(conn, t.MaxConnPerNamespace)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	udpHeader.SourcePort = conn.OutsideSrcPort

	// If destination should be rewritten, do it
	if conn.RewriteDestination {
		ipHeader.DestinationIP = any(conn.OutsideDstIP).(IPv4)
		udpHeader.DestinationPort = conn.OutsideDstPort
	}

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

func (t *Table[IP]) handleOutboundICMP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, namespace uintptr, now int64) error {
	if len(packet) < ipHeaderLen+8 {
		return fmt.Errorf("ICMP packet too small")
	}

	icmpType := packet[ipHeaderLen]

	// We only handle echo request/reply for now
	if icmpType != ICMPTypeEchoRequest && icmpType != ICMPTypeEchoReply {
		// For other ICMP types, pass through without NAT
		return nil
	}

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
		// Check redirect rules for ICMP (using port 0)
		targetDstIP := any(ipHeader.DestinationIP).(IP)
		redirectDstIP, _, shouldRedirect := t.ICMP.checkRedirectRule(targetDstIP, 0)

		if shouldRedirect {
			targetDstIP = redirectDstIP
		}

		// Create new connection with new ID
		outsideID := t.allocatePort()
		conn = &Conn[IP]{
			LastSeen:           now,
			Protocol:           ProtocolICMP,
			Namespace:          namespace,
			LocalSrcIP:         any(ipHeader.SourceIP).(IP),
			LocalSrcPort:       icmpHeader.ID,
			LocalDstIp:         any(ipHeader.DestinationIP).(IP),
			LocalDstPort:       0,
			OutsideSrcIP:       t.externalIP,
			OutsideSrcPort:     outsideID,
			OutsideDstIP:       targetDstIP,
			OutsideDstPort:     0,
			RewriteDestination: shouldRedirect,
		}
		t.ICMP.addConnection(conn, t.MaxConnPerNamespace)
	} else {
		conn.LastSeen = now
	}

	// Rewrite packet
	ipHeader.SourceIP = any(conn.OutsideSrcIP).(IPv4)
	icmpHeader.ID = conn.OutsideSrcPort

	// If destination should be rewritten, do it
	if conn.RewriteDestination {
		ipHeader.DestinationIP = any(conn.OutsideDstIP).(IPv4)
	}

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
	now := t.Now()

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

func (t *Table[IP]) handleInboundTCP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now int64) (uintptr, error) {
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
	t.TCP.updateLastSeen(conn, now)

	// Rewrite packet to restore original addresses
	ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
	tcpHeader.DestinationPort = conn.LocalSrcPort

	// If this was a redirected connection, restore source to what client expects
	if conn.RewriteDestination {
		ipHeader.SourceIP = any(conn.LocalDstIp).(IPv4)
		tcpHeader.SourcePort = conn.LocalDstPort
	}

	// Update headers in packet
	ipHeader.Marshal(packet)
	tcpHeader.Marshal(packet, ipHeaderLen)

	// Recalculate TCP checksum
	tcpData := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcpData[16:18], 0) // Clear checksum
	checksum := calculateTCPChecksum(ipHeader.SourceIP, ipHeader.DestinationIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], checksum)

	// Check if this is a connection termination (FIN or RST)
	if tcpHeader.Flags&(TCPFlagFIN|TCPFlagRST) != 0 {
		// Mark connection for immediate removal on next cleanup
		conn.PendingSweep = true
	}

	return conn.Namespace, nil
}

func (t *Table[IP]) handleInboundUDP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now int64) (uintptr, error) {
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
	t.UDP.updateLastSeen(conn, now)

	// Rewrite packet to restore original addresses
	ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
	udpHeader.DestinationPort = conn.LocalSrcPort

	// If this was a redirected connection, restore source to what client expects
	if conn.RewriteDestination {
		ipHeader.SourceIP = any(conn.LocalDstIp).(IPv4)
		udpHeader.SourcePort = conn.LocalDstPort
	}

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

func (t *Table[IP]) handleInboundICMP(packet []byte, ipHeader *IPv4Header, ipHeaderLen int, now int64) (uintptr, error) {
	if len(packet) < ipHeaderLen+8 {
		return 0, fmt.Errorf("ICMP packet too small")
	}

	icmpType := packet[ipHeaderLen]

	switch icmpType {
	case ICMPTypeEchoReply, ICMPTypeEchoRequest:
		// Handle echo reply/request
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
		t.ICMP.updateLastSeen(conn, now)

		// Rewrite packet to restore original addresses and ID
		ipHeader.DestinationIP = any(conn.LocalSrcIP).(IPv4)
		icmpHeader.ID = conn.LocalSrcPort

		// If this was a redirected connection, restore source to what client expects
		if conn.RewriteDestination {
			ipHeader.SourceIP = any(conn.LocalDstIp).(IPv4)
		}

		// Update headers in packet
		ipHeader.Marshal(packet)
		icmpHeader.Marshal(packet, ipHeaderLen)

		// Recalculate ICMP checksum
		icmpData := packet[ipHeaderLen:]
		binary.BigEndian.PutUint16(icmpData[2:4], 0) // Clear checksum
		checksum := calculateICMPChecksum(icmpData)
		binary.BigEndian.PutUint16(icmpData[2:4], checksum)

		return conn.Namespace, nil

	case ICMPTypeDestinationUnreachable:
		// ICMP error contains embedded packet that triggered the error
		// We need to look at the embedded packet to find the original connection
		// TODO: Implement ICMP error handling
		return 0, ErrDropPacket

	default:
		// Unsupported ICMP type
		return 0, ErrDropPacket
	}
}

// RunMaintenance removes expired connections from the NAT table.
// This should be called periodically to clean up stale connections.
// Connections are considered expired based on configurable protocol-specific timeouts.
func (t *Table[IP]) RunMaintenance(now int64) {
	t.TCP.cleanupExpired(now, t.TCPTimeout)
	t.UDP.cleanupExpired(now, t.UDPTimeout)
	t.ICMP.cleanupExpired(now, t.ICMPTimeout)
}

// AddRedirectRule adds a rule to redirect traffic from one destination to another
// This method is specific to IPv4 tables
func (t *Table[IPv4]) AddRedirectRule(protocol uint8, dstIP IPv4, dstPort uint16, newDstIP IPv4, newDstPort uint16) {
	rule := RedirectRule[IPv4]{
		DstIP:      dstIP,
		DstPort:    dstPort,
		NewDstIP:   newDstIP,
		NewDstPort: newDstPort,
	}

	switch protocol {
	case ProtocolTCP:
		t.TCP.mutex.Lock()
		t.TCP.redirectRules = append(t.TCP.redirectRules, rule)
		t.TCP.mutex.Unlock()
	case ProtocolUDP:
		t.UDP.mutex.Lock()
		t.UDP.redirectRules = append(t.UDP.redirectRules, rule)
		t.UDP.mutex.Unlock()
	case ProtocolICMP:
		t.ICMP.mutex.Lock()
		t.ICMP.redirectRules = append(t.ICMP.redirectRules, rule)
		t.ICMP.mutex.Unlock()
	}
}

// AddDropRule adds a rule to drop traffic to a specific port
// This method is specific to IPv4 tables
func (t *Table[IPv4]) AddDropRule(protocol uint8, dstPort uint16) {
	rule := DropRule{DstPort: dstPort}

	switch protocol {
	case ProtocolTCP:
		t.TCP.mutex.Lock()
		t.TCP.dropRules = append(t.TCP.dropRules, rule)
		t.TCP.mutex.Unlock()
	case ProtocolUDP:
		t.UDP.mutex.Lock()
		t.UDP.dropRules = append(t.UDP.dropRules, rule)
		t.UDP.mutex.Unlock()
	}
}
