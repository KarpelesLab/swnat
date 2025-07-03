package swnat

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewIPv4Table(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	if table == nil {
		t.Fatal("NewIPv4() returned nil")
	}
	
	ipv4Table, ok := table.(*Table[IPv4])
	if !ok {
		t.Fatal("NewIPv4() did not return *Table[IPv4]")
	}
	
	if ipv4Table.externalIP.IsZero() {
		t.Error("External IP should not be zero")
	}
}

func TestIPv4TableBasicNAT(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{8, 8, 8, 8}
	
	// Create outbound UDP packet
	outPacket := CreateIPv4UDPPacket(localIP, remoteIP, 5000, 53, []byte("test"))
	
	// Process outbound
	err := table.HandleOutboundPacket(outPacket, 1) // namespace = 1
	if err != nil {
		t.Fatalf("HandleOutboundPacket failed: %v", err)
	}
	
	// Verify source IP was changed
	header, _ := ParseIPv4Header(outPacket)
	if header.SourceIP.Equal(localIP) {
		t.Error("Source IP was not modified")
	}
	
	// Get the NAT port
	udpHeader, _ := ParseUDPHeader(outPacket, 20)
	natPort := udpHeader.SourcePort
	
	// Create inbound response
	inPacket := CreateIPv4UDPPacket(remoteIP, header.SourceIP, 53, natPort, []byte("response"))
	
	// Process inbound
	namespace, err := table.HandleInboundPacket(inPacket)
	if err != nil {
		t.Fatalf("HandleInboundPacket failed: %v", err)
	}
	if namespace != 1 {
		t.Errorf("Expected namespace 1, got %d", namespace)
	}
	
	// Verify destination was changed back
	header, _ = ParseIPv4Header(inPacket)
	if !header.DestinationIP.Equal(localIP) {
		t.Errorf("Destination IP not restored: got %v, want %v", header.DestinationIP, localIP)
	}
	
	udpHeader, _ = ParseUDPHeader(inPacket, 20)
	if udpHeader.DestinationPort != 5000 {
		t.Errorf("Destination port not restored: got %d, want 5000", udpHeader.DestinationPort)
	}
}

func TestIPv4TableTCPConnection(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{1, 1, 1, 1}
	
	// SYN packet
	synPacket := CreateIPv4TCPPacket(localIP, remoteIP, 45000, 80, TCPFlagSYN)
	
	err := table.HandleOutboundPacket(synPacket, 1)
	if err != nil {
		t.Fatalf("HandleOutboundPacket (SYN) failed: %v", err)
	}
	
	// Get NAT port
	header, _ := ParseIPv4Header(synPacket)
	tcpHeader, _ := ParseTCPHeader(synPacket, 20)
	natPort := tcpHeader.SourcePort
	
	// SYN-ACK response
	synAckPacket := CreateIPv4TCPPacket(remoteIP, header.SourceIP, 80, natPort, TCPFlagSYN|TCPFlagACK)
	
	namespace, err := table.HandleInboundPacket(synAckPacket)
	if err != nil {
		t.Fatalf("HandleInboundPacket (SYN-ACK) failed: %v", err)
	}
	if namespace != 1 {
		t.Errorf("Expected namespace 1, got %d", namespace)
	}
}

func TestIPv4TableICMP(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{8, 8, 8, 8}
	
	// Create ICMP echo request
	packet := CreateIPv4ICMPPacket(localIP, remoteIP, ICMPTypeEchoRequest, 0, 1234, 1)
	
	// Process outbound
	err := table.HandleOutboundPacket(packet, 1)
	if err != nil {
		t.Fatalf("HandleOutboundPacket (ICMP) failed: %v", err)
	}
	
	// Get the NAT ID
	header, _ := ParseIPv4Header(packet)
	icmpHeader, _ := ParseICMPHeader(packet, 20)
	natID := icmpHeader.ID
	
	// Create echo reply
	reply := CreateIPv4ICMPPacket(remoteIP, header.SourceIP, ICMPTypeEchoReply, 0, natID, 1)
	
	// Process inbound
	namespace, err := table.HandleInboundPacket(reply)
	if err != nil {
		t.Fatalf("HandleInboundPacket (ICMP) failed: %v", err)
	}
	if namespace != 1 {
		t.Errorf("Expected namespace 1, got %d", namespace)
	}
}

func TestIPv4TableNamespaceLimit(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	ipv4Table := table.(*Table[IPv4])
	
	// Set low limit for testing
	ipv4Table.MaxConnPerNamespace = 5
	
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{8, 8, 8, 8}
	
	// Create connections up to the limit
	for i := 0; i < 5; i++ {
		packet := CreateIPv4UDPPacket(localIP, remoteIP, uint16(5000+i), 53, []byte("test"))
		err := table.HandleOutboundPacket(packet, 2) // namespace = 2
		if err != nil {
			t.Fatalf("Connection %d failed: %v", i, err)
		}
	}
	
	// 6th connection should succeed but remove oldest
	packet := CreateIPv4UDPPacket(localIP, remoteIP, 5005, 53, []byte("test"))
	err := table.HandleOutboundPacket(packet, 2)
	if err != nil {
		t.Errorf("6th connection failed: %v", err)
	}
}

func TestIPv4TableRedirection(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	ipv4Table := table.(*Table[IPv4])
	
	// Add redirection rule
	redirectIP := IPv4{10, 0, 0, 1}
	ipv4Table.AddRedirectRule(ProtocolTCP, IPv4{1, 1, 1, 1}, 8080, redirectIP, 80)
	
	localIP := IPv4{192, 168, 1, 100}
	originalDstIP := IPv4{1, 1, 1, 1}
	
	// Create packet to port 8080
	packet := CreateIPv4TCPPacket(localIP, originalDstIP, 45000, 8080, TCPFlagSYN)
	
	err := table.HandleOutboundPacket(packet, 1)
	if err != nil {
		t.Fatalf("HandleOutboundPacket failed: %v", err)
	}
	
	// Verify destination was changed
	header, _ := ParseIPv4Header(packet)
	tcpHeader, _ := ParseTCPHeader(packet, 20)
	
	if !header.DestinationIP.Equal(redirectIP) {
		t.Errorf("Destination IP not redirected: got %v, want %v", header.DestinationIP, redirectIP)
	}
	if tcpHeader.DestinationPort != 80 {
		t.Errorf("Destination port not redirected: got %d, want 80", tcpHeader.DestinationPort)
	}
}

func TestIPv4TableDropRule(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	ipv4Table := table.(*Table[IPv4])
	
	// Add drop rule for port 22
	ipv4Table.AddDropRule(ProtocolTCP, 22)
	
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{1, 1, 1, 1}
	
	// Try to connect to port 22 (should be dropped)
	packet := CreateIPv4TCPPacket(localIP, remoteIP, 45000, 22, TCPFlagSYN)
	err := table.HandleOutboundPacket(packet, 1)
	if err != ErrDropPacket {
		t.Errorf("Expected ErrDropPacket, got %v", err)
	}
	
	// Try to connect to port 80 (should succeed)
	packet = CreateIPv4TCPPacket(localIP, remoteIP, 45000, 80, TCPFlagSYN)
	err = table.HandleOutboundPacket(packet, 1)
	if err != nil {
		t.Errorf("Packet to port 80 should not be dropped: %v", err)
	}
}

func TestIPv4TableMaintenance(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	ipv4Table := table.(*Table[IPv4])
	
	// Set very short timeout
	ipv4Table.UDPTimeout = 1 // 1 second
	
	// Create a connection
	localIP := IPv4{192, 168, 1, 100}
	remoteIP := IPv4{8, 8, 8, 8}
	packet := CreateIPv4UDPPacket(localIP, remoteIP, 5000, 53, []byte("test"))
	
	table.HandleOutboundPacket(packet, 1)
	
	// Wait for expiration
	time.Sleep(2 * time.Second)
	
	// Run maintenance
	now := time.Now().Unix()
	table.RunMaintenance(now)
	
	// Try to send inbound packet - should fail
	header, _ := ParseIPv4Header(packet)
	udpHeader, _ := ParseUDPHeader(packet, 20)
	response := CreateIPv4UDPPacket(remoteIP, header.SourceIP, 53, udpHeader.SourcePort, []byte("late"))
	
	_, err := table.HandleInboundPacket(response)
	if err == nil {
		t.Error("Expected error for expired connection")
	}
}

func TestIPv4TableConcurrency(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Simulate concurrent connections
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			localIP := IPv4{192, 168, 1, byte(id)}
			remoteIP := IPv4{8, 8, 8, 8}
			
			for j := 0; j < 10; j++ {
				// Outbound
				packet := CreateIPv4UDPPacket(localIP, remoteIP, uint16(5000+j), 53, []byte("test"))
				err := table.HandleOutboundPacket(packet, uintptr(id))
				if err != nil {
					errors <- err
					return
				}
				
				// Inbound response
				header, _ := ParseIPv4Header(packet)
				udpHeader, _ := ParseUDPHeader(packet, 20)
				response := CreateIPv4UDPPacket(remoteIP, header.SourceIP, 53, udpHeader.SourcePort, []byte("response"))
				_, err = table.HandleInboundPacket(response)
				if err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}
	
	// Run cleanup concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			table.RunMaintenance(time.Now().Unix())
			time.Sleep(10 * time.Millisecond)
		}
	}()
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

func TestIPv4TableInvalidPackets(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "too short",
			packet: []byte{0x45},
		},
		{
			name:   "invalid IP version",
			packet: append([]byte{0x65}, make([]byte, 19)...), // Version 6
		},
		{
			name:   "unsupported protocol",
			packet: func() []byte {
				p := make([]byte, 20)
				p[0] = 0x45
				p[9] = 99 // Unknown protocol
				return p
			}(),
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := table.HandleOutboundPacket(tt.packet, 1)
			if err == nil {
				t.Error("Expected error for invalid packet")
			}
		})
	}
}

func TestChecksumValidation(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	client := IPv4{192, 168, 1, 100}
	server := IPv4{8, 8, 8, 8}
	
	// Create packet with valid checksums
	packet := CreateIPv4UDPPacket(client, server, 5000, 53, []byte("test"))
	
	// Process packet
	err := table.HandleOutboundPacket(packet, 1)
	if err != nil {
		t.Fatalf("Failed to process packet: %v", err)
	}
	
	// Verify checksums are correct
	if !VerifyIPv4Checksum(packet) {
		t.Error("Invalid IP checksum after NAT")
	}
	
	if !VerifyUDPChecksum(packet) {
		t.Error("Invalid UDP checksum after NAT")
	}
}