package swnat_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KarpelesLab/swnat"
)

func TestEndToEndUDPSession(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	
	client1 := swnat.IPv4{192, 168, 1, 100}
	client2 := swnat.IPv4{192, 168, 1, 101}
	server := swnat.IPv4{8, 8, 8, 8}
	
	// Client 1 -> Server
	req1 := swnat.CreateIPv4UDPPacket(client1, server, 5000, 53, []byte("query1"))
	err := table.HandleOutboundPacket(req1, 1) // namespace 1
	if err != nil {
		t.Fatalf("Client1 outbound failed: %v", err)
	}
	
	// Extract NAT details
	header1, _ := swnat.ParseIPv4Header(req1)
	udp1, _ := swnat.ParseUDPHeader(req1, 20)
	natIP1 := header1.SourceIP
	natPort1 := udp1.SourcePort
	
	// Client 2 -> Server (same destination)
	req2 := swnat.CreateIPv4UDPPacket(client2, server, 5000, 53, []byte("query2"))
	err = table.HandleOutboundPacket(req2, 2) // namespace 2
	if err != nil {
		t.Fatalf("Client2 outbound failed: %v", err)
	}
	
	// Extract NAT details
	_, _ = swnat.ParseIPv4Header(req2)
	udp2, _ := swnat.ParseUDPHeader(req2, 20)
	natPort2 := udp2.SourcePort
	
	// Verify different NAT ports
	if natPort1 == natPort2 {
		t.Error("Clients should have different NAT ports")
	}
	
	// Server -> Client 1
	resp1 := swnat.CreateIPv4UDPPacket(server, natIP1, 53, natPort1, []byte("response1"))
	namespace, err := table.HandleInboundPacket(resp1)
	if err != nil {
		t.Fatalf("Response to client1 failed: %v", err)
	}
	if namespace != 1 {
		t.Errorf("Expected namespace 1, got %d", namespace)
	}
	
	// Verify correct translation
	header, _ := swnat.ParseIPv4Header(resp1)
	udp, _ := swnat.ParseUDPHeader(resp1, 20)
	if !header.DestinationIP.Equal(client1) {
		t.Errorf("Response routed to wrong client: got %v, want %v", header.DestinationIP, client1)
	}
	if udp.DestinationPort != 5000 {
		t.Errorf("Wrong destination port: got %d, want 5000", udp.DestinationPort)
	}
	
	// Server -> Client 2
	resp2 := swnat.CreateIPv4UDPPacket(server, natIP1, 53, natPort2, []byte("response2"))
	namespace, err = table.HandleInboundPacket(resp2)
	if err != nil {
		t.Fatalf("Response to client2 failed: %v", err)
	}
	if namespace != 2 {
		t.Errorf("Expected namespace 2, got %d", namespace)
	}
	
	header, _ = swnat.ParseIPv4Header(resp2)
	if !header.DestinationIP.Equal(client2) {
		t.Errorf("Response routed to wrong client: got %v, want %v", header.DestinationIP, client2)
	}
}

func TestMultipleNamespaces(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	ipv4Table := table.(*swnat.Table[swnat.IPv4])
	
	// Set different limits for namespaces
	ipv4Table.MaxConnPerNamespace = 2
	
	client := swnat.IPv4{192, 168, 1, 100}
	servers := []swnat.IPv4{
		{1, 1, 1, 1},
		{8, 8, 8, 8},
		{9, 9, 9, 9},
	}
	
	// Limited namespace - should allow only 2 connections, 3rd will evict oldest
	for i, server := range servers[:3] {
		packet := swnat.CreateIPv4UDPPacket(client, server, uint16(5000+i), 80, nil)
		err := table.HandleOutboundPacket(packet, 10) // namespace 10
		
		if err != nil {
			t.Errorf("Limited namespace connection %d failed: %v", i, err)
		}
	}
	
	// Different namespace - should allow connections
	for i, server := range servers {
		packet := swnat.CreateIPv4UDPPacket(client, server, uint16(6000+i), 80, nil)
		err := table.HandleOutboundPacket(packet, 20) // namespace 20
		if err != nil {
			t.Errorf("Different namespace connection %d failed: %v", i, err)
		}
	}
}

func TestConnectionPersistence(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	
	client := swnat.IPv4{192, 168, 1, 100}
	server := swnat.IPv4{8, 8, 8, 8}
	
	// Establish connection
	packet := swnat.CreateIPv4UDPPacket(client, server, 5000, 53, []byte("initial"))
	table.HandleOutboundPacket(packet, 1)
	
	header, _ := swnat.ParseIPv4Header(packet)
	udp, _ := swnat.ParseUDPHeader(packet, 20)
	natIP := header.SourceIP
	natPort := udp.SourcePort
	
	// Send multiple packets through same connection
	for i := 0; i < 10; i++ {
		// Outbound
		out := swnat.CreateIPv4UDPPacket(client, server, 5000, 53, []byte("data"))
		table.HandleOutboundPacket(out, 1)
		
		h, _ := swnat.ParseIPv4Header(out)
		u, _ := swnat.ParseUDPHeader(out, 20)
		
		// Verify same NAT mapping
		if !h.SourceIP.Equal(natIP) {
			t.Error("NAT IP changed unexpectedly")
		}
		if u.SourcePort != natPort {
			t.Error("NAT port changed unexpectedly")
		}
		
		// Inbound
		in := swnat.CreateIPv4UDPPacket(server, natIP, 53, natPort, []byte("reply"))
		table.HandleInboundPacket(in)
		
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHighConcurrency(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	
	var (
		successCount int64
		errorCount   int64
		wg           sync.WaitGroup
	)
	
	// 50 concurrent clients
	for c := 0; c < 50; c++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			
			client := swnat.IPv4{192, 168, 1, byte(clientID)}
			
			// Each client makes 20 connections
			for i := 0; i < 20; i++ {
				server := swnat.IPv4{10, 0, 0, byte(i)}
				
				// Outbound
				packet := swnat.CreateIPv4UDPPacket(client, server, uint16(10000+i), 80, []byte("test"))
				packet2 := make([]byte, len(packet))
				copy(packet2, packet)
				
				err := table.HandleOutboundPacket(packet, uintptr(clientID))
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					continue
				}
				
				// Extract NAT info
				header, _ := swnat.ParseIPv4Header(packet)
				udp, _ := swnat.ParseUDPHeader(packet, 20)
				
				// Inbound response
				response := swnat.CreateIPv4UDPPacket(server, header.SourceIP, 80, udp.SourcePort, []byte("response"))
				_, err = table.HandleInboundPacket(response)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					continue
				}
				
				atomic.AddInt64(&successCount, 1)
			}
		}(c)
	}
	
	wg.Wait()
	
	t.Logf("Concurrent test: %d successful, %d errors", successCount, errorCount)
	if errorCount > 0 {
		t.Errorf("Concurrent operations had %d errors", errorCount)
	}
	if successCount != 1000 { // 50 clients * 20 connections
		t.Errorf("Expected 1000 successful operations, got %d", successCount)
	}
}

func TestConnectionExpiry(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	ipv4Table := table.(*swnat.Table[swnat.IPv4])
	
	// Set very short timeout for testing
	ipv4Table.UDPTimeout = 1 // 1 second
	
	client := swnat.IPv4{192, 168, 1, 100}
	server := swnat.IPv4{8, 8, 8, 8}
	
	// Create connection
	packet := swnat.CreateIPv4UDPPacket(client, server, 5000, 53, []byte("test"))
	table.HandleOutboundPacket(packet, 1)
	
	header, _ := swnat.ParseIPv4Header(packet)
	udp, _ := swnat.ParseUDPHeader(packet, 20)
	
	// Immediate response should work
	response := swnat.CreateIPv4UDPPacket(server, header.SourceIP, 53, udp.SourcePort, []byte("immediate"))
	_, err := table.HandleInboundPacket(response)
	if err != nil {
		t.Error("Immediate response failed")
	}
	
	// Wait for expiry
	time.Sleep(2 * time.Second)
	table.RunMaintenance(time.Now().Unix())
	
	// Late response should fail
	lateResponse := swnat.CreateIPv4UDPPacket(server, header.SourceIP, 53, udp.SourcePort, []byte("late"))
	_, err = table.HandleInboundPacket(lateResponse)
	if err == nil {
		t.Error("Late response should fail after connection expiry")
	}
}

func TestPortExhaustion(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	
	client := swnat.IPv4{192, 168, 1, 100}
	
	// Track allocated ports
	allocatedPorts := make(map[uint16]bool)
	var mu sync.Mutex
	
	// Try to exhaust port space (this test is limited to prevent long runtime)
	maxAttempts := 1000
	for i := 0; i < maxAttempts; i++ {
		server := swnat.IPv4{10, 0, byte(i >> 8), byte(i & 0xFF)}
		packet := swnat.CreateIPv4UDPPacket(client, server, 5000, 80, nil)
		
		err := table.HandleOutboundPacket(packet, 1)
		if err != nil {
			t.Logf("Port allocation failed at attempt %d: %v", i, err)
			break
		}
		
		// Track allocated port
		udp, _ := swnat.ParseUDPHeader(packet, 20)
		mu.Lock()
		if allocatedPorts[udp.SourcePort] {
			t.Errorf("Port %d allocated twice", udp.SourcePort)
		}
		allocatedPorts[udp.SourcePort] = true
		mu.Unlock()
	}
	
	t.Logf("Successfully allocated %d unique ports", len(allocatedPorts))
}

func TestComplexScenario(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	ipv4Table := table.(*swnat.Table[swnat.IPv4])
	
	// Configure table
	ipv4Table.MaxConnPerNamespace = 10
	ipv4Table.UDPTimeout = 30
	ipv4Table.TCPTimeout = 300
	
	// Add drop rule
	ipv4Table.AddDropRule(swnat.ProtocolTCP, 25)
	
	// Test premium namespace
	premium := swnat.IPv4{192, 168, 1, 10}
	for i := 0; i < 20; i++ {
		packet := swnat.CreateIPv4UDPPacket(premium, swnat.IPv4{1, 1, 1, 1}, uint16(10000+i), 80, nil)
		err := table.HandleOutboundPacket(packet, 100) // premium namespace
		if err != nil && i < 10 {
			t.Errorf("Premium connection %d failed: %v", i, err)
		}
	}
	
	// Test basic namespace with limits
	basic := swnat.IPv4{192, 168, 1, 20}
	for i := 0; i < 15; i++ {
		packet := swnat.CreateIPv4UDPPacket(basic, swnat.IPv4{2, 2, 2, 2}, uint16(10000+i), 80, nil)
		err := table.HandleOutboundPacket(packet, 200) // basic namespace
		if err != nil && i < 10 {
			t.Errorf("Basic connection %d failed: %v", i, err)
		}
	}
	
	// Test SMTP blocking
	packet := swnat.CreateIPv4TCPPacket(premium, swnat.IPv4{3, 3, 3, 3}, 10000, 25, swnat.TCPFlagSYN)
	err := table.HandleOutboundPacket(packet, 100)
	if err != swnat.ErrDropPacket {
		t.Error("SMTP connection should be blocked")
	}
	
	// Verify active connections
	table.RunMaintenance(time.Now().Unix())
	t.Log("Maintenance completed")
}

func TestChecksumValidation(t *testing.T) {
	publicIP := net.ParseIP("1.2.3.4")
	table := swnat.NewIPv4(publicIP)
	
	client := swnat.IPv4{192, 168, 1, 100}
	server := swnat.IPv4{8, 8, 8, 8}
	
	// Create packet with valid checksums
	packet := swnat.CreateIPv4UDPPacket(client, server, 5000, 53, []byte("test"))
	originalPayload := make([]byte, 4)
	copy(originalPayload, packet[28:32])
	
	// Process packet
	err := table.HandleOutboundPacket(packet, 1)
	if err != nil {
		t.Fatalf("Failed to process packet: %v", err)
	}
	
	// Verify checksums are correct
	if !swnat.VerifyIPv4Checksum(packet) {
		t.Error("Invalid IP checksum after NAT")
	}
	
	if !swnat.VerifyUDPChecksum(packet) {
		t.Error("Invalid UDP checksum after NAT")
	}
	
	// Verify packet payload is preserved
	currentPayload := packet[28:32]
	for i := range originalPayload {
		if currentPayload[i] != originalPayload[i] {
			t.Error("Packet payload was modified")
			break
		}
	}
}