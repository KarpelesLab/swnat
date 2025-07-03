package swnat

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

func BenchmarkParseIPv4Header(b *testing.B) {
	packet := make([]byte, 60)
	packet[0] = 0x45 // Version 4, IHL 5
	packet[9] = 6    // TCP
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIPv4Header(packet)
	}
}

func BenchmarkParseTCPHeader(b *testing.B) {
	packet := make([]byte, 40)
	packet[0] = 0x45 // Version 4, IHL 5
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseTCPHeader(packet, 20)
	}
}

func BenchmarkIPv4ToString(b *testing.B) {
	ip := IPv4{192, 168, 1, 1}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ip.String()
	}
}

func BenchmarkParseIPv4(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIPv4("192.168.1.1")
	}
}

func BenchmarkHandleOutboundPacket(b *testing.B) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	// Pre-create packets
	packets := make([][]byte, 100)
	for i := range packets {
		srcIP := IPv4{192, 168, 1, byte(i)}
		dstIP := IPv4{8, 8, 8, 8}
		packets[i] = CreateIPv4UDPPacket(srcIP, dstIP, uint16(10000+i), 53, nil)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := make([]byte, len(packets[i%100]))
		copy(packet, packets[i%100])
		table.HandleOutboundPacket(packet, uintptr(i%10))
	}
}

func BenchmarkHandleInboundPacket(b *testing.B) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	// Setup connections first
	setupPackets := make([][]byte, 100)
	
	for i := 0; i < 100; i++ {
		srcIP := IPv4{192, 168, 1, byte(i)}
		dstIP := IPv4{8, 8, 8, 8}
		packet := CreateIPv4UDPPacket(srcIP, dstIP, uint16(10000+i), 53, nil)
		
		// Process to create NAT mapping
		table.HandleOutboundPacket(packet, uintptr(i%10))
		
		// Extract NAT info and create inbound packet
		header, _ := ParseIPv4Header(packet)
		udp, _ := ParseUDPHeader(packet, 20)
		
		setupPackets[i] = CreateIPv4UDPPacket(dstIP, header.SourceIP, 53, udp.SourcePort, nil)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := make([]byte, len(setupPackets[i%100]))
		copy(packet, setupPackets[i%100])
		table.HandleInboundPacket(packet)
	}
}

func BenchmarkConcurrentNAT(b *testing.B) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		
		for pb.Next() {
			// Create random packet
			srcIP := IPv4{192, 168, byte(r.Intn(256)), byte(r.Intn(256))}
			dstIP := IPv4{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))}
			srcPort := uint16(r.Intn(65536))
			dstPort := uint16(r.Intn(65536))
			
			packet := CreateIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, nil)
			table.HandleOutboundPacket(packet, uintptr(r.Intn(100)))
		}
	})
}

func BenchmarkCleanup(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			publicIP := net.ParseIP("1.2.3.4")
			
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				
				// Setup table with connections
				table := NewIPv4(publicIP)
				ipv4Table := table.(*Table[IPv4])
				ipv4Table.UDPTimeout = 1 // Very short timeout
				
				for j := 0; j < size; j++ {
					srcIP := IPv4{192, 168, byte(j >> 8), byte(j & 0xFF)}
					dstIP := IPv4{8, 8, 8, 8}
					packet := CreateIPv4UDPPacket(srcIP, dstIP, uint16(10000+j), 53, nil)
					table.HandleOutboundPacket(packet, uintptr(j%10))
				}
				
				// Let connections expire
				time.Sleep(2 * time.Second)
				
				b.StartTimer()
				table.Cleanup(time.Now().Unix())
			}
		})
	}
}

func BenchmarkPacketCreation(b *testing.B) {
	srcIP := IPv4{192, 168, 1, 1}
	dstIP := IPv4{8, 8, 8, 8}
	
	b.Run("UDP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = CreateIPv4UDPPacket(srcIP, dstIP, 5000, 53, []byte("test"))
		}
	})
	
	b.Run("TCP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = CreateIPv4TCPPacket(srcIP, dstIP, 5000, 80, TCPFlagSYN)
		}
	})
	
	b.Run("ICMP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = CreateIPv4ICMPPacket(srcIP, dstIP, ICMPTypeEchoRequest, 0, 1234, 1)
		}
	})
}

func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("10k-connections", func(b *testing.B) {
		publicIP := net.ParseIP("1.2.3.4")
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			
			table := NewIPv4(publicIP)
			
			// Create 10k connections
			for j := 0; j < 10000; j++ {
				srcIP := IPv4{192, 168, byte(j >> 8), byte(j & 0xFF)}
				dstIP := IPv4{8, 8, 8, 8}
				packet := CreateIPv4UDPPacket(srcIP, dstIP, uint16(10000+(j%1000)), 53, nil)
				table.HandleOutboundPacket(packet, uintptr(j%100))
			}
			
			b.StartTimer()
			// Measure cleanup time
			table.Cleanup(time.Now().Unix())
		}
	})
}

func BenchmarkChecksumCalculation(b *testing.B) {
	header := make([]byte, 20)
	header[0] = 0x45 // Version 4, IHL 5
	
	b.Run("IPv4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = calculateIPv4Checksum(header)
		}
	})
	
	tcpData := make([]byte, 40)
	srcIP := IPv4{192, 168, 1, 1}
	dstIP := IPv4{8, 8, 8, 8}
	
	b.Run("TCP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = calculateTCPChecksum(srcIP, dstIP, tcpData)
		}
	})
	
	udpData := make([]byte, 20)
	
	b.Run("UDP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = calculateUDPChecksum(srcIP, dstIP, udpData)
		}
	})
}

func BenchmarkTableOperations(b *testing.B) {
	publicIP := net.ParseIP("1.2.3.4")
	table := NewIPv4(publicIP)
	ipv4Table := table.(*Table[IPv4])
	
	b.Run("AddRedirectRule", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ipv4Table.AddRedirectRule(ProtocolTCP, IPv4{1, 1, 1, 1}, uint16(8080+i%100), IPv4{10, 0, 0, 1}, 80)
		}
	})
	
	b.Run("AddDropRule", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ipv4Table.AddDropRule(ProtocolTCP, uint16(1000+i%100))
		}
	})
}