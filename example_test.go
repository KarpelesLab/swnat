package swnat_test

import (
	"fmt"
	"net"
	"time"

	"github.com/KarpelesLab/swnat"
)

func ExampleTable() {
	// Create a new IPv4 NAT table with external IP
	externalIP := net.ParseIP("192.168.1.1")
	nat := swnat.NewIPv4(externalIP)

	// Example packet (simplified for demonstration)
	// In real usage, this would be an actual IP packet
	packet := make([]byte, 1500)

	// Namespace identifier for the source
	namespace := uintptr(1)

	// Handle outbound packet
	err := nat.HandleOutboundPacket(packet, namespace)
	if err == swnat.ErrDropPacket {
		fmt.Println("Packet dropped by NAT")
		return
	} else if err != nil {
		fmt.Printf("Error processing packet: %v\n", err)
		return
	}

	// Packet has been modified and can be forwarded

	// For inbound packets (return traffic)
	returnNamespace, err := nat.HandleInboundPacket(packet)
	if err == swnat.ErrDropPacket {
		fmt.Println("Inbound packet has no matching connection")
		return
	} else if err != nil {
		fmt.Printf("Error processing inbound packet: %v\n", err)
		return
	}

	fmt.Printf("Return packet belongs to namespace: %d\n", returnNamespace)
}

func ExampleTable_Cleanup() {
	// Create a new IPv4 NAT table
	externalIP := net.ParseIP("192.168.1.1")
	nat := swnat.NewIPv4(externalIP)

	// Perform regular cleanup of expired connections
	currentTime := time.Now().Unix()
	nat.Cleanup(currentTime)

	// For performance optimization, you can provide a custom time source
	if table, ok := nat.(*swnat.Table[swnat.IPv4]); ok {
		// Use a cached time value that updates less frequently
		table.Now = func() int64 { return currentTime }
	}
}

func ExampleTable_MaxConnPerNamespace() {
	// Create a new IPv4 NAT table
	externalIP := net.ParseIP("192.168.1.1")
	nat := swnat.NewIPv4(externalIP)

	// Configure connection limits
	if table, ok := nat.(*swnat.Table[swnat.IPv4]); ok {
		// Increase the maximum connections per namespace from default 200 to 500
		table.MaxConnPerNamespace = 500
	}

	// The NAT will now allow up to 500 connections per namespace
	// When this limit is reached, the oldest connection will be evicted
}
