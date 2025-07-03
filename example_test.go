package swnat_test

import (
	"fmt"
	"net"

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
