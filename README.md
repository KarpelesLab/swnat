# swnat - Software NAT Library for Go

[![GoDoc](https://godoc.org/github.com/KarpelesLab/swnat?status.svg)](https://godoc.org/github.com/KarpelesLab/swnat)

A pure Go implementation of a software NAT (Network Address Translation) engine with support for TCP, UDP, and ICMP protocols.

## Features

- IPv4 support (with IPv6 structure ready for future implementation)
- TCP, UDP, and ICMP protocol handling
- Connection tracking with state management
- Namespace isolation support
- Thread-safe connection management
- Automatic port allocation for outbound connections
- Packet checksum recalculation
- Configurable time source for performance optimization
- Automatic cleanup of expired connections
- Per-namespace connection limits with LRU eviction
- TCP session state tracking (automatic cleanup on FIN/RST)
- Traffic filtering rules (drop packets to specific ports)
- Destination rewrite rules (redirect traffic to different IPs/ports)
- Configurable protocol timeouts

## Installation

```bash
go get github.com/KarpelesLab/swnat
```

## Usage

```go
package main

import (
    "log"
    "net"
    "time"
    "sync/atomic"
    "github.com/KarpelesLab/swnat"
)

func main() {
    // Create a new IPv4 NAT table with external IP
    externalIP := net.ParseIP("203.0.113.1")
    nat := swnat.NewIPv4(externalIP)
    
    // Process outbound packet
    packet := getPacketFromInterface() // Your packet capture logic
    namespace := uintptr(1) // Namespace identifier
    
    err := nat.HandleOutboundPacket(packet, namespace)
    if err == swnat.ErrDropPacket {
        // Packet should be dropped
        return
    } else if err != nil {
        log.Printf("Error processing packet: %v", err)
        return
    }
    
    // Packet has been modified and can be forwarded
    sendPacketToInterface(packet)
    
    // For inbound packets (return traffic)
    inboundPacket := getInboundPacket()
    returnNamespace, err := nat.HandleInboundPacket(inboundPacket)
    if err == swnat.ErrDropPacket {
        // No matching connection found
        return
    } else if err != nil {
        log.Printf("Error processing inbound packet: %v", err)
        return
    }
    
    // Route packet back to the correct namespace
    routeToNamespace(inboundPacket, returnNamespace)
    
    // Periodically cleanup expired connections
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        for now := range ticker.C {
            nat.RunMaintenance(now.Unix())
        }
    }()
}
```

### Performance Optimization

For high-performance scenarios, you can override the time source:

```go
// Use a custom time source that updates less frequently
var currentTime int64
go func() {
    for {
        atomic.StoreInt64(&currentTime, time.Now().Unix())
        time.Sleep(time.Second)
    }
}()

if table, ok := nat.(*swnat.Table[swnat.IPv4]); ok {
    table.Now = func() int64 { return atomic.LoadInt64(&currentTime) }
}
```

### Connection Limits

You can configure the maximum connections per namespace:

```go
if table, ok := nat.(*swnat.Table[swnat.IPv4]); ok {
    // Set maximum 500 connections per namespace
    table.MaxConnPerNamespace = 500
}
```

When the limit is reached, the oldest connection (by last activity) will be evicted to make room for new connections.

### Traffic Filtering and Redirection

```go
// Cast to access IPv4-specific methods
if table, ok := nat.(*swnat.Table[swnat.IPv4]); ok {
    // Drop all SMTP traffic (port 25)
    table.AddDropRule(swnat.ProtocolTCP, 25)
    
    // Redirect DNS traffic from 10.0.0.243:53 to 10.7.0.0:5353
    dnsOrigIP, _ := swnat.ParseIPv4("10.0.0.243")
    dnsNewIP, _ := swnat.ParseIPv4("10.7.0.0")
    table.AddRedirectRule(swnat.ProtocolUDP, dnsOrigIP, 53, dnsNewIP, 5353)
    
    // Configure custom timeouts
    table.TCPTimeout = 3600  // 1 hour
    table.UDPTimeout = 300   // 5 minutes
    table.ICMPTimeout = 60   // 1 minute
}
```

## How It Works

1. **Outbound Packets**: When a packet from inside the NAT needs to go out:
   - The library parses the packet headers (IP, TCP/UDP/ICMP)
   - Creates or updates a connection tracking entry
   - Rewrites source IP and port to the external IP and an allocated port
   - Recalculates checksums
   - Returns the modified packet ready for transmission

2. **Inbound Packets**: When a return packet arrives:
   - Looks up the connection based on destination port
   - Rewrites destination IP and port back to the original internal values
   - Recalculates checksums
   - Returns the namespace identifier for proper routing

3. **Connection Tracking**: The library maintains connection state for all active flows, allowing proper translation of return traffic.

4. **Connection Maintenance**: Expired connections are removed during periodic maintenance based on protocol-specific timeouts:
   - TCP: 24 hours (or immediately on next cleanup after FIN/RST)
   - UDP: 3 minutes  
   - ICMP: 30 seconds

5. **Connection Limits**: Each namespace has a configurable maximum connection limit (default: 200). When reached, the oldest connection is evicted using LRU policy.

## Architecture

- `Table[IP]`: Main NAT table structure (generic for IPv4/IPv6)
- `Pair[IP]`: Connection tracking storage with thread-safe operations
- `Conn[IP]`: Individual connection state
- Packet parsing and manipulation functions for each protocol

## Future Enhancements

- IPv6 support (structure already in place)
- Port forwarding/DNAT capabilities
- Connection statistics and monitoring
- ICMP error message handling (Type 3 - Destination Unreachable)
- Connection state tracking (SYN, ESTABLISHED, etc.)

## License

See LICENSE file for details.