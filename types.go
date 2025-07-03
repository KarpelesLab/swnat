package swnat

import "sync"

type (
	IPv4 [4]byte
	IPv6 [16]byte
)

type NAT interface {
	HandleOutboundPacket(packet []byte, namespace uintptr) error
	HandleInboundPacket(packet []byte) (uintptr, error)
	RunMaintenance(now int64)
}

type Conn[IP comparable] struct {
	LastSeen  int64
	Protocol  uint8 // ICMP, TCP, UDP
	Namespace uintptr

	LocalSrcIP   IP
	LocalSrcPort uint16
	LocalDstIp   IP
	LocalDstPort uint16

	OutsideSrcIP   IP
	OutsideSrcPort uint16
	OutsideDstIP   IP
	OutsideDstPort uint16

	// special flags
	RewriteDestination bool
	PendingSweep       bool // Mark connection for immediate removal (e.g. TCP FIN/RST)
}

type ExternalKey[IP comparable] struct {
	SrcIP, DstIP     IP
	SrcPort, DstPort uint16
}
type InternalKey[IP comparable] struct {
	SrcIP, DstIP     IP
	SrcPort, DstPort uint16
	Namespace        uintptr
}

// RedirectRule defines a rule for redirecting traffic
type RedirectRule[IP comparable] struct {
	DstIP      IP
	DstPort    uint16
	NewDstIP   IP
	NewDstPort uint16
}

// DropRule defines a rule for dropping traffic to specific ports
type DropRule struct {
	DstPort uint16
}

type Pair[IP comparable] struct {
	mutex         sync.RWMutex
	in            map[ExternalKey[IP]]*Conn[IP]
	out           map[InternalKey[IP]]*Conn[IP]
	redirectRules []RedirectRule[IP]
	dropRules     []DropRule
}
