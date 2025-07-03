package swnat

type Table[IP comparable] struct {
	TCP  Pair[IP]
	UDP  Pair[IP]
	ICMP Pair[IP]
}

func NewIPv4() NAT {
	return &Table[IPv4]{}
}

func (t *Table[IP]) HandleOutboundPacket(packet []byte, namespace uintptr) error {
	// TODO
	return nil
}

func (t *Table[IP]) HandleInboundPacket(packet []byte) (uintptr, error) {
	// TODO
	return 0, nil
}
