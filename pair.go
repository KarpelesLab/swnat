package swnat

func (p *Pair[IP]) init() {
	p.in = make(map[ExternalKey[IP]]*Conn[IP])
	p.out = make(map[InternalKey[IP]]*Conn[IP])
}

func (p *Pair[IP]) lookupOutbound(key InternalKey[IP]) *Conn[IP] {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.out[key]
}

func (p *Pair[IP]) lookupInbound(key ExternalKey[IP]) *Conn[IP] {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.in[key]
}

func (p *Pair[IP]) addConnection(conn *Conn[IP], maxPerNamespace int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if we need to evict old connections from this namespace
	if maxPerNamespace > 0 {
		count := 0
		var oldest *Conn[IP]
		var oldestKey InternalKey[IP]

		// Count connections in this namespace and find oldest
		for key, c := range p.out {
			if key.Namespace == conn.Namespace && !c.PendingSweep {
				count++
				if oldest == nil || c.LastSeen < oldest.LastSeen {
					oldest = c
					oldestKey = key
				}
			}
		}

		// If we're at the limit, remove the oldest connection
		if count >= maxPerNamespace && oldest != nil {
			externalKey := ExternalKey[IP]{
				SrcIP:   oldest.OutsideDstIP,
				DstIP:   oldest.OutsideSrcIP,
				SrcPort: oldest.OutsideDstPort,
				DstPort: oldest.OutsideSrcPort,
			}
			delete(p.out, oldestKey)
			delete(p.in, externalKey)
		}
	}

	// Create keys
	internalKey := InternalKey[IP]{
		SrcIP:     conn.LocalSrcIP,
		DstIP:     conn.LocalDstIp,
		SrcPort:   conn.LocalSrcPort,
		DstPort:   conn.LocalDstPort,
		Namespace: conn.Namespace,
	}

	externalKey := ExternalKey[IP]{
		SrcIP:   conn.OutsideDstIP,
		DstIP:   conn.OutsideSrcIP,
		SrcPort: conn.OutsideDstPort,
		DstPort: conn.OutsideSrcPort,
	}

	p.out[internalKey] = conn
	p.in[externalKey] = conn
}

func (p *Pair[IP]) removeConnection(conn *Conn[IP]) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Create keys
	internalKey := InternalKey[IP]{
		SrcIP:     conn.LocalSrcIP,
		DstIP:     conn.LocalDstIp,
		SrcPort:   conn.LocalSrcPort,
		DstPort:   conn.LocalDstPort,
		Namespace: conn.Namespace,
	}

	externalKey := ExternalKey[IP]{
		SrcIP:   conn.OutsideDstIP,
		DstIP:   conn.OutsideSrcIP,
		SrcPort: conn.OutsideDstPort,
		DstPort: conn.OutsideSrcPort,
	}

	delete(p.out, internalKey)
	delete(p.in, externalKey)
}

func (p *Pair[IP]) cleanupExpired(now int64, timeout int64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Collect connections to remove
	var toRemove []*Conn[IP]
	for _, conn := range p.out {
		if conn.PendingSweep || (now-conn.LastSeen > timeout) {
			toRemove = append(toRemove, conn)
		}
	}

	// Remove expired connections
	for _, conn := range toRemove {
		internalKey := InternalKey[IP]{
			SrcIP:     conn.LocalSrcIP,
			DstIP:     conn.LocalDstIp,
			SrcPort:   conn.LocalSrcPort,
			DstPort:   conn.LocalDstPort,
			Namespace: conn.Namespace,
		}

		externalKey := ExternalKey[IP]{
			SrcIP:   conn.OutsideDstIP,
			DstIP:   conn.OutsideSrcIP,
			SrcPort: conn.OutsideDstPort,
			DstPort: conn.OutsideSrcPort,
		}

		delete(p.out, internalKey)
		delete(p.in, externalKey)
	}
}

// checkDropRule checks if a packet should be dropped based on drop rules
func (p *Pair[IP]) checkDropRule(dstPort uint16) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, rule := range p.dropRules {
		if rule.DstPort == dstPort {
			return true
		}
	}
	return false
}

// checkRedirectRule checks if a packet should be redirected
// Returns newDstIP, newDstPort, shouldRedirect
func (p *Pair[IP]) checkRedirectRule(dstIP IP, dstPort uint16) (IP, uint16, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, rule := range p.redirectRules {
		if rule.DstPort == dstPort && rule.DstIP == dstIP {
			return rule.NewDstIP, rule.NewDstPort, true
		}
	}
	return dstIP, dstPort, false
}
