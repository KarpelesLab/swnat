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

func (p *Pair[IP]) addConnection(conn *Conn[IP]) {
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
		if now-conn.LastSeen > timeout {
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
