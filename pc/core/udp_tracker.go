//go:build windows
// +build windows

package core

import (
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"vpnshare-pc/proxy"
)

type udpKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

type udpFlow struct {
	key       udpKey
	mu        sync.Mutex
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	ctrlConn  net.Conn
	lastSeen  time.Time
	closed    chan struct{}
}

// UDPTracker manages UDP forwarding through SOCKS5 UDP ASSOCIATE.
type UDPTracker struct {
	ft    *FullTunnel
	flows map[udpKey]*udpFlow
	mu    sync.Mutex
}

func NewUDPTracker(ft *FullTunnel) *UDPTracker {
	u := &UDPTracker{
		ft:    ft,
		flows: make(map[udpKey]*udpFlow),
	}
	go u.cleanupLoop()
	return u
}

func (u *UDPTracker) HandlePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, data []byte) {
	if dstIP.String() == u.ft.phoneIP {
		return
	}

	key := udpKey{srcIP.String(), srcPort, dstIP.String(), dstPort}

	u.mu.Lock()
	flow, ok := u.flows[key]
	if !ok {
		flow = &udpFlow{
			key:      key,
			lastSeen: time.Now(),
			closed:   make(chan struct{}),
		}
		u.flows[key] = flow
		u.mu.Unlock()
		u.createFlow(flow)
	} else {
		flow.lastSeen = time.Now()
		u.mu.Unlock()
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.udpConn == nil || flow.relayAddr == nil {
		return
	}

	targetHost := u.ft.resolveTarget(dstIP)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(dstPort)))
	hdr, err := proxy.BuildUDPHeader(target)
	if err != nil {
		return
	}
	pkt := make([]byte, len(hdr)+len(data))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], data)
	flow.udpConn.WriteTo(pkt, flow.relayAddr)
}

func (u *UDPTracker) createFlow(flow *udpFlow) {
	udpConn, relayAddr, ctrlConn, err := u.ft.socks.UDPAssociate()
	if err != nil {
		log.Printf("UDP assoc: %v", err)
		u.mu.Lock()
		delete(u.flows, flow.key)
		u.mu.Unlock()
		return
	}

	flow.mu.Lock()
	flow.udpConn = udpConn
	flow.relayAddr = relayAddr
	flow.ctrlConn = ctrlConn
	flow.mu.Unlock()

	go u.receiveLoop(flow)
}

func (u *UDPTracker) receiveLoop(flow *udpFlow) {
	buf := make([]byte, 4096+256)
	for {
		select {
		case <-flow.closed:
			return
		default:
		}
		flow.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, _, err := flow.udpConn.ReadFrom(buf)
		if err != nil {
			u.removeFlow(flow.key)
			return
		}
		_, payload, _, err := proxy.ParseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		u.ft.sendUDPPacket(
			net.ParseIP(flow.key.dstIP), net.ParseIP(flow.key.srcIP),
			flow.key.dstPort, flow.key.srcPort,
			payload,
		)
		flow.lastSeen = time.Now()
	}
}

func (u *UDPTracker) removeFlow(key udpKey) {
	u.mu.Lock()
	flow, ok := u.flows[key]
	if ok {
		delete(u.flows, key)
		select {
		case <-flow.closed:
		default:
			close(flow.closed)
		}
		if flow.udpConn != nil {
			flow.udpConn.Close()
		}
		if flow.ctrlConn != nil {
			flow.ctrlConn.Close()
		}
	}
	u.mu.Unlock()
}

func (u *UDPTracker) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		u.mu.Lock()
		now := time.Now()
		for k, f := range u.flows {
			if now.Sub(f.lastSeen) > 5*time.Minute {
				go u.removeFlow(k)
			}
		}
		u.mu.Unlock()
	}
}

func (u *UDPTracker) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for k, f := range u.flows {
		select {
		case <-f.closed:
		default:
			close(f.closed)
		}
		if f.udpConn != nil {
			f.udpConn.Close()
		}
		if f.ctrlConn != nil {
			f.ctrlConn.Close()
		}
		delete(u.flows, k)
	}
}
