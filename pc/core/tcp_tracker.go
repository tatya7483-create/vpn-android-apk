//go:build windows
// +build windows

package core

import (
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

type tcpConn struct {
	key         connKey
	mu          sync.Mutex
	state       int
	localSeq    uint32
	localAck    uint32
	remote      net.Conn
	established chan struct{}
	closed      chan struct{}
	ft          *FullTunnel
}

const (
	stateInit        = 0
	stateSynRecv     = 1
	stateEstablished = 2
	stateFinWait     = 3
	stateClosed      = 4
)

// TCPTracker manages TCP connections through SOCKS5.
type TCPTracker struct {
	ft    *FullTunnel
	conns map[connKey]*tcpConn
	mu    sync.Mutex
	seqCtr uint32
}

func NewTCPTracker(ft *FullTunnel) *TCPTracker {
	return &TCPTracker{
		ft:    ft,
		conns: make(map[connKey]*tcpConn),
		seqCtr: 4000000,
	}
}

func (t *TCPTracker) HandlePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, data []byte, opts []byte) {
	key := connKey{srcIP.String(), srcPort, dstIP.String(), dstPort}

	t.mu.Lock()
	conn, ok := t.conns[key]
	if !ok {
		if flags&tcpSYN != 0 && flags&tcpACK == 0 {
			t.seqCtr += 65001 // increment ISN for new connection
			conn = &tcpConn{
				key:         key,
				state:       stateInit,
				localSeq:    t.seqCtr,
				localAck:    seq + 1,
				established: make(chan struct{}),
				closed:      make(chan struct{}),
				ft:          t.ft,
			}
			t.conns[key] = conn
			t.mu.Unlock()
			conn.handleSYN(seq)
			return
		}
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.handlePacket(seq, ack, flags, data)
}

func (c *tcpConn) handleSYN(clientSeq uint32) {
	c.localAck = clientSeq + 1

	targetHost := c.ft.resolveTarget(net.ParseIP(c.key.dstIP))
	target := net.JoinHostPort(targetHost, uint16ToStr(c.key.dstPort))

	go func() {
		remote, err := c.ft.socks.DialConn("tcp", target)
		c.mu.Lock()
		defer c.mu.Unlock()

		if err != nil {
			log.Printf("TCP SYN dial %s: %v", target, err)
			// Send RST
			c.ft.sendTCPSimple(
				net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
				c.key.dstPort, c.key.srcPort,
				0, c.localAck, tcpRST,
			)
			c.closeLocked()
			return
		}

		c.remote = remote
		c.state = stateSynRecv

		// Send SYN-ACK
		c.ft.sendTCPPacket(
			net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
			c.key.dstPort, c.key.srcPort,
			c.localSeq, c.localAck,
			tcpSYN|tcpACK,
			nil, nil,
		)
		c.localSeq++ // SYN consumes one sequence number
	}()
}

func (c *tcpConn) handlePacket(seq, ack uint32, flags byte, data []byte) {
	if c.state == stateClosed {
		return
	}

	if flags&tcpRST != 0 {
		c.closeLocked()
		return
	}

	// ACK completing the three-way handshake
	if c.state == stateSynRecv && flags&tcpACK != 0 {
		if ack == c.localSeq {
			c.state = stateEstablished
			close(c.established)
			go c.relayRemoteToClient()
		}
	}

	// Data from client
	if c.state == stateEstablished && len(data) > 0 {
		expected := c.localAck
		if seq == expected {
			c.localAck = seq + uint32(len(data))
			c.ft.sendTCPSimple(
				net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
				c.key.dstPort, c.key.srcPort,
				c.localSeq, c.localAck, tcpACK,
			)
			if c.remote != nil {
				c.remote.SetWriteDeadline(time.Now().Add(60 * time.Second))
				_, err := c.remote.Write(data)
				if err != nil {
					c.sendRST()
					c.closeLocked()
					return
				}
			}
		} else if seq+uint32(len(data)) <= expected {
			// Duplicate - re-ACK
			c.ft.sendTCPSimple(
				net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
				c.key.dstPort, c.key.srcPort,
				c.localSeq, c.localAck, tcpACK,
			)
		}
	}

	// ACK for data we sent from remote
	if c.state == stateEstablished && flags&tcpACK != 0 && len(data) == 0 && flags&tcpFIN == 0 {
		// Update our understanding of what the client has received
		// We don't retransmit, so just note that our seq is acknowledged
	}

	// FIN from client
	if flags&tcpFIN != 0 {
		c.localAck++
		c.ft.sendTCPSimple(
			net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
			c.key.dstPort, c.key.srcPort,
			c.localSeq, c.localAck, tcpACK,
		)
		// Half-close remote if possible
		if tc, ok := c.remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			c.remote.Close()
		}
		c.state = stateFinWait
	}
}

func (c *tcpConn) relayRemoteToClient() {
	buf := make([]byte, 32768)
	for {
		select {
		case <-c.closed:
			return
		default:
		}
		if c.remote == nil {
			return
		}
		c.remote.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := c.remote.Read(buf)
		if err != nil {
			c.mu.Lock()
			if err == io.EOF {
				// Send FIN
				c.ft.sendTCPSimple(
					net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
					c.key.dstPort, c.key.srcPort,
					c.localSeq, c.localAck, tcpFIN|tcpACK,
				)
				c.localSeq++
			} else {
				c.sendRST()
			}
			c.closeLocked()
			c.mu.Unlock()
			return
		}
		if n > 0 {
			c.mu.Lock()
			c.ft.sendTCPPacket(
				net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
				c.key.dstPort, c.key.srcPort,
				c.localSeq, c.localAck, tcpPSH|tcpACK,
				buf[:n], nil,
			)
			c.localSeq += uint32(n)
			c.mu.Unlock()
		}
	}
}

func (c *tcpConn) sendRST() {
	c.ft.sendTCPSimple(
		net.ParseIP(c.key.dstIP), net.ParseIP(c.key.srcIP),
		c.key.dstPort, c.key.srcPort,
		c.localSeq, c.localAck, tcpRST,
	)
}

func (c *tcpConn) closeLocked() {
	if c.state == stateClosed {
		return
	}
	c.state = stateClosed
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	if c.remote != nil {
		c.remote.Close()
		c.remote = nil
	}
	c.ft.tcpTracker.removeConn(c.key)
}

func (t *TCPTracker) removeConn(key connKey) {
	t.mu.Lock()
	delete(t.conns, key)
	t.mu.Unlock()
}

func (t *TCPTracker) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, c := range t.conns {
		c.mu.Lock()
		if c.remote != nil {
			c.remote.Close()
		}
		select {
		case <-c.closed:
		default:
			close(c.closed)
		}
		c.state = stateClosed
		c.mu.Unlock()
		delete(t.conns, k)
	}
}

func uint16ToStr(p uint16) string {
	return strconv.Itoa(int(p))
}
