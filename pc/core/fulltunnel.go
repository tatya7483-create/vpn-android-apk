//go:build windows
// +build windows

package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"vpnshare-pc/discovery"
	"vpnshare-pc/proxy"
)

const (
	tunIP      = "10.0.99.2"
	tunGateway = "10.0.99.1"
	tunDNS     = "10.0.99.1"
	tunMTU     = 1420
	tunIfName  = "VPNShare"
)

// FullTunnel manages the Wintun + tun2socks full tunnel.
type FullTunnel struct {
	SocksAddr string

	adapter         *wintun.Adapter
	session         wintun.Session
	sessionStarted  bool
	socks           *proxy.Socks5Client
	fakeDNS         *FakeDNS
	tcpTracker      *TCPTracker
	udpTracker      *UDPTracker
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	mu              sync.Mutex
	running         bool
	writeMu         sync.Mutex
	originalGateway net.IP
	phoneIP         string
}

func NewFullTunnel(socksAddr string) *FullTunnel {
	return &FullTunnel{
		SocksAddr: socksAddr,
		socks:     proxy.NewSocks5Client(socksAddr),
		fakeDNS:   NewFakeDNS(),
	}
}

func (ft *FullTunnel) Start() error {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if ft.running {
		return fmt.Errorf("уже запущено")
	}

	if !isAdmin() {
		return fmt.Errorf("режим полного туннеля требует запуска от имени администратора")
	}

	host, _, err := net.SplitHostPort(ft.SocksAddr)
	if err != nil {
		return fmt.Errorf("неверный адрес SOCKS: %w", err)
	}
	ft.phoneIP = host

	ft.originalGateway, err = discovery.GetOriginalGateway(ft.phoneIP)
	if err != nil {
		log.Printf("Предупреждение: не удалось определить исходный шлюз: %v", err)
	}

	if err := ensureWintunDLL(); err != nil {
		return err
	}

	ft.adapter, err = wintun.CreateAdapter(tunIfName, "VPN Share Tunnel", nil)
	if err != nil {
		return fmt.Errorf("создать TUN адаптер (нужны права администратора?): %w", err)
	}

	success := false
	defer func() {
		if !success {
			ft.cleanup()
		}
	}()

	if err := configureTUNAdapter(ft.adapter, tunIP, "255.255.255.0", tunGateway, tunDNS); err != nil {
		log.Printf("Предупреждение: настройка адаптера: %v", err)
	}

	ft.session, err = ft.adapter.StartSession(0x400000)
	if err != nil {
		ft.closeAdapter()
		return fmt.Errorf("запустить сессию TUN: %w", err)
	}
	ft.sessionStarted = true

	ft.tcpTracker = NewTCPTracker(ft)
	ft.udpTracker = NewUDPTracker(ft)
	ft.running = true

	if err := ft.setRouting(); err != nil {
		log.Printf("Предупреждение: настройка маршрутов: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ft.cancel = cancel
	ft.wg.Add(1)
	go ft.readLoop(ctx)

	success = true
	log.Printf("Full tunnel started (TUN=%s, SOCKS5=%s)", tunIP, ft.SocksAddr)
	return nil
}

func (ft *FullTunnel) Stop() error {
	ft.mu.Lock()
	if !ft.running {
		ft.mu.Unlock()
		return nil
	}
	ft.running = false
	ft.mu.Unlock()

	if ft.cancel != nil {
		ft.cancel()
	}
	ft.wg.Wait()
	ft.cleanup()
	log.Println("Full tunnel stopped")
	return nil
}

func (ft *FullTunnel) Check() error {
	conn, err := net.DialTimeout("tcp", ft.SocksAddr, 3*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (ft *FullTunnel) cleanup() {
	_ = ft.restoreRouting()
	if ft.tcpTracker != nil {
		ft.tcpTracker.Close()
		ft.tcpTracker = nil
	}
	if ft.udpTracker != nil {
		ft.udpTracker.Close()
		ft.udpTracker = nil
	}
	if ft.sessionStarted && ft.session != nil {
		ft.session.End()
		ft.session = nil
		ft.sessionStarted = false
	}
	ft.closeAdapter()
}

func (ft *FullTunnel) closeAdapter() {
	if ft.adapter != nil {
		ft.adapter.Close()
		ft.adapter = nil
	}
}

func (ft *FullTunnel) readLoop(ctx context.Context) {
	defer ft.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, err := ft.session.ReceivePacket()
		if err != nil {
			if err == wintun.ErrRateDropException {
				time.Sleep(time.Millisecond)
				continue
			}
			// Try other error names
			if err.Error() == "Write packet failed due to rate limit, try later" {
				time.Sleep(time.Millisecond)
				continue
			}
			if ft.running {
				log.Printf("TUN read: %v", err)
			}
			return
		}

		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		ft.handlePacket(pktCopy)
		ft.session.ReleaseReceivePacket(pkt)
	}
}

func (ft *FullTunnel) handlePacket(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		ft.handleIPv4(pkt)
	}
}

func (ft *FullTunnel) handleIPv4(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return
	}
	pkt = pkt[:totalLen]

	proto := pkt[9]
	srcIP := net.IP(make([]byte, 4))
	copy(srcIP, pkt[12:16])
	dstIP := net.IP(make([]byte, 4))
	copy(dstIP, pkt[16:20])
	payload := pkt[ihl:]

	switch proto {
	case 6:
		if len(payload) < 20 {
			return
		}
		ft.handleTCPv4(srcIP, dstIP, payload)
	case 17:
		if len(payload) < 8 {
			return
		}
		ft.handleUDPv4(srcIP, dstIP, payload)
	case 1:
		if len(payload) < 8 {
			return
		}
		ft.handleICMPv4(pkt, srcIP, dstIP, payload)
	}
}

func (ft *FullTunnel) handleTCPv4(srcIP, dstIP net.IP, payload []byte) {
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	seqNum := binary.BigEndian.Uint32(payload[4:8])
	ackNum := binary.BigEndian.Uint32(payload[8:12])
	dataOff := int(payload[12]>>4) * 4
	if dataOff < 20 || len(payload) < dataOff {
		return
	}
	flags := payload[13]
	tcpData := payload[dataOff:]

	ft.tcpTracker.HandlePacket(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum, flags, tcpData)
}

func (ft *FullTunnel) handleUDPv4(srcIP, dstIP net.IP, payload []byte) {
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	udpLen := binary.BigEndian.Uint16(payload[4:6])
	if int(udpLen) < 8 || int(udpLen) > len(payload) {
		return
	}
	udpData := payload[8:udpLen]

	if dstPort == 53 && dstIP.Equal(net.ParseIP(tunDNS)) {
		resp := ft.fakeDNS.fakeDNSReply(udpData)
		if resp != nil {
			ft.sendUDPPacket(dstIP, srcIP, dstPort, srcPort, resp)
		}
		return
	}

	ft.udpTracker.HandlePacket(srcIP, dstIP, srcPort, dstPort, udpData)
}

func (ft *FullTunnel) handleICMPv4(pkt []byte, srcIP, dstIP net.IP, payload []byte) {
	icmpType := payload[0]
	if icmpType == 8 {
		tunNetIP := net.ParseIP(tunIP)
		tunGwIP := net.ParseIP(tunGateway)
		if dstIP.Equal(tunNetIP) || dstIP.Equal(tunGwIP) {
			reply := make([]byte, len(pkt))
			copy(reply, pkt)
			copy(reply[12:16], dstIP.To4())
			copy(reply[16:20], srcIP.To4())
			replyIHL := int(reply[0]&0x0F) * 4
			reply[replyIHL] = 0
			icmpPayload := reply[replyIHL:]
			icmpPayload[2] = 0
			icmpPayload[3] = 0
			recalculateIPv4Checksum(reply)
			csum := ipChecksum(icmpPayload)
			binary.BigEndian.PutUint16(icmpPayload[2:4], csum)
			ft.sendPacket(reply)
		}
	}
}

func (ft *FullTunnel) sendPacket(data []byte) {
	ft.writeMu.Lock()
	defer ft.writeMu.Unlock()
	buf, err := ft.session.AllocateSendPacket(len(data))
	if err != nil {
		return
	}
	copy(buf, data)
	ft.session.SendPacket(buf)
}

func (ft *FullTunnel) sendTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, data []byte, tcpOpts []byte) {
	tcpHdrLen := 20 + len(tcpOpts)
	ip := make([]byte, 20+tcpHdrLen+len(data))

	ip[0] = 0x45
	ip[1] = 0x00
	totalLen := uint16(20 + tcpHdrLen + len(data))
	binary.BigEndian.PutUint16(ip[2:4], totalLen)
	binary.BigEndian.PutUint16(ip[4:6], 0x1337)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	recalculateIPv4Checksum(ip)

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((20+len(tcpOpts))/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	if len(tcpOpts) > 0 {
		copy(tcp[20:], tcpOpts)
	}
	if len(data) > 0 {
		copy(ip[20+tcpHdrLen:], data)
	}

	csum := tcpChecksum(srcIP, dstIP, 6, tcp[:tcpHdrLen+len(data)])
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	ft.sendPacket(ip)
}

func (ft *FullTunnel) sendTCPSimple(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte) {
	ft.sendTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, nil, nil)
}

func (ft *FullTunnel) sendUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, data []byte) {
	udpLen := 8 + len(data)
	ip := make([]byte, 20+udpLen)

	ip[0] = 0x45
	ip[1] = 0x00
	totalLen := uint16(20 + udpLen)
	binary.BigEndian.PutUint16(ip[2:4], totalLen)
	binary.BigEndian.PutUint16(ip[4:6], 0x1337)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	recalculateIPv4Checksum(ip)

	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], data)

	ft.sendPacket(ip)
}

func (ft *FullTunnel) resolveTarget(dstIP net.IP) string {
	if domain, ok := ft.fakeDNS.Lookup(dstIP); ok {
		return domain
	}
	return dstIP.String()
}

func recalculateIPv4Checksum(ip []byte) {
	ip[10] = 0
	ip[11] = 0
	csum := ipChecksum(ip[:int((ip[0]&0x0F))*4])
	binary.BigEndian.PutUint16(ip[10:12], csum)
}

func ipChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, protocol byte, tcpSeg []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSeg)))
	csumData := make([]byte, 0, len(pseudo)+len(tcpSeg)+1)
	csumData = append(csumData, pseudo...)
	csumData = append(csumData, tcpSeg...)
	if len(csumData)%2 == 1 {
		csumData = append(csumData, 0)
	}
	return ipChecksum(csumData)
}

func isAdmin() bool {
	var token windows.Token
	pseudoHandle := windows.Handle(^uintptr(0))
	if err := windows.OpenProcessToken(pseudoHandle, windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
