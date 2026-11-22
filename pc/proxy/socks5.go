package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
)

// Socks5Client wraps a connection to a SOCKS5 proxy.
type Socks5Client struct {
	ProxyAddr string
	Timeout   time.Duration
}

func NewSocks5Client(addr string) *Socks5Client {
	return &Socks5Client{ProxyAddr: addr, Timeout: 30 * time.Second}
}

// VerifySocks5 checks if a SOCKS5 proxy is reachable and supports no-auth.
func VerifySocks5(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Greeting: VER, NMETHODS, METHODS
	_, err = conn.Write([]byte{socks5Version, 1, authNone})
	if err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return errors.New("не SOCKS5")
	}
	if buf[1] != authNone {
		return errors.New("требуется аутентификация")
	}
	return nil
}

// DialConn creates a TCP connection through the SOCKS5 proxy.
// Returns the established connection to the target.
func (c *Socks5Client) DialConn(network, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("неверный адрес %s: %w", target, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("неверный порт: %s", portStr)
	}

	conn, err := net.DialTimeout("tcp", c.ProxyAddr, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("подключение к SOCKS5: %w", err)
	}
	conn.SetDeadline(time.Now().Add(c.Timeout))

	// Greeting
	if _, err := conn.Write([]byte{socks5Version, 1, authNone}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != socks5Version || buf[1] != authNone {
		conn.Close()
		return nil, errors.New("SOCKS5 авторизация не удалась")
	}

	// Build request
	req := buildRequest(cmdConnect, host, uint16(portNum))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply
	if err := readReply(conn); err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Time{}) // clear deadline
	return conn, nil
}

// UDPAssociate creates a UDP association. Returns UDP socket to use, and the address to send to.
func (c *Socks5Client) UDPAssociate() (*net.UDPConn, *net.UDPAddr, net.Conn, error) {
	// TCP connection for control
	tcpConn, err := net.DialTimeout("tcp", c.ProxyAddr, c.Timeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("UDP assoc: %w", err)
	}
	tcpConn.SetDeadline(time.Now().Add(c.Timeout))

	// Greeting
	if _, err := tcpConn.Write([]byte{socks5Version, 1, authNone}); err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, buf); err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}
	if buf[0] != socks5Version || buf[1] != authNone {
		tcpConn.Close()
		return nil, nil, nil, errors.New("SOCKS5 авторизация не удалась")
	}

	// UDP ASSOCIATE request (DST.ADDR and DST.PORT are client's UDP endpoint - can be 0.0.0.0:0)
	req := buildRequest(cmdUDPAssoc, "0.0.0.0", 0)
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}

	// Read reply - this tells us the UDP relay address on the proxy
	relayIP, relayPort, err := readReplyAddr(tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}

	tcpConn.SetDeadline(time.Time{})

	// Create local UDP socket
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		tcpConn.Close()
		return nil, nil, nil, err
	}

	relayAddr := &net.UDPAddr{IP: net.ParseIP(relayIP), Port: int(relayPort)}

	// If the relay IP is 0.0.0.0, replace with proxy IP
	if relayAddr.IP == nil || relayAddr.IP.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(c.ProxyAddr)
		relayAddr.IP = net.ParseIP(proxyHost)
	}

	return udpConn, relayAddr, tcpConn, nil
}

func buildRequest(cmd byte, host string, port uint16) []byte {
	var req []byte
	req = append(req, socks5Version, cmd, 0x00)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, atypIPv4)
			req = append(req, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			req = append(req, atypIPv6)
			req = append(req, ip6...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req = append(req, pb...)
	return req
}

func readReply(conn net.Conn) error {
	_, _, err := readReplyAddr(conn)
	return err
}

func readReplyAddr(conn net.Conn) (string, uint16, error) {
	// VER, REP, RSV, ATYP
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != socks5Version {
		return "", 0, errors.New("неверный ответ SOCKS5")
	}
	if hdr[1] != repSuccess {
		return "", 0, fmt.Errorf("SOCKS5 ошибка: код %d", hdr[1])
	}

	var addr string
	switch hdr[3] {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", 0, err
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return "", 0, err
		}
		addr = string(dom)
	default:
		return "", 0, errors.New("неподдерживаемый ATYP в ответе")
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(pb)
	return addr, port, nil
}

// BuildUDPHeader builds a SOCKS5 UDP header for sending to relay.
func BuildUDPHeader(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	var hdr []byte
	hdr = append(hdr, 0x00, 0x00, 0x00) // RSV=0, FRAG=0

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append(hdr, atypIPv4)
			hdr = append(hdr, ip4...)
		} else {
			hdr = append(hdr, atypIPv6)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		hdr = append(hdr, atypDomain, byte(len(host)))
		hdr = append(hdr, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(portNum))
	hdr = append(hdr, pb...)
	return hdr, nil
}

// ParseUDPHeader parses a SOCKS5 UDP header from a packet.
// Returns target address, payload, and bytes consumed.
func ParseUDPHeader(data []byte) (addr *net.UDPAddr, payload []byte, n int, err error) {
	if len(data) < 4 {
		return nil, nil, 0, errors.New("слишком короткий UDP пакет")
	}
	// RSV + FRAG
	if data[2] != 0 {
		return nil, nil, 0, errors.New("фрагментация не поддерживается")
	}
	atyp := data[3]
	pos := 4
	var host string
	switch atyp {
	case atypIPv4:
		if len(data) < pos+4+2 {
			return nil, nil, 0, errors.New("короткий IPv4")
		}
		host = net.IP(data[pos : pos+4]).String()
		pos += 4
	case atypIPv6:
		if len(data) < pos+16+2 {
			return nil, nil, 0, errors.New("короткий IPv6")
		}
		host = net.IP(data[pos : pos+16]).String()
		pos += 16
	case atypDomain:
		if len(data) < pos+1 {
			return nil, nil, 0, errors.New("короткий домен")
		}
		l := int(data[pos])
		pos++
		if len(data) < pos+l+2 {
			return nil, nil, 0, errors.New("короткий домен")
		}
		host = string(data[pos : pos+l])
		pos += l
	default:
		return nil, nil, 0, fmt.Errorf("неизвестный ATYP: %d", atyp)
	}
	if len(data) < pos+2 {
		return nil, nil, 0, errors.New("нет порта")
	}
	port := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	ip := net.ParseIP(host)
	if ip == nil {
		resolved, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return nil, nil, 0, err
		}
		ip = resolved.IP
	}
	addr = &net.UDPAddr{IP: ip, Port: port}
	payload = data[pos:]
	n = pos
	return addr, payload, n, nil
}
