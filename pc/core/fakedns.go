package core

import (
	"encoding/binary"
	"net"
	"sync"
)

// FakeDNS maps domain names to fake IP addresses in the 198.18.0.0/15 range.
type FakeDNS struct {
	mu         sync.RWMutex
	domainToIP map[string]net.IP
	ipToDomain map[string]string
	nextIP     uint32
}

func NewFakeDNS() *FakeDNS {
	return &FakeDNS{
		domainToIP: make(map[string]net.IP),
		ipToDomain: make(map[string]string),
		nextIP:     uint32(198)<<24 | uint32(18)<<16 | 0<<8 | 2,
	}
}

func (f *FakeDNS) Lookup(ip net.IP) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	domain, ok := f.ipToDomain[ip.String()]
	return domain, ok
}

func (f *FakeDNS) Register(domain string) net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip, ok := f.domainToIP[domain]; ok {
		return ip
	}
	ip := uint32ToIP(f.nextIP)
	f.nextIP++
	if f.nextIP > (uint32(198)<<24|uint32(19)<<16|255<<8|254) {
		f.nextIP = uint32(198)<<24 | uint32(18)<<16 | 0<<8 | 2
	}
	f.domainToIP[domain] = ip
	f.ipToDomain[ip.String()] = domain
	return ip
}

func uint32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

// fakeDNSReply creates a DNS response mapping the queried domain to a fake IP.
func (f *FakeDNS) fakeDNSReply(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	_ = query[0:2] // txID (kept for reference)
	qdcount := binary.BigEndian.Uint16(query[4:6])
	if qdcount == 0 {
		return nil
	}

	pos := 12
	var domain string
	for pos < len(query) {
		if pos >= len(query) {
			return nil
		}
		labelLen := int(query[pos])
		pos++
		if labelLen == 0 {
			break
		}
		if pos+labelLen > len(query) {
			return nil
		}
		if domain != "" {
			domain += "."
		}
		domain += string(query[pos : pos+labelLen])
		pos += labelLen
	}
	if pos+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[pos : pos+2])

	if qtype != 1 {
		resp := make([]byte, len(query))
		copy(resp, query)
		binary.BigEndian.PutUint16(resp[2:4], 0x8103)
		binary.BigEndian.PutUint16(resp[6:8], 0)
		return resp
	}

	fakeIP := f.Register(domain)

	resp := make([]byte, pos+16)
	copy(resp, query)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], qdcount)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	resp[pos] = 0xC0
	resp[pos+1] = 0x0C
	binary.BigEndian.PutUint16(resp[pos+2:pos+4], 1)
	binary.BigEndian.PutUint16(resp[pos+4:pos+6], 1)
	binary.BigEndian.PutUint32(resp[pos+6:pos+10], 60)
	binary.BigEndian.PutUint16(resp[pos+10:pos+12], 4)
	copy(resp[pos+12:pos+16], fakeIP.To4())

	return resp[:pos+16]
}
