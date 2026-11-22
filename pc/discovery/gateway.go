package discovery

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"vpnshare-pc/proxy"
)

// known USB-tethering subnets from Android
var usbSubnets = []*net.IPNet{
	mustParseCIDR("192.168.42.0/24"),
	mustParseCIDR("192.168.43.0/24"),
	mustParseCIDR("192.168.137.0/24"),
	mustParseCIDR("10.0.0.0/24"),
	mustParseCIDR("172.20.10.0/28"),
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// FindPhone tries to locate the phone's IP on USB tethering interfaces.
// It first checks common gateway IPs in USB subnets, then scans.
func FindPhone(socksPort int) (string, error) {
	// Common gateway addresses used by Android USB tethering
	candidates := []string{
		"192.168.42.129",
		"192.168.43.1",
		"192.168.42.1",
		"192.168.137.1",
		"10.0.0.1",
		"172.20.10.1",
	}

	port := fmt.Sprintf("%d", socksPort)

	// 1. Check the well-known gateway IPs first (fast path)
	var wg sync.WaitGroup
	var found = make(chan string, 1)
	var done = make(chan struct{})

	for _, ip := range candidates {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, port)
			if err := proxy.VerifySocks5(addr); err == nil {
				select {
				case found <- ip:
				default:
				}
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case ip := <-found:
		return ip, nil
	case <-time.After(4 * time.Second):
	case <-done:
	}

	// 2. Check if any interface has an IP in USB subnets and try its gateway
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok || ipnet.IP.To4() == nil {
					continue
				}
				// Check if this IP is in a USB subnet
				for _, subnet := range usbSubnets {
					if subnet.Contains(ipnet.IP) {
						// The gateway is typically .1 or .129 in that subnet
						gw := guessGateway(ipnet)
						addr := net.JoinHostPort(gw, port)
						if err := proxy.VerifySocks5(addr); err == nil {
							return gw, nil
						}
					}
				}
			}
		}
	}

	// 3. Broader scan: scan all /24 subnets of non-loopback interfaces for SOCKS5
	ifaces2, _ := net.Interfaces()
	scanCh := make(chan string, 1)
	var scanWg sync.WaitGroup
	scanned := make(map[string]bool)

	for _, iface := range ifaces2 {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			// Get the /24 prefix and scan last octet 1-254
			ip := ipnet.IP.To4()
			prefix := ip.Mask(net.CIDRMask(24, 32))
			prefixStr := prefix.String()
			if scanned[prefixStr] {
				continue
			}
			scanned[prefixStr] = true
			for i := 1; i < 255; i++ {
				targetIP := net.IPv4(prefix[0], prefix[1], prefix[2], byte(i))
				target := targetIP.String()
				if target == ip.String() {
					continue // skip ourselves
				}
				scanWg.Add(1)
				go func(t string) {
					defer scanWg.Done()
					addr := net.JoinHostPort(t, port)
					if err := proxy.VerifySocks5(addr); err == nil {
						select {
						case scanCh <- t:
						default:
						}
					}
				}(target)
			}
		}
	}

	go func() {
		scanWg.Wait()
		close(scanCh)
	}()

	select {
	case ip, ok := <-scanCh:
		if ok {
			return ip, nil
		}
	case <-time.After(8 * time.Second):
	}

	return "", errors.New("телефон не найден. Проверьте что USB-модем включён и прокси запущен")
}

// guessGateway guesses the gateway IP for a given IP network.
// Android USB tethering typically uses .129 (classic) or .1 as gateway.
func guessGateway(ipnet *net.IPNet) string {
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	// Common patterns
	candidates := []byte{129, 1, 254}
	for _, c := range candidates {
		gw := net.IPv4(ip[0], ip[1], ip[2], c)
		if !gw.Equal(ip) {
			return gw.String()
		}
	}
	// Default: .1
	return net.IPv4(ip[0], ip[1], ip[2], 1).String()
}

// GetOriginalGateway finds the original default gateway (needed to route phone traffic directly in full tunnel).
func GetOriginalGateway(phoneIP string) (net.IP, error) {
	// Get routing table - find the gateway for the phone's IP
	// Since phone is on a local subnet, its gateway is in that subnet.
	// We return the interface's gateway or the IP used to reach the phone.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	target := net.ParseIP(phoneIP)
	if target == nil {
		return nil, errors.New("неверный IP телефона")
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.Contains(target) {
				// This is the interface to the phone. The gateway is the phone itself.
				// For routing: we need to keep route to phoneIP via this interface's original gateway.
				// But since the phone is on the same subnet, we don't need a gateway - it's on-link.
				// We just need to ensure the route to the phone's subnet doesn't go through TUN.
				return nil, nil // on-link
			}
		}
	}

	// Fallback: check Windows routing table via syscall
	return getWindowsGateway(phoneIP)
}
