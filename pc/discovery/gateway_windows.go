//go:build windows
// +build windows

package discovery

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetBestRoute = iphlpapi.NewProc("GetBestRoute")
	procGetIpForwardTable = iphlpapi.NewProc("GetIpForwardTable")
)

// MIB_IPFORWARDROW from Windows SDK
type mibIPForwardRow struct {
	DwForwardDest      uint32
	DwForwardMask      uint32
	DwForwardPolicy    uint32
	DwForwardNextHop   uint32
	DwForwardIfIndex   int32
	DwForwardType      uint32
	DwForwardProto     uint32
	DwForwardAge       uint32
	DwForwardNextHopAS uint32
	DwForwardMetric1   uint32
	DwForwardMetric2   uint32
	DwForwardMetric3   uint32
	DwForwardMetric4   uint32
	DwForwardMetric5   uint32
}

// getWindowsGateway finds the best gateway (next hop) to reach a destination IP.
func getWindowsGateway(destIP string) (net.IP, error) {
	ip := net.ParseIP(destIP).To4()
	if ip == nil {
		return nil, errors.New("invalid IPv4")
	}
	dest := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	var row mibIPForwardRow
	// GetBestRoute(destAddr, sourceAddr (0), *row)
	ret, _, _ := procGetBestRoute.Call(
		uintptr(dest),
		0,
		uintptr(unsafe.Pointer(&row)),
	)
	if ret != 0 {
		return nil, errors.New("GetBestRoute failed")
	}
	nexthop := row.DwForwardNextHop
	if nexthop == 0 {
		// on-link (same subnet)
		return nil, nil
	}
	gw := net.IPv4(byte(nexthop), byte(nexthop>>8), byte(nexthop>>16), byte(nexthop>>24))
	return gw, nil
}
