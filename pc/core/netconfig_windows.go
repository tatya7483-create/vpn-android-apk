//go:build windows
// +build windows

package core

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wintun"
)

// configureTUNAdapter sets IP address, subnet, gateway and DNS on the Wintun adapter using netsh.
func configureTUNAdapter(adapter *wintun.Adapter, ip, subnet, gateway, dns string) error {
	ifName := tunIfName

	// Set IP address and gateway
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%q", ifName), "static", ip, "255.255.255.0", gateway, "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address: %v: %s", err, string(out))
	}

	// Set DNS
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		fmt.Sprintf("name=%q", ifName), "static", dns, "primary")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set dns: %v: %s", err, string(out))
	}

	// Add static ARP/neighbor entry for the gateway to avoid ARP timeouts
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "neighbors",
		ifName, gateway, "00-00-00-00-00-01")
	cmd.CombinedOutput() // Non-fatal

	// Also add neighbor for the TUN IP itself
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "neighbors",
		ifName, ip, "00-00-00-00-00-02")
	cmd.CombinedOutput()

	return nil
}

// setRouting sets the default route to the TUN adapter.
func (ft *FullTunnel) setRouting() error {
	ifName := tunIfName

	// Add a host route for the phone IP through the original gateway BEFORE changing default route
	if ft.originalGateway != nil {
		cmd := exec.Command("route", "add", ft.phoneIP, ft.originalGateway.String(), "metric", "5")
		if out, err := cmd.CombinedOutput(); err != nil {
			// Try change
			cmd2 := exec.Command("route", "change", ft.phoneIP, ft.originalGateway.String(), "metric", "5")
			if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
				return fmt.Errorf("route add phone: %v: %s; change: %v: %s", err, string(out), err2, string(out2))
			}
		}
	} else {
		// On-link: add a /32 route for the phone via its interface
		// Get the interface index for the phone's network
		ifIdx := findInterfaceForIP(ft.phoneIP)
		if ifIdx > 0 {
			cmd := exec.Command("route", "add", ft.phoneIP, ft.phoneIP, "if", fmt.Sprintf("%d", ifIdx), "metric", "5")
			cmd.CombinedOutput()
		}
	}

	// Change default route metric of TUN to be the lowest (highest priority)
	// First, set existing default routes to higher metric
	if ft.originalGateway != nil {
		cmd := exec.Command("route", "change", "0.0.0.0", ft.originalGateway.String(), "metric", "50")
		cmd.CombinedOutput()
	}

	// Add default route through TUN
	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/0",
		fmt.Sprintf("name=%q", ifName), "nexthop="+tunGateway, "metric", "10")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Try alternative syntax
		cmd2 := exec.Command("route", "add", "0.0.0.0", tunGateway, "metric", "10", "if", findInterfaceByName(ifName))
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("set default route: %v: %s; route add: %v: %s", err, string(out), err2, string(out2))
		}
	}

	return nil
}

// restoreRouting cleans up routes.
func (ft *FullTunnel) restoreRouting() error {
	if ft.phoneIP != "" {
		exec.Command("route", "delete", ft.phoneIP).CombinedOutput()
	}
	// Remove the TUN default route
	exec.Command("route", "delete", "0.0.0.0", tunGateway).CombinedOutput()
	return nil
}

// findInterfaceForIP finds the interface index for the IP that can reach a target.
func findInterfaceForIP(targetIP string) int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	target := net.ParseIP(targetIP)
	if target == nil {
		return 0
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
				return iface.Index
			}
		}
	}
	return 0
}

// findInterfaceByName finds interface index by name using netsh.
func findInterfaceByName(name string) string {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				return fields[0]
			}
		}
	}
	return ""
}
