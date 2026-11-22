//go:build !windows
// +build !windows

package discovery

import (
	"errors"
	"net"
)

func getWindowsGateway(destIP string) (net.IP, error) {
	return nil, errors.New("Windows-only function")
}
