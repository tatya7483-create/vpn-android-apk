//go:build !windows
// +build !windows

package core

import "errors"

type SystemProxy struct {
	ProxyAddr string
}

func NewSystemProxy(proxyAddr string) *SystemProxy {
	return &SystemProxy{ProxyAddr: proxyAddr}
}

func (s *SystemProxy) Apply() error {
	return errors.New("системный прокси поддерживается только на Windows")
}

func (s *SystemProxy) Restore() error {
	return nil
}
