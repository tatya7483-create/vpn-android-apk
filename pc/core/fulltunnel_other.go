//go:build !windows
// +build !windows

package core

import "errors"

type FullTunnel struct {
	SocksAddr string
}

func NewFullTunnel(socksAddr string) *FullTunnel {
	return &FullTunnel{SocksAddr: socksAddr}
}

func (ft *FullTunnel) Start() error {
	return errors.New("полный туннель поддерживается только на Windows")
}

func (ft *FullTunnel) Stop() error {
	return nil
}

func (ft *FullTunnel) Check() error {
	return errors.New("не запущено")
}
