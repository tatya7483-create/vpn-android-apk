//go:build windows
// +build windows

package core

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

var (
	wininet                   = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption     = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

// SystemProxy manages Windows system proxy settings.
type SystemProxy struct {
	ProxyAddr string

	originalProxyEnable   uint32
	originalProxyServer   string
	originalProxyOverride string
	originalAutoConfigURL string
	originalAutoDetect    uint32
	saved                 bool
}

func NewSystemProxy(proxyAddr string) *SystemProxy {
	return &SystemProxy{ProxyAddr: proxyAddr}
}

func (s *SystemProxy) Apply() error {
	if err := s.saveCurrent(); err != nil {
		return fmt.Errorf("сохранить настройки: %w", err)
	}

	proxyServer := fmt.Sprintf("http=%s", s.ProxyAddr)

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("открыть реестр: %w", err)
	}
	defer k.Close()

	k.SetDWordValue("ProxyEnable", 1)
	k.SetStringValue("ProxyServer", proxyServer)
	k.SetStringValue("ProxyOverride", "<local>")
	k.SetDWordValue("AutoDetect", 0)
	k.SetStringValue("AutoConfigURL", "")

	s.refreshSettings()
	return nil
}

func (s *SystemProxy) Restore() error {
	if !s.saved {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("открыть реестр: %w", err)
	}
	defer k.Close()

	k.SetDWordValue("ProxyEnable", s.originalProxyEnable)
	if s.originalProxyServer != "" {
		k.SetStringValue("ProxyServer", s.originalProxyServer)
	} else {
		k.DeleteValue("ProxyServer")
	}
	if s.originalProxyOverride != "" {
		k.SetStringValue("ProxyOverride", s.originalProxyOverride)
	} else {
		k.DeleteValue("ProxyOverride")
	}
	if s.originalAutoConfigURL != "" {
		k.SetStringValue("AutoConfigURL", s.originalAutoConfigURL)
	} else {
		k.DeleteValue("AutoConfigURL")
	}
	k.SetDWordValue("AutoDetect", s.originalAutoDetect)

	s.refreshSettings()
	s.saved = false
	return nil
}

func (s *SystemProxy) saveCurrent() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	s.originalProxyEnable = getDWord(k, "ProxyEnable")
	s.originalProxyServer, _, _ = k.GetStringValue("ProxyServer")
	s.originalProxyOverride, _, _ = k.GetStringValue("ProxyOverride")
	s.originalAutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")
	s.originalAutoDetect = getDWord(k, "AutoDetect")
	s.saved = true
	return nil
}

func getDWord(k registry.Key, name string) uint32 {
	val, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return uint32(val)
}

func (s *SystemProxy) refreshSettings() {
	procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}
