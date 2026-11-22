//go:build windows
// +build windows

package core

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// Windows API for Internet Settings proxy.
var (
	wininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")

	winHTTP           = syscall.NewLazyDLL("winhttp.dll")
	procWinHttpSetDefaultProxyConfiguration = winHTTP.NewProc("WinHttpSetDefaultProxyConfiguration")
	procWinHttpGetDefaultProxyConfiguration = winHTTP.NewProc("WinHttpGetDefaultProxyConfiguration")
)

const (
	internetOptionRefresh       = 37
	internetOptionProxySettings = 39
	internetOptionSettingsChanged = 39

	winHTTPAccessTypeNamedProxy = 3
)

type winHTTPCurrentUserIEProxyConfig struct {
	AutoDetect    bool
	AutoConfigURL *uint16
	Proxy         *uint16
	ProxyBypass   *uint16
}

type winHTTPProxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

// SystemProxy manages Windows system proxy settings.
type SystemProxy struct {
	ProxyAddr string

	// Saved original settings for restore
	originalProxyEnable  uint32
	originalProxyServer  string
	originalProxyOverride string
	originalAutoConfigURL string
	originalAutoDetect    uint32
	saved                 bool
}

func NewSystemProxy(proxyAddr string) *SystemProxy {
	return &SystemProxy{ProxyAddr: proxyAddr}
}

// Apply sets the system proxy to our HTTP proxy.
func (s *SystemProxy) Apply() error {
	// Save current settings
	if err := s.saveCurrent(); err != nil {
		return fmt.Errorf("сохранить настройки: %w", err)
	}

	proxyServer := fmt.Sprintf("http=%s", s.ProxyAddr) // Use HTTP proxy for system

	// Set proxy in registry
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("открыть реестр: %w", err)
	}
	defer k.Close()

	k.SetDWordValue("ProxyEnable", 1)
	k.SetStringValue("ProxyServer", proxyServer)
	k.SetStringValue("ProxyOverride", "<local>")
	k.SetDWordValue("AutoDetect", 0)
	// Don't touch AutoConfigURL, set to empty to disable PAC
	k.SetStringValue("AutoConfigURL", "")

	// Notify system of changes
	s.refreshSettings()

	return nil
}

// Restore original proxy settings.
func (s *SystemProxy) Restore() error {
	if !s.saved {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
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
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.READ)
	if err != nil {
		return err
	}
	defer k.Close()

	s.originalProxyEnable, _, _ = k.GetDWordValue("ProxyEnable")
	s.originalProxyServer, _, _ = k.GetStringValue("ProxyServer")
	s.originalProxyOverride, _, _ = k.GetStringValue("ProxyOverride")
	s.originalAutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")
	s.originalAutoDetect, _, _ = k.GetDWordValue("AutoDetect")
	s.saved = true
	return nil
}

func (s *SystemProxy) refreshSettings() {
	// InternetSetOption with INTERNET_OPTION_SETTINGS_CHANGED and INTERNET_OPTION_REFRESH
	procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// Non-windows stub
var _ = errors.New("") // placeholder to avoid "imported and not used"
