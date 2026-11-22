//go:build !windows
// +build !windows

package ui

import "vpnshare-pc/core"

func RunTray(app *core.App, mode string) {
	// Tray not available on non-Windows; block forever
	select {}
}
