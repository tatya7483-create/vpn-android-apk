//go:build windows
// +build windows

package ui

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/getlantern/systray"

	"vpnshare-pc/core"
)

//go:embed res/icon.ico
var iconData []byte

func RunTray(app *core.App, mode string) {
	systray.Run(func() {
		onReady(app, mode)
	}, onExit)
}

func onReady(app *core.App, mode string) {
	systray.SetIcon(iconData)
	systray.SetTitle("VPN Share")
	tooltip := fmt.Sprintf("VPN Share — %s", modeDescription(mode))
	systray.SetTooltip(tooltip)

	mStatus := systray.AddMenuItem("Подключено", "Статус")
	mStatus.Disable()

	systray.AddSeparator()

	mSysProxy := systray.AddMenuItem("Режим: системный прокси", "")
	mFullTunnel := systray.AddMenuItem("Режим: полный туннель", "")

	systray.AddSeparator()

	mReconnect := systray.AddMenuItem("Переподключить", "")
	mExit := systray.AddMenuItem("Выход", "")

	// Update menu based on current mode
	updateMenuMode(mSysProxy, mFullTunnel, mode)

	go func() {
		for {
			select {
			case <-mReconnect.ClickedCh:
				app.Stop()
				os.Exit(0)
			case <-mSysProxy.ClickedCh:
				app.Stop()
				if err := app.StartSystemProxy(); err != nil {
					mStatus.SetTitle(fmt.Sprintf("Ошибка: %v", err))
				} else {
					mode = "sysproxy"
					updateMenuMode(mSysProxy, mFullTunnel, mode)
					mStatus.SetTitle("Подключено (системный прокси)")
				}
			case <-mFullTunnel.ClickedCh:
				app.Stop()
				if err := app.StartFullTunnel(); err != nil {
					mStatus.SetTitle(fmt.Sprintf("Ошибка: %v", err))
				} else {
					mode = "full"
					updateMenuMode(mSysProxy, mFullTunnel, mode)
					mStatus.SetTitle("Подключено (полный туннель)")
				}
			case <-mExit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func updateMenuMode(mSys, mFull *systray.MenuItem, mode string) {
	switch mode {
	case "sysproxy":
		mSys.Check()
		mFull.Uncheck()
	case "full":
		mFull.Check()
		mSys.Uncheck()
	}
}

func modeDescription(mode string) string {
	switch mode {
	case "sysproxy":
		return "системный прокси"
	case "full":
		return "полный туннель"
	}
	return mode
}

func onExit() {
	os.Exit(0)
}
