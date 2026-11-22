package core

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Mode represents the connection mode.
type Mode int

const (
	ModeStopped Mode = iota
	ModeSystemProxy
	ModeFullTunnel
)

// App manages the VPN connection state.
type App struct {
	SocksAddr string
	HttpAddr  string

	mu     sync.Mutex
	mode   Mode
	sp     *SystemProxy
	ft     *FullTunnel
	stopCh chan struct{}
}

// Status holds the current state for UI.
type Status struct {
	Mode      Mode
	Connected bool
	Error     string
}

func NewApp(socksAddr, httpAddr string) *App {
	return &App{
		SocksAddr: socksAddr,
		HttpAddr:  httpAddr,
		mode:      ModeStopped,
		stopCh:    make(chan struct{}),
	}
}

// StartSystemProxy starts the system proxy mode.
func (a *App) StartSystemProxy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != ModeStopped {
		return fmt.Errorf("уже запущено")
	}

	sp := NewSystemProxy(a.HttpAddr)
	if err := sp.Apply(); err != nil {
		return fmt.Errorf("системный прокси: %w", err)
	}
	a.sp = sp
	a.mode = ModeSystemProxy
	log.Println("Системный прокси включён")

	go a.monitorConnection()
	return nil
}

// StartFullTunnel starts the full tunnel (TUN) mode.
func (a *App) StartFullTunnel() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != ModeStopped {
		return fmt.Errorf("уже запущено")
	}

	ft := NewFullTunnel(a.SocksAddr)
	if err := ft.Start(); err != nil {
		return fmt.Errorf("полный туннель: %w", err)
	}
	a.ft = ft
	a.mode = ModeFullTunnel
	log.Println("Полный туннель включён")

	go a.monitorConnection()
	return nil
}

// Stop disconnects and rolls back all settings.
func (a *App) Stop() {
	a.mu.Lock()
	mode := a.mode
	sp := a.sp
	ft := a.ft
	a.sp = nil
	a.ft = nil
	a.mode = ModeStopped
	a.mu.Unlock()

	select {
	case <-a.stopCh:
		// already closed
	default:
		close(a.stopCh)
	}

	switch mode {
	case ModeSystemProxy:
		if sp != nil {
			if err := sp.Restore(); err != nil {
				log.Printf("Ошибка отката системного прокси: %v", err)
			}
		}
	case ModeFullTunnel:
		if ft != nil {
			if err := ft.Stop(); err != nil {
				log.Printf("Ошибка остановки туннеля: %v", err)
			}
		}
	}
	log.Println("Настройки сброшены, соединение закрыто")
}

// GetStatus returns the current status.
func (a *App) GetStatus() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{Mode: a.mode, Connected: a.mode != ModeStopped}
}

func (a *App) monitorConnection() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			if !a.checkAlive() {
				log.Println("Соединение потеряно, переподключение…")
				a.reconnect()
			}
		}
	}
}

func (a *App) checkAlive() bool {
	a.mu.Lock()
	proxyAddr := a.HttpAddr
	socksAddr := a.SocksAddr
	mode := a.mode
	a.mu.Unlock()

	var addr string
	switch mode {
	case ModeSystemProxy:
		addr = proxyAddr
	case ModeFullTunnel:
		addr = socksAddr
	default:
		return true
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (a *App) reconnect() {
	a.mu.Lock()
	mode := a.mode
	var sp *SystemProxy
	var ft *FullTunnel
	if a.sp != nil {
		sp = a.sp
		a.sp = nil
	}
	if a.ft != nil {
		ft = a.ft
		a.ft = nil
	}
	a.mode = ModeStopped
	a.mu.Unlock()

	if sp != nil {
		sp.Restore()
	}
	if ft != nil {
		ft.Stop()
	}

	time.Sleep(2 * time.Second)
	for i := 0; i < 20; i++ {
		select {
		case <-a.stopCh:
			return
		default:
		}
		var err error
		a.mu.Lock()
		switch mode {
		case ModeSystemProxy:
			sp2 := NewSystemProxy(a.HttpAddr)
			err = sp2.Apply()
			if err == nil {
				a.sp = sp2
				a.mode = ModeSystemProxy
				log.Println("Переподключено (системный прокси)")
			}
		case ModeFullTunnel:
			ft2 := NewFullTunnel(a.SocksAddr)
			err = ft2.Start()
			if err == nil {
				a.ft = ft2
				a.mode = ModeFullTunnel
				log.Println("Переподключено (полный туннель)")
			}
		}
		a.mu.Unlock()
		if err == nil {
			return
		}
		log.Printf("Попытка %d не удалась: %v", i+1, err)
		time.Sleep(3 * time.Second)
	}
	log.Println("Не удалось переподключиться после 20 попыток")
}
