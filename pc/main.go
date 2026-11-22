package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vpnshare-pc/core"
	"vpnshare-pc/discovery"
	"vpnshare-pc/proxy"
	"vpnshare-pc/ui"
)

func main() {
	mode := flag.String("mode", "sysproxy", "Режим: sysproxy (системный прокси) или full (полный туннель)")
	phoneIP := flag.String("phone", "", "IP телефона (автоопределение если не указан)")
	socksPort := flag.Int("socks-port", 1080, "Порт SOCKS5 на телефоне")
	httpPort := flag.Int("http-port", 8080, "Порт HTTP-прокси на телефоне")
	noTray := flag.Bool("no-tray", false, "Не показывать иконку в трее (консольный режим)")
	verbose := flag.Bool("v", false, "Подробные логи")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)
	if !*verbose {
		log.SetFlags(log.Ltime)
	}

	fmt.Println("=== VPN Share (PC клиент) ===")
	fmt.Println("Режим:", *mode)

	// Find phone IP if not specified
	phone := *phoneIP
	if phone == "" {
		found, err := discovery.FindPhone(*socksPort)
		if err != nil {
			log.Fatalf("Не удалось найти телефон на USB-адаптере: %v\nУбедитесь что USB-модем включён и прокси запущен на телефоне.", err)
		}
		phone = found
		fmt.Printf("Найден телефон: %s\n", phone)
	} else {
		fmt.Printf("Используем указанный IP: %s\n", phone)
	}

	socksAddr := fmt.Sprintf("%s:%d", phone, *socksPort)
	httpAddr := fmt.Sprintf("%s:%d", phone, *httpPort)

	// Verify SOCKS5 proxy is reachable
	if err := proxy.VerifySocks5(socksAddr); err != nil {
		log.Fatalf("SOCKS5 прокси недоступен на %s: %v\nУбедитесь что прокси запущен на телефоне.", socksAddr, err)
	}
	fmt.Printf("SOCKS5 прокси доступен: %s\n", socksAddr)

	// Create app
	app := core.NewApp(socksAddr, httpAddr)

	// Handle shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nПолучен сигнал завершения, выполняется откат настроек…")
		app.Stop()
		os.Exit(0)
	}()

	// Start in selected mode
	var startErr error
	switch *mode {
	case "sysproxy":
		startErr = app.StartSystemProxy()
	case "full":
		startErr = app.StartFullTunnel()
	default:
		log.Fatalf("Неизвестный режим: %s (используйте sysproxy или full)", *mode)
	}
	if startErr != nil {
		log.Fatalf("Ошибка запуска: %v", startErr)
	}
	fmt.Println("Подключение активно. Нажмите Ctrl+C для выхода.")

	// Show tray UI or just wait
	if !*noTray {
		ui.RunTray(app, *mode)
	} else {
		// Console mode - block until signal
		select {}
	}
}
