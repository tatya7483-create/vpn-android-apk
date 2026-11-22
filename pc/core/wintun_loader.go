//go:build windows
// +build windows

package core

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

//go:embed res/wintun.dll
var wintunDLL []byte

var wintunModule syscall.Handle

// ensureWintunDLL loads wintun.dll so that the wintun package can find it.
func ensureWintunDLL() error {
	if wintunModule != 0 {
		return nil
	}

	// 1. Look next to the executable first
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidate := filepath.Join(exeDir, "wintun.dll")
		if st, err := os.Stat(candidate); err == nil && st.Size() > 1000 {
			h, err := loadDLL(candidate)
			if err == nil {
				wintunModule = h
				return nil
			}
		}
	}

	// 2. Current working directory
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "wintun.dll")
		if st, err := os.Stat(candidate); err == nil && st.Size() > 1000 {
			h, err := loadDLL(candidate)
			if err == nil {
				wintunModule = h
				return nil
			}
		}
	}

	// 3. Extract embedded DLL and load it
	tmpDir := filepath.Join(os.TempDir(), "vpnshare")
	if err := os.MkdirAll(tmpDir, 0755); err == nil {
		dllPath := filepath.Join(tmpDir, "wintun.dll")
		if len(wintunDLL) > 1000 {
			if err := os.WriteFile(dllPath, wintunDLL, 0644); err == nil {
				h, err := loadDLL(dllPath)
				if err == nil {
					wintunModule = h
					return nil
				}
			}
		}
	}

	return fmt.Errorf("wintun.dll не найден. Поместите wintun.dll в папку с программой (рядом с VpnShare.exe)")
}

func loadDLL(path string) (syscall.Handle, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}
	pathW, err := syscall.UTF16PtrFromString(absPath)
	if err != nil {
		return 0, err
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	ret, _, callErr := loadLibrary.Call(uintptr(unsafe.Pointer(pathW)))
	if ret == 0 {
		return 0, fmt.Errorf("LoadLibrary failed for %s: %v", path, callErr)
	}
	return syscall.Handle(ret), nil
}
