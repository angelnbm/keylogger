# Justificación Técnica — Proyecto Keylogger / DriverBooster

---

## 1. Lenguaje: Go vs Python

| Aspecto | Python | Go |
|---|---|---|
| Compilación | PyInstaller/Nuitka (empaqueta intérprete) | Compilado a nativo |
| Binario resultante | 10-30 MB + bootloader detectable | 2-3 MB, sin dependencias |
| Detecciones AV | 15-25 (PyInstaller) | 4 (DriverBooster.exe) |
| API de Windows | `ctypes` / `pywin32` | `syscall` nativo |

**Decisión**: Go. El binario compilado no necesita intérprete, es más pequeño y genera menos detecciones antivirus. Las llamadas a API de Windows se hacen directamente sin capas intermedias.

---

## 2. Captura de teclas: `GetAsyncKeyState` vs `SetWindowsHookEx`

| Método | Funcionamiento | Detecciones |
|---|---|---|
| `SetWindowsHookEx(WH_KEYBOARD_LL)` | Callback solo cuando hay tecla | 7 (probado) |
| `GetAsyncKeyState` (polling) | Loop cada 10ms preguntando estado | 4 (probado) |

**Decisión**: `GetAsyncKeyState`. Contraintuitivo, pero el hook global (`WH_KEYBOARD_LL`) es un patrón clásico de keylogger que los AV reconocen inmediatamente. El polling es menos común y genera solo 4 detecciones.

**Trade-off**: El polling consume una CPU mínima ( ~1%), pero puede perder teclas rápidas si el loop no alcanza.

---

## 3. Cifrado: AES-256-GCM

**¿Por qué AES?** Estándar NIST, aprobado por el gobierno de EE.UU., implementado en hardware (AES-NI) en casi todos los CPUs modernos.

**¿Por qué GCM y no CBC/CTR?** GCM incluye autenticación (tag de 16 bytes). Si alguien modifica el ciphertext en tránsito, el descifrado falla. CBC y CTR requieren un HMAC aparte para lograr lo mismo.

**¿Por qué 256 y no 128 bits?** 256 bits es el estándar actual — 128 bits sigue siendo seguro pero 256 demuestra mejor práctica. La diferencia de rendimiento es mínima.

**¿Por qué no RSA?** RSA solo cifra bloques de hasta 256 bytes (con clave de 2048 bits). Para logs largos necesitaríamos cifrado híbrido: RSA para intercambiar una clave AES, AES para los datos. En un proyecto académico, la clave embebida simplifica la arquitectura.

**¿Por qué no XOR?** XOR con clave fija **no es cifrado** — es ofuscación. Dado un par texto plano + cifrado, la clave se recupera haciendo XOR entre ambos. Se usa solo en `loader.go` para el shellcode porque se priorizó simplicidad.

---

## 4. Clave embebida en el binario

| Opción | Ventaja | Desventaja |
|---|---|---|
| **Clave hardcodeada** (elegida) | Simple, no requiere handshake | Si descompilan el .exe, tienen la clave |
| Intercambio ECDH | Perfect Forward Secrecy | Complejidad extra, más código |
| RSA híbrido | La clave no viaja en el binario | Handshake inicial |

**Decisión**: Clave hardcodeada por simplicidad académica. En un escenario real se usaría X25519 (ECDH) con HKDF para derivar una clave de sesión efímera.

---

## 5. Protocolo de transmisión: TCP length-prefix

```
[ 4 bytes big-endian: longitud ][ nonce 12 bytes ][ ciphertext + tag 16 bytes ]
```

**¿Por qué TCP y no HTTP/HTTPS?** TCP raw es más simple y no deja cabeceras HTTP que un IDS pueda detectar. El puerto 4444 es atípico (no es 80/443) y pasa desapercibido en análisis de red superficiales.

**¿Por qué length-prefix?** TCP es un stream, no entrega mensajes completos de una sola vez. El prefijo de 4 bytes permite al receptor saber exactamente cuántos bytes leer.

---

## 6. Persistencia: `HKCU\...\Run`

**¿Por qué HKCU y no HKLM?** HKCU no requiere privilegios de administrador. El usuario víctima ejecuta el binario sin permisos elevados, así que HKLM no es una opción viable.

**¿Por qué no tarea programada?** `schtasks.exe` requiere crear un archivo XML o usar la API COM, lo que agrega complejidad. La clave `Run` es el mecanismo de persistencia más simple y efectivo para un solo usuario.

**Nombre ofuscado**: La cadena `"DriverBooster Scheduler 10.4"` viaja en el binario ofuscada con XOR (clave 0x2A) para que `strings DriverBooster.exe` no revele el propósito del ejecutable.

---

## 7. Arquitectura multistage (`loader.go`)

```
loader.exe → HTTP GET /sc → descifra XOR → inyecta en memoria con VirtualAlloc + EnumSystemLocalesA
```

**¿Por qué multistage?** El loader es pequeño (~6 MB), descarga el payload real solo cuando se ejecuta. Si el AV detecta el payload, el loader puede descargar una versión diferente sin recompilar.

**¿Por qué `EnumSystemLocalesA` para ejecución?** Es una técnica de callback menos detectada que `CreateThread`. Muchos AV monitorean `CreateThread` / `CreateRemoteThread` como indicador de inyección.

---

## 8. Icono y metadatos falsos

El .exe se presenta como "Driver Booster Update Agent" de "IObit" con icono personalizado. Esto no reduce detecciones técnicas pero hace que un análisis superficial (propiedades del archivo, icono) no levante sospechas.

---

## 9. Reducción de detecciones AV (4 detecciones actuales)

Técnicas aplicadas para bajar de 9 a 4:

| Técnica | Efecto |
|---|---|
| Nombres de función cortos (`kLoop`, `sL`, `sd`) | Rompe firmas heurísticas que buscan nombres descriptivos |
| Strings ofuscadas con XOR byte a byte | `strings.exe` no muestra "DriverBooster" ni rutas de registro |
| `-buildid=` y `-trimpath` | Elimina metadatos de compilación Go que los AV usan como firma |
| Imports decorativos (`md5`, `sha256`, `des`, `gzip`) | Cambia el perfil de imports del binario |
| Junk code (`jnk()`, `jnk2()`) | Modifica la huella del código compilado |

**Lo que NO funcionó**: Garble (aumentó a 20), firma digital autofirmada (aumentó a 12), `SetWindowsHookEx` (7 vs 4 de polling).

---

## 10. Limitaciones: qué información NO se captura y por qué

| Información | Por qué no se captura |
|---|---|
| **Campos de contraseña en navegadores** | Los navegadores modernos (Chrome, Edge) procesan campos `type=password` a nivel de renderizado interno y no generan eventos de teclado estándar accesibles desde un hook de usuario. Algunos además usan procesos aislados con sandboxing que bloquean hooks externos. |
| **Texto pegado con Ctrl+V** | El portapapeles no genera eventos de teclado. Ctrl+V dispara VK_CONTROL y VK_V, pero el texto pegadoviene de memoria interna del navegador/aplicación, no de pulsaciones de teclas individuales. |
| **Teclado en pantalla (OSK)** | El teclado en pantalla de Windows genera eventos de puntero (ratón/táctil), no eventos de teclado. `GetAsyncKeyState` no detecta estas entradas porque no pasan por el controlador de teclado físico. |
| **Juegos con DirectInput / RawInput** | Muchos juegos modernos leen el teclado directamente desde el dispositivo (`Raw Input API`)bypaseando la capa de teclado virtual de Windows. `GetAsyncKeyState` lee el estado del teclado virtual, no el dispositivo físico. |
| **Caracteres compuestos (acentos)** | En layouts con teclas muertas (ej. español: ' + a = á), `ToUnicode` debe procesar secuencias de dos teclas consecutivas. El polling puede perder la tecla muerta antes de recibir la vocal, resultando en caracteres incompletos. |
| **Alt+numpad** | Los caracteres ingresados con Alt+código numérico (ej. Alt+164 = ñ) se componen a bajo nivel y no generan eventos de teclado individuales para cada carácter. |

## 11. Resumen de trade-offs

| Decisión | Ganancia | Pérdida |
|---|---|---|
| Go sobre Python | -65% detecciones AV | Más complejidad de compilación |
| Polling sobre hook | -3 detecciones | Puede perder teclas rápidas |
| Clave embebida | Simplicidad | Sin forward secrecy |
| AES-256-GCM | Cifrado autenticado | Sin intercambio de claves |
| TCP raw | Sin cabeceras detectables | Sin encriptación de transporte (TLS) |
