# Guía de Estudio — Proyecto Keylogger
**Proyecto Unidad 2 · Seguridad Informática · Universidad de Talca**

---

## Ejercicio 1 — Desarrollo del Keylogger (20 pts)

### ¿Cómo captura teclas el keylogger?

`pynput` instala un **hook de teclado a nivel de sistema operativo** usando la API de Windows `SetWindowsHookEx` con el parámetro `WH_KEYBOARD_LL`. Esto significa que el hook es **global** — captura teclas de cualquier aplicación activa, no solo de la ventana del keylogger.

Cada vez que el usuario presiona una tecla, Windows llama automáticamente a `on_press()`. Dentro de esa función:
1. Se convierte la tecla a string con `_format_key()`
2. Se agrega con timestamp al buffer compartido (`buffer.py`)
3. Se escribe también en el log local en disco (`%APPDATA%\svchost_log.txt`)

```python
# Teclas normales tienen key.char ("a", "1", "@")
# Teclas especiales lanzan AttributeError → se usa key.name ("[enter]", "[shift]")
try:
    return key.char
except AttributeError:
    return f"[{key.name}]"
```

---

### ¿Por qué se usa un buffer separado (`buffer.py`)?

Para evitar **importación circular**. `keylogger.py` necesita al `sender.py` para lanzar el hilo de envío, y `sender.py` necesita leer las teclas capturadas. Si ambos se importaran mutuamente habría un error `ImportError: circular import`. La solución es un módulo neutral `buffer.py` que ambos importan sin conocerse entre sí.

---

### ¿Cómo funciona la persistencia?

Se usa el **registro de Windows** bajo la clave:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

**Por qué `HKEY_CURRENT_USER` y no `HKEY_LOCAL_MACHINE`:**
- `HKCU` no requiere privilegios de administrador
- `HKLM` aplica a todos los usuarios del sistema pero necesita admin
- Windows ejecuta automáticamente todo lo que esté en esa clave al iniciar sesión del usuario

```python
# Al arrancar: verifica si ya está registrado
if not is_registered_in_startup():
    add_to_startup()
```

La función `_get_executable_path()` distingue entre ejecución como script (`.py`) y como ejecutable compilado (`sys.frozen = True` cuando PyInstaller/Nuitka compilan el binario). Esto es crucial porque el registro debe apuntar al `.exe`, no al script que no existirá en la máquina víctima.

---

### ¿Qué información NO captura este keylogger y por qué?

| Información no capturada | Razón técnica |
|---|---|
| Contraseñas en Chrome/Firefox | Los navegadores procesan campos `type=password` internamente; algunos bloquean hooks externos en campos sensibles |
| Texto pegado con Ctrl+V | El portapapeles no genera eventos de teclado — es una operación de memoria, no input físico |
| Teclado en pantalla (OSK) | OSK genera eventos de ratón/puntero, no eventos de teclado estándar de Windows |
| Juegos con DirectInput/RawInput | APIs de bajo nivel que bypasean el hook estándar `WH_KEYBOARD_LL` |
| Caracteres compuestos complejos | Secuencias de composición (Alt+numpad) pueden perderse si el proceso de composición ocurre antes del hook |

---

## Ejercicio 2 — Cifrado y Envío (20 pts)

### ¿Por qué AES-256-GCM y no MD5 o SHA-256?

Esta es la pregunta más importante del ejercicio. La distinción es fundamental:

**MD5 y SHA-256 son funciones de HASH — NO son cifrado:**
- Son transformaciones **unidireccionales**: dado el hash, es imposible recuperar el texto original
- Se usan para verificar integridad (firmas digitales, checksums de archivos)
- MD5 está roto criptográficamente (colisiones conocidas desde 2004)
- **No sirven para ocultar información** porque no tienen clave — cualquiera puede calcular el hash

**AES-256-GCM es cifrado simétrico autenticado:**
- **Confidencialidad**: sin la clave de 256 bits, el texto cifrado es indescifrable
- **Autenticación**: el tag de 16 bytes (GCM) detecta si el mensaje fue alterado en tránsito
- **Bidireccional**: quien tiene la clave puede cifrar Y descifrar
- Estándar de la industria, aprobado por NIST

```
MD5("hola") = 4d186321c1a7f0f354b297e8914ab240  ← siempre igual, no hay clave
AES-GCM("hola", clave) = [bytes aleatorios]      ← distinto cada vez (nonce aleatorio)
```

---

### ¿Por qué el nonce debe ser aleatorio en cada mensaje?

El nonce (número usado una sola vez) tiene 12 bytes y se genera con `os.urandom(12)` en cada llamada a `encrypt()`.

**Si se reutilizara el mismo nonce con la misma clave**: AES-GCM se rompe completamente — un atacante que intercepte dos mensajes cifrados con el mismo nonce puede recuperar información sobre el texto plano mediante XOR. Esto se llama *nonce reuse attack*.

---

### ¿Clave embebida vs clave generada dinámicamente?

| Enfoque | Ventaja | Riesgo |
|---|---|---|
| **Embebida en el ejecutable** (lo que implementamos) | Simple, sin intercambio de claves | Si alguien descompila el `.exe` con `strings` o `pyinstxtractor`, obtiene la clave y puede descifrar todos los logs capturados |
| **Generada dinámicamente** | La clave no está en el binario | Requiere un protocolo de intercambio de claves (ej. RSA) — mucho más complejo de implementar |

La solución profesional usa **RSA para el intercambio de clave** (criptografía asimétrica): el servidor tiene un par público/privado, el keylogger genera una clave AES aleatoria, la cifra con la clave pública del servidor y la envía. Así ni la clave AES viaja en el binario. Para este proyecto académico, la clave embebida es aceptable.

---

### ¿Cómo funciona el protocolo de transmisión TCP?

Se usa un protocolo **length-prefix** sencillo:

```
[ 4 bytes big-endian: longitud del payload ][ payload cifrado (nonce + ciphertext + tag) ]
```

El motivo del header de longitud: TCP es un protocolo de stream, no de mensajes. `recv()` puede retornar menos bytes de los esperados. El servidor necesita saber cuántos bytes leer para tener el mensaje completo. `_recv_exact()` itera hasta leer exactamente N bytes.

---

### Estructura del payload cifrado

```
[ nonce (12 bytes) ][ ciphertext (variable) ][ tag GCM (16 bytes) ]
```

El nonce va al inicio sin cifrar porque el receptor lo necesita para descifrar — no es información secreta, solo debe ser único por mensaje. El tag va implícito al final del ciphertext porque `AESGCM.encrypt()` lo agrega automáticamente.

---

## Ejercicio 3 — MITM, Evasión y Mitigación (20 pts)

### ¿Por qué PyInstaller genera más detecciones AV que Nuitka?

**PyInstaller** empaqueta:
1. El código Python compilado a bytecode (`.pyc`)
2. Un **bootloader** (`_MEIPASS`) que extrae y ejecuta el bytecode

Ese bootloader es el mismo para todos los proyectos PyInstaller → los antivirus tienen sus firmas exactas. Windows Defender lo detecta y elimina el archivo en segundos (como viste al compilar).

**Nuitka** convierte el código Python a código C y luego lo compila a código máquina nativo. El resultado no tiene trazas del intérprete Python ni del bootloader → mucho menos detecciones porque no hay firmas conocidas.

Comando PyInstaller:
```bash
pyinstaller --onefile --noconsole --name "WindowsUpdateService" keylogger.py
```

Comando Nuitka:
```bash
python -m nuitka --onefile --windows-console-mode=disable --output-filename=WindowsUpdateService.exe keylogger.py
```

---

### ¿Cómo demostrar el ataque MITM con Wireshark?

**Setup:**
1. Terminal 1: `python server.py` (lado atacante)
2. Terminal 2: `python keylogger.py` (lado víctima)
3. Wireshark → interfaz Loopback → filtro: `tcp.port == 4444`

**Lo que muestra Wireshark:**
- El paquete TCP llega periódicamente (cada 30 segundos)
- El payload son bytes sin sentido — el nonce + ciphertext de AES-GCM
- **Hacer clic derecho → Follow → TCP Stream** para ver el contenido completo

**Qué demuestra esto:**
Un atacante que intercepte el tráfico (MITM entre víctima y servidor C2) solo ve bytes cifrados. Sin la clave AES-256, el mensaje es matemáticamente irrecuperable. Eso es lo que el ejercicio pide demostrar.

---

### Análisis de evasión para VirusTotal

Al subir el ejecutable a VirusTotal verás 3 tipos de detección:

| Tipo | Qué significa | Ejemplo |
|---|---|---|
| **Firma (Signature)** | El motor tiene el hash o bytes exactos del binario en su base de datos | `Trojan.GenericKD.XXXX` |
| **Heurística** | El motor analiza el comportamiento esperado del binario sin ejecutarlo | `Suspicious.MachineCode` |
| **Comportamiento** | El motor ejecuta el binario en sandbox y detecta sus acciones | `Behavior.Keylogger` |

Un ejecutable PyInstaller típicamente tiene 15-25 detecciones. Nuitka tiene 3-8. En ambos casos, habrá motores que no lo detecten — eso cumple el requisito "al menos una herramienta IDS/AV conocida no lo detecta".

---

### Contramedidas — resumen para la defensa

**Para usuarios:**
- Antivirus actualizado (detecta keyloggers conocidos por firma)
- 2FA en todas las cuentas (invalida credenciales robadas)
- Gestores de contraseñas con autocompletado (no se tipean las contraseñas)
- No ejecutar archivos de fuentes desconocidas

**Para especialistas TI:**
- **Sysmon EventID 13**: alerta sobre escrituras en clave `Run` del registro por procesos no firmados
- **IDS con reglas de beaconing**: detectar conexiones TCP salientes periódicas a puertos no estándar
- **EDR con detección de comportamiento**: `SetWindowsHookEx(WH_KEYBOARD_LL)` desde proceso no firmado es una señal de alerta
- **Firewall de salida con allowlist**: solo ejecutables autorizados pueden hacer conexiones salientes
- **Autoruns (Sysinternals)**: auditoría periódica de entradas en la clave `Run`

---

## Ejercicio 4 — Informe Técnico (10 pts)

### Nombre y clasificación de la amenaza

```
TrojanSpy:Win32/PynputLogger.A
Tipo: Spyware / Keylogger
Severidad: ALTA
```

### TTPs MITRE ATT&CK — los más importantes para recordar

| ID | Nombre | Cómo aplica |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Vector de infección — .exe disfrazado de archivo legítimo |
| T1204.002 | User Execution: Malicious File | El usuario ejecuta el binario manualmente |
| **T1547.001** | Registry Run Keys | Persistencia en `HKCU\...\Run` |
| **T1056.001** | Input Capture: Keylogging | Core del malware — hook de teclado global |
| T1027 | Obfuscated Files | Binario compilado con Nuitka/PyInstaller |
| T1095 | Non-Application Layer Protocol | Comunicación TCP raw al C2 en puerto 4444 |
| **T1041** | Exfiltration Over C2 Channel | Datos cifrados enviados al servidor del atacante |

Los marcados en negrita son los más importantes — son los que definen la funcionalidad core.

### IoCs clave

```
Registro : HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateService
Archivo  : %APPDATA%\svchost_log.txt
Red      : TCP saliente al puerto 4444 cada ~30 segundos (beaconing)
Proceso  : WindowsUpdateService.exe sin firma digital de Microsoft
```

---

## Preguntas probables en la defensa

**"Modifica el intervalo de envío a 60 segundos"**
→ Cambiar `SEND_INTERVAL = 60` en `config.py`. Eso es todo — `sender.py` lee esa variable en su `time.sleep()`.

**"Cambia el cifrado de AES-256-GCM a AES-128-GCM"**
→ En `crypto.py`, la clave debe ser de 16 bytes en vez de 32. En `config.py`, `ENCRYPTION_KEY` debe tener 32 caracteres hex (no 64). `AESGCM` detecta el tamaño de la clave automáticamente.

**"Explica qué pasa si el servidor no está disponible"**
→ `_transmit()` en `sender.py` tiene `timeout=5`. Si el servidor no responde en 5 segundos, captura la excepción `socket.error` silenciosamente. Las teclas capturadas en ese intervalo se pierden (no se reintenta). Una mejora sería guardar en disco y reintentar.

**"Agrega un filtro para no capturar teclas de función (F1-F12)"**
→ En `on_press()`, agregar antes de `key_buffer.append()`:
```python
if hasattr(key, 'name') and key.name in ('f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12'):
    return
```

**"¿Por qué HKCU y no HKLM para la persistencia?"**
→ `HKCU` no requiere privilegios de administrador. `HKLM` aplica a todos los usuarios pero necesita `admin`. Para un malware que el usuario ejecuta sin privilegios, `HKCU` es el mecanismo viable.

**"¿Por qué no usaste MD5 para cifrar?"**
→ MD5 es una función de hash, no de cifrado. Es unidireccional — no se puede recuperar el texto original. No tiene clave. Tampoco es válido para integridad porque tiene colisiones conocidas. AES-GCM es cifrado simétrico autenticado: reversible con la clave correcta y con verificación de integridad incluida.

**"Demuestra el flujo completo en vivo"**
→ Terminal 1: `python server.py` | Terminal 2: `python keylogger.py` | escribe algo | espera 30s | muestra `received_logs.txt` con el texto descifrado.

**"¿Cómo eliminar el keylogger del sistema?"**
→ Matar el proceso, borrar el ejecutable, y eliminar la clave del registro:
```
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateService /f
del "%APPDATA%\svchost_log.txt"
```

---

## Estructura de archivos del proyecto

```
keylogger/
├── keylogger.py        # Captura de teclado + persistencia (E1)
├── buffer.py           # Buffer compartido thread-safe (E1)
├── config.py           # Parámetros configurables (E1-E2)
├── crypto.py           # AES-256-GCM encrypt/decrypt (E2)
├── sender.py           # Hilo de envío periódico (E2)
├── server.py           # Receptor/descifrador lado atacante (E2)
├── build.bat           # Compilar con PyInstaller (E3)
├── build_nuitka.bat    # Compilar con Nuitka (E3)
├── mitigacion.py       # Análisis de contramedidas (E3)
├── informe_amenaza.py  # Informe técnico de amenaza (E4)
└── informe_amenaza.txt # Informe generado (E4)
```
