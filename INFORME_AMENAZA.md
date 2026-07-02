# Informe Técnico de Amenaza — DriverBooster Update Agent

**Clasificación**: TrojanSpy.Win64/DriverBooster.A
**Tipo**: Spyware / Keylogger
**Severidad**: ALTA (CVSS 8.2)
**Fecha de análisis**: Julio 2026

---

## 1. Descripción de la amenaza

DriverBooster Update Agent es un troyano de tipo spyware con funcionalidad de keylogger dirigido a sistemas Windows 10/11 de 64 bits. Se distribuye como un binario compilado en Go que simula ser un agente legítimo de actualización de controladores (driver updater) de IObit. Una vez ejecutado, captura todas las pulsaciones de teclado del sistema víctima, las cifra con AES-256-GCM y las transmite periódicamente por TCP a un servidor de Comando y Control (C2).

El malware emplea un diseño multistage opcional: un loader primario (`loader.exe`) descarga e inyecta shellcode en memoria, mientras que el binario principal (`DriverBooster.exe`) contiene toda la funcionalidad de captura y exfiltración.

---

## 2. Vector de infección

| Vector | Técnica |
|---|---|
| Ingeniería social | El binario llega como archivo adjunto en correo de phishing o descarga desde sitios no oficiales, disfrazado de "Driver Booster Update Agent.msi" o "DriverBooster_Setup.exe" |
| Ejecución del usuario | La víctima ejecuta manualmente el binario (T1204.002) |
| Sin explotación | No requiere vulnerabilidades del sistema — usa solo APIs legítimas de Windows |

**Sistema operativo objetivo**: Microsoft Windows 10/11 x64

---

## 3. TTPs según MITRE ATT&CK

| ID | Nombre | Implementación |
|---|---|---|
| **T1566.001** | Spearphishing Attachment | Vector de entrada: el binario se envía como adjunto malicioso |
| **T1204.002** | User Execution: Malicious File | El usuario ejecuta DriverBooster.exe manualmente |
| **T1055.001** | Process Injection | `loader.go` inyecta shellcode en memoria via `VirtualAlloc` + `EnumSystemLocalesA` |
| **T1547.001** | Registry Run Keys / Startup Folder | Persistencia en `HKCU\...\Run\DriverBooster Scheduler 10.4` |
| **T1056.001** | Input Capture: Keylogging | Captura de teclas via `GetAsyncKeyState` con polling cada 10ms |
| **T1027** | Obfuscated Files or Information | Strings ofuscadas con XOR en el binario; imports decorativos |
| **T1095** | Non-Application Layer Protocol | Comunicación TCP raw al C2 en puerto 4444 |
| **T1041** | Exfiltration Over C2 Channel | Datos cifrados con AES-256-GCM enviados al servidor del atacante |
| **T1070.004** | Indicator Removal: File Deletion | Sin logs locales en disco — todo se transmite y se borra del buffer |

---

## 4. Indicadores de Compromiso (IoCs)

### Indicadores de red

| Tipo | Valor |
|---|---|
| IP C2 | `195.0.1.5` |
| Puerto C2 | `4444` (TCP) |
| Puerto HTTP (loader) | `8080` (TCP) |
| Protocolo | TCP raw con length-prefix (4 bytes big-endian + payload) |
| Patrón de tráfico | Beaconing cada 30 segundos + 5 segundos iniciales |
| User-Agent (loader) | Default Go HTTP client |

### Indicadores de host

| Tipo | Valor |
|---|---|
| Nombre de proceso | `DriverBooster.exe` |
| Nombre de proceso alternativo | `WindowsUpdateService.exe` |
| Ruta de persistencia | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DriverBooster Scheduler 10.4` |
| Ruta de log local | `%APPDATA%\DriverBooster\logs\cache.dat` (si se implementa almacenamiento) |
| DLLs cargadas | `user32.dll`, `advapi32.dll`, `kernel32.dll` |
| APIs clave | `GetAsyncKeyState`, `GetKeyboardState`, `ToUnicode`, `MapVirtualKeyW` |

### Hashes (binario compilado)

| Archivo | SHA-256 |
|---|---|
| `DriverBooster.exe` | (calcular con `sha256sum` o `Get-FileHash`) |
| `WindowsUpdateService.exe` | (calcular con `sha256sum` o `Get-FileHash`) |

---

## 5. Flujo de ataque

```
1. FASE DE ENTREGA
   Correo phishing → DriverBooster_Setup.exe

2. FASE DE EJECUCIÓN
   Usuario ejecuta el binario
   → Pausa 5s (evasión sandbox)
   → Persistencia en Run
   → Inicia captura de teclas

3. FASE DE OPERACIÓN
   Cada tecla → buffer en memoria
   Cada 30s → buffer se cifra con AES-256-GCM
   → Se envía por TCP a 195.0.1.5:4444

4. FASE DE EXFILTRACIÓN
   Servidor C2 descifra y muestra el texto
   Almacena en driver_updates.log
```

---

## 6. Impacto potencial

| Impacto | Descripción |
|---|---|
| **Confidencialidad** | ALTO — Captura contraseñas, correos, mensajes, datos bancarios |
| **Integridad** | BAJO — No modifica archivos ni sistema |
| **Disponibilidad** | BAJO — No afecta la operación del sistema |
| **Privacidad** | ALTO — Registro completo de toda actividad de teclado |

La información capturada puede incluir:
- Credenciales de acceso (correo, banco, redes sociales)
- Números de tarjeta de crédito tipeados
- Mensajes privados y conversaciones
- Código fuente y documentación sensible

---

## 7. Recomendaciones de mitigación

### Para usuarios

1. **Activar 2FA** en todas las cuentas — las contraseñas capturadas no sirven sin el segundo factor
2. **Usar gestor de contraseñas** — Bitwarden, Keepass o similar evitan tipear credenciales
3. **No ejecutar archivos de fuentes no verificadas**
4. **Mantener antivirus actualizado** — Windows Defender detecta el binario en análisis posteriores

### Para equipos de seguridad

1. **Monitorear EventID 13 de Sysmon** — escrituras en clave `Run` por procesos no firmados
2. **Regla de firewall de salida** — bloquear tráfico a puertos no estándar (4444, 8080) desde estaciones de trabajo
3. **Detección de beaconing** — alertar sobre conexiones TCP periódicas a IPs externas en intervalos fijos (30s)
4. **EDR con reglas de captura de input** — `GetAsyncKeyState` como API de monitoreo
5. **Autoruns** programado semanalmente para detectar persistencia no autorizada

---

## 8. Referencias

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1056/001/
- FortiGuard Threat Report: https://www.fortiguard.com/
- VirusTotal: (subir binario para ver detecciones)
