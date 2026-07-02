# DriverBooster Update Agent

Proyecto académico de Seguridad Informática — Universidad de Talca.

Simula un agente de actualización de drivers que en realidad es un keylogger con arquitectura multistage.

## Componentes

- **`agent.go`** — Keylogger en Go. Captura teclas por polling (`GetAsyncKeyState`), las cifra con AES-256-GCM y las envía por TCP al servidor C2. Se persiste en `HKCU\...\Run`.
- **`loader.go`** — Stage 1. Descarga shellcode cifrado vía HTTP, lo descifra con XOR y lo inyecta en memoria.
- **`server.py`** — Servidor C2 dual: TCP (recibe logs cifrados en puerto 4444) + HTTP (sirve payloads en puerto 8080).
- **`keylogger.py`** — Versión Python legada del keylogger (reemplazada por `agent.go`).
- **`config.py`** — Parámetros compartidos (IP, puerto, clave AES).

## Compilar

### Requisitos

- [Go](https://go.dev/dl/) 1.21 o superior
- [goversioninfo](https://github.com/josephspurrier/goversioninfo) (para el icono)

```bash
# Instalar goversioninfo
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
```

### Compilar el agente

```bash
# Desde la raíz del proyecto:
build.bat
# Genera: dist\DriverBooster.exe
```

O manualmente:

```bash
go build -ldflags="-s -w -H windowsgui -buildid=" -trimpath -o dist\DriverBooster.exe agent.go
```

### Compilar el loader

```bash
go build -ldflags="-s -w -H windowsgui" -o dist\loader.exe loader.go
```

## Demo rápida

```bash
# 1. En Parrot (atacante):
python3 server.py

# 2. En Windows (víctima):
dist\DriverBooster.exe

# 3. Escribir, esperar 35s, los logs aparecen en el server.
```
