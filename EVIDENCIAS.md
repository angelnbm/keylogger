# Evidencias Ejercicio 3 — MITM, Evasión y Mitigación

---

## Parte 1: Análisis VirusTotal

### Resultado obtenido

| Archivo | Detecciones | Motores totales |
|---|---|---|
| `keylogger.py` (código fuente) | 3 / 72 | VirusTotal |
| `WindowsUpdateService.exe` (compilado) | 0 / 72 | VirusTotal |

### Por qué el .py tiene 3 detecciones y el .exe tiene 0

El archivo `.py` está en texto plano. Los motores AV escanean el archivo y encuentran strings que coinciden con firmas conocidas de keyloggers:

- `keyboard.Listener` — patrón de pynput, librería conocida para keylogging
- `winreg` + `CurrentVersion\Run` — patrón de persistencia en registro
- `SetWindowsHookEx` (usado internamente por pynput) — API de hook de teclado

Esto se llama **detección por firma estática de strings** — el motor no ejecuta el código, solo busca patrones de texto conocidos.

Al compilar con PyInstaller (`build.bat`), el código Python se convierte a bytecode y se empaqueta cifrado dentro del ejecutable. Los strings que disparaban las 3 detecciones ya no aparecen en texto plano en el binario → los motores no encuentran sus firmas → **0 detecciones**.

### Conclusión para el informe

> La compilación con PyInstaller actúa como capa de ofuscación efectiva contra detección basada en firmas estáticas. El mismo código que es detectado en forma de script obtiene 0/72 detecciones al ser compilado a binario, ya que el bytecode queda encapsulado y los patrones de texto conocidos desaparecen del ejecutable. Esto demuestra la diferencia entre detección estática (análisis de strings) y detección dinámica (análisis de comportamiento en ejecución).

### Screenshots a tomar
- [ ] VirusTotal con `keylogger.py` mostrando los 3 motores y su categoría
- [ ] VirusTotal con `WindowsUpdateService.exe` mostrando 0/72
- [ ] Anotar qué categoría usan los 3 motores que detectan el .py (firma / heurística / comportamiento)

---

## Parte 2: Ataque MITM con Wireshark

### Qué demuestra esta parte

Un atacante que intercepte el tráfico entre el keylogger y el servidor solo ve bytes cifrados — no puede leer las teclas capturadas sin la clave AES-256. Eso es lo que hay que mostrar con Wireshark.

---

### Paso 1 — Instalar Wireshark

Descargar desde: https://www.wireshark.org/download.html  
Instalar con las opciones por defecto (incluye Npcap, necesario para capturar en loopback).

---

### Paso 2 — Preparar las dos terminales

Abrir **dos terminales** en la carpeta del proyecto:

**Terminal 1 (servidor / atacante):**
```
python server.py
```
Debe mostrar: `[*] Escuchando en 0.0.0.0:4444`

**Terminal 2 (víctima):**
```
python keylogger.py
```
No muestra nada — corre silenciosamente en segundo plano.

---

### Paso 3 — Capturar tráfico con Wireshark

1. Abrir Wireshark
2. Seleccionar la interfaz **Npcap Loopback Adapter** (para tráfico local 127.0.0.1)
3. En el campo de filtro escribir: `tcp.port == 4444`
4. Hacer clic en el ícono azul de tiburón (Start capture)
5. Escribir varias palabras en cualquier ventana del sistema
6. Esperar 30 segundos (el SEND_INTERVAL del config.py)
7. Cuando aparezca un paquete TCP en la lista, hacer clic en él
8. Clic derecho → **Follow** → **TCP Stream**

---

### Paso 4 — Qué mostrar en el TCP Stream

La ventana que aparece mostrará algo similar a:

```
.R.....B..u..X...^..d...S..J....x..U....P..3..z..
..w...[...j..C....$.k...X..L.f.....9.....m........
```

Eso son los 12 bytes de nonce + el ciphertext AES-GCM + el tag de 16 bytes.
**No hay texto legible porque todo está cifrado.**

Cambiar la vista de "ASCII" a "Hex Dump" para que se vea más claro que son bytes sin sentido.

---

### Paso 5 — Comparar con el texto descifrado

Mientras Wireshark muestra los bytes cifrados, en la Terminal 1 (servidor) se ve el texto en claro después de descifrar:

```
============================================================
[2026-06-30 10:15:32] de 127.0.0.1:XXXXX
============================================================
[2026-06-30 10:15:01] h
[2026-06-30 10:15:02] o
[2026-06-30 10:15:03] l
[2026-06-30 10:15:04] a
```

---

### Screenshots a tomar

- [ ] **Screenshot 1**: Las dos terminales corriendo (server.py + keylogger.py)
- [ ] **Screenshot 2**: Wireshark con el filtro `tcp.port == 4444` y el paquete TCP visible en la lista
- [ ] **Screenshot 3**: El TCP Stream mostrando los bytes cifrados (ilegibles)
- [ ] **Screenshot 4**: Terminal del servidor mostrando el texto descifrado en claro
- [ ] **Screenshot 5** (opcional pero recomendado): Las screenshots 3 y 4 lado a lado para mostrar el contraste cifrado vs descifrado

---

### Qué explicar en la defensa sobre el MITM

> "Un atacante que realice un ataque Man-in-the-Middle e intercepte el tráfico TCP entre el keylogger y el servidor C2 solo obtiene el payload cifrado con AES-256-GCM (visible en el TCP Stream de Wireshark). Sin la clave de 256 bits, el contenido es matemáticamente irrecuperable — AES-256 no tiene vulnerabilidades conocidas que permitan forzar la clave en tiempo razonable. El nonce aleatorio por mensaje garantiza además que dos transmisiones del mismo texto producen ciphertexts completamente distintos, dificultando el análisis por correlación."

---

## Checklist final Ejercicio 3

- [ ] Screenshot VirusTotal `keylogger.py` — 3 detecciones
- [ ] Screenshot VirusTotal `WindowsUpdateService.exe` — 0 detecciones
- [ ] Screenshot Wireshark — paquete TCP capturado (filtro tcp.port == 4444)
- [ ] Screenshot Wireshark — TCP Stream con bytes cifrados
- [ ] Screenshot servidor — texto descifrado en claro
- [ ] Análisis escrito: por qué el .py tiene 3 y el .exe tiene 0
- [ ] Análisis escrito: por qué el MITM no puede descifrar el tráfico
