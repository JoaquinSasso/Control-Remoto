"""
Dashboard SSH: panel web local para lanzar comandos en la PC de escritorio vía SSH.

Uso:
    Doble clic en "Iniciar Dashboard.bat" (instala dependencias, levanta el
    server y abre el navegador).

    O a mano:
        pip install -r requirements.txt
        python app.py            -> abrir http://127.0.0.1:8000
        python app.py --abrir    -> lo abre solo cuando el server está listo
"""

import base64
import json
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, StringConstraints
from starlette.middleware.trustedhost import TrustedHostMiddleware

# --- Configuración -----------------------------------------------------------

SSH_DESTINO = "joa@100.108.158.91"
TIMEOUT_SEGUNDOS = 600  # compilaciones largas (gradle, etc.)
# Code page OEM de la PC remota (Windows en español = 850). cmd.exe lee los
# comandos por stdin en esta code page: con UTF-8 (chcp 65001) rompe las tildes.
CODEPAGE_REMOTA = "cp850"
# Vacío = carpeta de usuario de la cuenta SSH en la PC remota (%USERPROFILE%).
# Ojo: `joa` tiene su perfil en C:\Users\nico_, no en C:\Users\joa.
RUTA_INICIAL_EXPLORADOR = ""
TIMEOUT_EXPLORAR = 30

# Solo escucha en la propia notebook: cualquiera que alcance este puerto puede
# ejecutar comandos en la PC remota. Si se cambia HOST para acceder desde otro
# equipo, agregar su IP/nombre a HOSTS_PERMITIDOS.
HOST = "127.0.0.1"
PORT = 8000
HOSTS_PERMITIDOS = ["127.0.0.1", "localhost"]

BASE_DIR = Path(__file__).resolve().parent
ARCHIVO_COMANDOS = BASE_DIR / "comandos.json"
INDEX_HTML = BASE_DIR / "static" / "index.html"

COMANDOS_INICIALES = {
    "hostname": {"nombre": "Hostname", "comando_ssh": "hostname"},
    "whoami": {"nombre": "Usuario actual", "comando_ssh": "whoami"},
    "procesos-python": {
        "nombre": "Procesos Python",
        "comando_ssh": 'tasklist /FI "IMAGENAME eq python.exe"',
    },
    "discos": {
        "nombre": "Espacio en disco",
        "comando_ssh": 'powershell -NoProfile -Command "Get-PSDrive -PSProvider FileSystem"',
    },
}

# --- Persistencia (comandos.json) --------------------------------------------

_lock = threading.Lock()  # los endpoints sync corren en un threadpool


def _leer() -> dict[str, dict]:
    if not ARCHIVO_COMANDOS.exists():
        _escribir(COMANDOS_INICIALES)
        return dict(COMANDOS_INICIALES)
    with ARCHIVO_COMANDOS.open(encoding="utf-8") as f:
        return json.load(f)


def _escribir(datos: dict[str, dict]) -> None:
    # Escritura atómica: si el proceso muere a mitad, comandos.json queda intacto.
    tmp = ARCHIVO_COMANDOS.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    tmp.replace(ARCHIVO_COMANDOS)


def _con_id(id_: str, cmd: dict) -> dict:
    return {"id": id_, **cmd}


# --- Modelos ------------------------------------------------------------------

TextoNoVacio = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class Comando(BaseModel):
    nombre: TextoNoVacio
    comando_ssh: TextoNoVacio


class PedidoEjecucion(BaseModel):
    comando: TextoNoVacio


class PedidoExplorar(BaseModel):
    path: str | None = None


# --- App ----------------------------------------------------------------------

app = FastAPI(title="Dashboard SSH")

# Bloquea DNS rebinding (un dominio externo que resuelve a 127.0.0.1).
app.add_middleware(TrustedHostMiddleware, allowed_hosts=HOSTS_PERMITIDOS)


@app.middleware("http")
async def bloquear_cross_origin(request: Request, call_next):
    """Evita que otra web abierta en el navegador dispare comandos contra esta API (CSRF)."""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "Origen no permitido"}, status_code=403)
    return await call_next(request)


@app.get("/", include_in_schema=False)
def index():
    # no-cache: revalida siempre, así los cambios al HTML se ven con un simple F5.
    return FileResponse(INDEX_HTML, headers={"Cache-Control": "no-cache"})


@app.get("/api/config")
def config():
    return {"destino": SSH_DESTINO, "timeout": TIMEOUT_SEGUNDOS}


@app.get("/api/comandos")
def listar_comandos():
    with _lock:
        return [_con_id(id_, cmd) for id_, cmd in _leer().items()]


@app.post("/api/comandos", status_code=201)
def crear_comando(comando: Comando):
    with _lock:
        datos = _leer()
        id_ = uuid.uuid4().hex[:8]
        datos[id_] = comando.model_dump()
        _escribir(datos)
        return _con_id(id_, datos[id_])


@app.put("/api/comandos/{id_}")
def actualizar_comando(id_: str, comando: Comando):
    with _lock:
        datos = _leer()
        if id_ not in datos:
            raise HTTPException(404, "Comando no encontrado")
        datos[id_] = comando.model_dump()
        _escribir(datos)
        return _con_id(id_, datos[id_])


@app.delete("/api/comandos/{id_}", status_code=204)
def eliminar_comando(id_: str):
    with _lock:
        datos = _leer()
        if datos.pop(id_, None) is None:
            raise HTTPException(404, "Comando no encontrado")
        _escribir(datos)
    return Response(status_code=204)


# --- Ejecución remota ---------------------------------------------------------


def _decodificar(datos: bytes | None) -> str:
    """
    ssh.exe reenvía los bytes tal cual los produce la PC remota. cmd.exe escribe
    en la code page OEM (CODEPAGE_REMOTA), pero hay programas que emiten UTF-8
    por su cuenta. Se intenta UTF-8 estricto primero y, si falla, la code page
    OEM (que acepta cualquier byte).
    """
    if not datos:
        return ""
    try:
        texto = datos.decode("utf-8-sig")
    except UnicodeDecodeError:
        texto = datos.decode(CODEPAGE_REMOTA, errors="replace")
    return texto.replace("\r\n", "\n")


def _argumentos_ssh(comando_remoto: str) -> list[str]:
    ssh = shutil.which("ssh")
    if ssh is None:
        raise HTTPException(500, "No se encontró ssh en el PATH de esta máquina")
    # Lista de argumentos sin shell=True: así `&&`, `|`, etc. los interpreta el
    # cmd.exe remoto y no el de la notebook.
    return [
        ssh,
        "-T",                               # sin terminal: la E/S va por pipes
        "-o", "BatchMode=yes",              # nunca pedir contraseña: fallar en vez de colgarse
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",     # detecta conexiones muertas (p. ej. si se cae Tailscale)
        SSH_DESTINO,
        comando_remoto,
    ]


def _ssh(comando_remoto: str, timeout: int) -> tuple[bytes, bytes, int | None]:
    """Conexión de un solo uso (la usa el explorador). Devuelve (stdout, stderr, código); código None = timeout."""
    try:
        proc = subprocess.run(
            _argumentos_ssh(comando_remoto), stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or b"", exc.stderr or b"", None


class ErrorSesion(Exception):
    """No se pudo abrir la sesión SSH (red, clave, host key...)."""


def _leer_flujo(flujo, cola: queue.Queue) -> None:
    for bloque in iter(lambda: flujo.read1(65536), b""):
        cola.put(bloque)
    cola.put(None)  # EOF: la sesión terminó


def _con_cd_d(linea: str) -> str:
    # En cmd, `cd D:\x` cambia el directorio de D: pero no pasa a esa unidad; con /d sí.
    return re.sub(r"^(\s*(?:cd|chdir))\s+(?!/)", r"\1 /d ", linea, count=1, flags=re.IGNORECASE)


class SesionSSH:
    """
    Una única conexión `ssh destino cmd` que queda abierta: el cmd.exe remoto
    conserva el directorio (cd), las variables (set), etc. entre comandos.

    Protocolo: cada comando entra por stdin dentro de un bloque `( ... ) <nul`
    (así `pause`, `set /p` o un input() reciben EOF en vez de comerse las líneas
    siguientes) y detrás va una línea que imprime un marcador único con el
    errorlevel y el %cd% en stdout, y el marcador solo en stderr. Todo lo que
    llega antes de los marcadores es la salida del comando.
    """

    def __init__(self):
        self._lock = threading.Lock()  # un comando a la vez, como en una consola
        self._proc: subprocess.Popen | None = None
        self._colas: dict[str, queue.Queue] = {}
        self._buffers: dict[str, bytearray] = {}
        self._prompt_mas = b""  # "¿Más? ": cmd lo imprime por cada línea de continuación de un bloque
        self._hubo_sesion = False
        self.cwd: str | None = None  # último directorio conocido; se restaura al reconectar

    def _viva(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _cerrar(self) -> None:
        if self._viva():
            self._proc.kill()  # el cmd remoto muere con la conexión
        self._proc = None

    def _esperar(self, flujo: str, patron: re.Pattern, limite: float) -> tuple[bytes, tuple, str]:
        """Lee `flujo` hasta que aparece `patron`. Devuelve (lo anterior, grupos del match, estado)."""
        buf, cola = self._buffers[flujo], self._colas[flujo]
        while True:
            if m := patron.search(buf):
                # Copiar antes de recortar: el match apunta al mismo bytearray.
                antes, grupos = bytes(buf[:m.start()]), tuple(bytes(g) for g in m.groups())
                del buf[:m.end()]
                return antes, grupos, "ok"
            try:
                bloque = cola.get(timeout=max(0.0, limite - time.monotonic()))
            except queue.Empty:
                return bytes(buf), (), "timeout"
            if bloque is None:
                return bytes(buf), (), "cerrada"
            buf += bloque

    def _resto(self, flujo: str, segundos: float) -> bytes:
        """Todo lo que llegue por `flujo` hasta su EOF o hasta `segundos` (p. ej. el error de ssh al cortarse)."""
        buf, cola = self._buffers[flujo], self._colas[flujo]
        limite = time.monotonic() + segundos
        while True:
            try:
                bloque = cola.get(timeout=max(0.0, limite - time.monotonic()))
            except queue.Empty:
                break
            if bloque is None:
                break
            buf += bloque
        return bytes(buf)

    def _enviar(self, lineas: str, limite: float) -> tuple[bytes, bytes, int | None, str | None, str]:
        """Manda líneas al cmd remoto y espera el marcador. Devuelve (stdout, stderr, errorlevel, cwd, estado)."""
        marca = f"__FIN_{uuid.uuid4().hex}__"
        # "@": que no se repita en pantalla aunque el usuario haya hecho `echo on`.
        texto = lineas + f"@echo {marca} %errorlevel% %cd%& echo {marca} 1>&2\r\n"
        try:
            self._proc.stdin.write(texto.encode(CODEPAGE_REMOTA, errors="replace"))
            self._proc.stdin.flush()
        except OSError:
            return b"", self._resto("err", 2), None, None, "cerrada"

        # El errorlevel tiene que ser un número: si el usuario hizo `echo on`, cmd repite la
        # línea tal cual la recibe ("%errorlevel%" sin expandir) y eso no debe tomarse como el final.
        marca_b = re.escape(marca.encode())
        stdout, grupos, estado = self._esperar("out", re.compile(marca_b + rb" (-?\d+) ([^\r\n]*)\r\n"), limite)
        if estado == "ok":
            stderr, _, estado = self._esperar("err", re.compile(marca_b + rb"[^\r\n]*\r\n"), limite)
        else:
            stderr = self._resto("err", 2 if estado == "cerrada" else 0)
        if estado != "ok":
            return stdout, stderr, None, None, estado
        codigo, cwd = grupos
        return stdout, stderr, int(codigo), cwd.decode(CODEPAGE_REMOTA).strip(), "ok"

    def _iniciar(self) -> None:
        # /q: que cmd no repita cada línea que lee por stdin. /d: sin AutoRun del registro.
        self._proc = subprocess.Popen(
            _argumentos_ssh("cmd /d /q"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self._colas = {"out": queue.Queue(), "err": queue.Queue()}
        self._buffers = {"out": bytearray(), "err": bytearray()}
        for nombre, flujo in (("out", self._proc.stdout), ("err", self._proc.stderr)):
            threading.Thread(target=_leer_flujo, args=(flujo, self._colas[nombre]), daemon=True).start()

        # Sin eco no hay prompt (el /q solo no alcanza con stdin por pipe). Se
        # descarta el banner de Windows y se vuelve al último directorio conocido.
        inicio = "@echo off\r\n" + (f'cd /d "{self.cwd}" 2>nul\r\n' if self.cwd else "")
        _, stderr, _, cwd, estado = self._enviar(inicio, time.monotonic() + 20)
        if estado != "ok":
            self._cerrar()
            if estado == "timeout":
                raise ErrorSesion("La PC remota no respondió al abrir la sesión SSH")
            raise ErrorSesion(_decodificar(stderr).strip() or "No se pudo abrir la sesión SSH")
        self.cwd = cwd

        # Un bloque con una línea de continuación: lo que imprime es el prompt "¿Más? " de este Windows.
        mas, _, _, _, estado = self._enviar("(cd .\r\n) <nul\r\n", time.monotonic() + 10)
        self._prompt_mas = mas if estado == "ok" else b""
        self._hubo_sesion = True

    def estado(self) -> str | None:
        """Directorio actual; abre la sesión si hace falta."""
        if self._viva():  # sin lock: puede haber un comando largo corriendo
            return self.cwd
        with self._lock:
            if not self._viva():
                self._iniciar()
            return self.cwd

    def reiniciar(self) -> str | None:
        """Corta la sesión (y el comando en curso, si hay uno) y abre una nueva en la carpeta de usuario."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.kill()
        with self._lock:
            self._cerrar()
            self.cwd = None
            self._iniciar()
            return self.cwd

    def ejecutar(self, comando: str, timeout: float) -> dict:
        with self._lock:
            aviso = None
            if not self._viva():
                reconexion = self._hubo_sesion
                self._iniciar()
                if reconexion:
                    aviso = "Se abrió una nueva conexión SSH: se conservó el directorio, no las variables de entorno."

            cwd_inicial = self.cwd
            lineas = [_con_cd_d(l) for l in comando.replace("\r\n", "\n").split("\n") if l.strip()]
            # (call ) pone errorlevel en 0: si no, un `set` "hereda" el error del comando anterior.
            bloque = "@(call )\r\n(" + "\r\n".join(lineas) + "\r\n) <nul\r\n"
            inicio = time.perf_counter()
            stdout, stderr, codigo, cwd, estado = self._enviar(bloque, time.monotonic() + timeout)

            # Quitar los "¿Más? " (uno por línea de continuación) que cmd imprime antes de la salida.
            for _ in range(len(lineas)):
                if not self._prompt_mas or not stdout.startswith(self._prompt_mas):
                    break
                stdout = stdout[len(self._prompt_mas):]

            if estado == "ok":
                self.cwd = cwd
            else:
                self._cerrar()
                if estado == "cerrada":
                    aviso = "La sesión SSH terminó (exit o se cortó la conexión). El próximo comando abre una nueva."

            return {
                "comando": comando,
                "stdout": _decodificar(stdout),
                "stderr": _decodificar(stderr),
                "codigo_salida": codigo,
                "timeout": estado == "timeout",
                "duracion_ms": round((time.perf_counter() - inicio) * 1000),
                "cwd_inicial": cwd_inicial,
                "cwd": self.cwd,
                "aviso": aviso,
            }


sesion = SesionSSH()


@app.post("/api/ejecutar")
def ejecutar(pedido: PedidoEjecucion):
    try:
        pedido.comando.encode(CODEPAGE_REMOTA)
    except UnicodeEncodeError as e:
        raise HTTPException(400, f"cmd.exe no puede recibir el carácter {e.object[e.start]!r} (code page {CODEPAGE_REMOTA})")
    try:
        return sesion.ejecutar(pedido.comando, TIMEOUT_SEGUNDOS)
    except ErrorSesion as e:
        raise HTTPException(502, str(e))


@app.get("/api/sesion")
def estado_sesion():
    try:
        return {"cwd": sesion.estado()}
    except ErrorSesion as e:
        raise HTTPException(502, str(e))


@app.post("/api/sesion/reiniciar")
def reiniciar_sesion():
    try:
        return {"cwd": sesion.reiniciar()}
    except ErrorSesion as e:
        raise HTTPException(502, str(e))


# --- Explorador de archivos ---------------------------------------------------

# Es el pipeline `Get-ChildItem | Select-Object Name, IsFolder | ConvertTo-Json`,
# con los arreglos que necesita para no romperse con rutas reales:
#  - Viaja como -EncodedCommand y la ruta, en base64: el cmd.exe remoto no
#    interpreta nada (% ^ & ") y un nombre con ' o ’ no corta el string.
#  - -LiteralPath: los corchetes [ ] de un nombre no se toman como comodines.
#  - @(...) en -InputObject: siempre es un array, aunque haya 1 elemento o ninguno.
#  - Lo no-ASCII sale como \uXXXX: no depende de la code page de la consola remota.
#  - Los errores también salen como JSON por stdout, con el mensaje de Windows.
# Cada script deja su resultado en $r; el inicio y el fin son comunes.
_PS_INICIO = "$ProgressPreference = 'SilentlyContinue'\n"
_PS_FIN = r"""
$json = ConvertTo-Json -InputObject $r -Depth 4 -Compress
[regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
"""

_SCRIPT_CARPETA = r"""
$ruta = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__RUTA_B64__'))
if (-not $ruta) { $ruta = $env:USERPROFILE }
try {
    $dir = Get-Item -LiteralPath $ruta -Force -ErrorAction Stop
    if ($dir -isnot [IO.DirectoryInfo]) { throw "No es una carpeta: $ruta" }
    $items = @(Get-ChildItem -LiteralPath $dir.FullName -ErrorAction Stop |
        Select-Object Name, @{Name='IsFolder';Expression={$_.PSIsContainer}})
    $padre = if ($dir.Parent) { $dir.Parent.FullName } else { $null }
    $r = @{ ok = $true; path = $dir.FullName; padre = $padre; items = $items }
} catch [Management.Automation.ItemNotFoundException] {
    $r = @{ ok = $false; no_existe = $true; error = $_.Exception.Message }
} catch {
    $r = @{ ok = $false; no_existe = $false; error = $_.Exception.Message }
}
"""

# DriveInfo en vez de Get-PSDrive: trae tipo, etiqueta y espacio, y es instantáneo.
# Una unidad sin medio (lector de tarjetas vacío, DVD sin disco) sale con Listo = false.
_SCRIPT_DISCOS = r"""
$discos = foreach ($d in [IO.DriveInfo]::GetDrives()) {
    $item = [ordered]@{ Name = $d.Name; IsFolder = $true; Listo = $d.IsReady }
    if ($d.IsReady) {
        try { $item.Etiqueta = $d.VolumeLabel; $item.Libre = $d.AvailableFreeSpace; $item.Total = $d.TotalSize }
        catch { $item.Listo = $false }
    }
    [pscustomobject]$item
}
$r = @{ ok = $true; items = @($discos) }
"""

# Lo que hay "arriba" de la raíz de un disco: la lista de unidades, como en Windows.
ESTE_EQUIPO = "Este equipo"


def _powershell(script: str) -> dict:
    """Corre un script en la PowerShell remota y devuelve el JSON que deja en $r."""
    script_b64 = base64.b64encode((_PS_INICIO + script + _PS_FIN).encode("utf-16-le")).decode("ascii")
    stdout, stderr, codigo = _ssh(f"powershell -NoProfile -NonInteractive -EncodedCommand {script_b64}", TIMEOUT_EXPLORAR)
    if codigo is None:
        raise HTTPException(504, f"La PC remota no respondió en {TIMEOUT_EXPLORAR} s")
    try:
        return json.loads(stdout)
    except ValueError:
        # Sin JSON: falló ssh (red, clave, host key) o PowerShell no llegó a correr.
        detalle = _decodificar(stderr).strip() or f"Respuesta inválida de la PC remota (código {codigo})"
        raise HTTPException(502, detalle)


@app.post("/api/explorar")
def explorar(pedido: PedidoExplorar):
    ruta = (pedido.path or "").strip() or RUTA_INICIAL_EXPLORADOR

    if ruta.casefold() == ESTE_EQUIPO.casefold():
        discos = sorted(_powershell(_SCRIPT_DISCOS)["items"], key=lambda d: d["Name"])
        return {"path": ESTE_EQUIPO, "padre": None, "discos": True, "items": discos}

    if re.fullmatch(r"[A-Za-z]:", ruta):  # "C:" a secas sería el directorio actual de C:
        ruta += "\\"
    ruta_b64 = base64.b64encode(ruta.encode("utf-8")).decode("ascii")
    r = _powershell(_SCRIPT_CARPETA.replace("__RUTA_B64__", ruta_b64))

    if not r["ok"]:
        raise HTTPException(404 if r["no_existe"] else 400, r["error"])
    path = r["path"] if len(r["path"]) <= 3 else r["path"].rstrip("\\")  # "C:\" conserva su barra
    padre = r["padre"]
    if padre is None and re.fullmatch(r"[A-Za-z]:\\", path):
        padre = ESTE_EQUIPO  # desde la raíz de un disco se sube a la lista de unidades
    items = sorted(r["items"], key=lambda i: (not i["IsFolder"], i["Name"].casefold()))
    return {"path": path, "padre": padre, "discos": False, "items": items}


# --- Arranque -----------------------------------------------------------------


def _dashboard_activo(url: str) -> bool:
    """True si en `url` ya responde este dashboard (p. ej. el launcher se abrió dos veces)."""
    try:
        with urllib.request.urlopen(f"{url}/api/config", timeout=1) as resp:
            return "destino" in json.load(resp)
    except (OSError, ValueError):
        return False


def _abrir_navegador_al_iniciar(servidor: uvicorn.Server, url: str) -> None:
    # `started` se activa recién cuando uvicorn ya está escuchando en el puerto.
    while not servidor.started:
        time.sleep(0.1)
    webbrowser.open(url)


if __name__ == "__main__":
    abrir = "--abrir" in sys.argv
    url = f"http://{'127.0.0.1' if HOST == '0.0.0.0' else HOST}:{PORT}"

    if abrir and _dashboard_activo(url):
        print(f"El dashboard ya está corriendo en {url}; solo se abre el navegador.")
        webbrowser.open(url)
        sys.exit(0)

    print(f"Dashboard SSH -> {url}  (destino: {SSH_DESTINO})")
    servidor = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT))
    if abrir:
        threading.Thread(target=_abrir_navegador_al_iniciar, args=(servidor, url), daemon=True).start()
    try:
        servidor.run()
    except KeyboardInterrupt:  # Ctrl+C: salir sin traceback
        pass
