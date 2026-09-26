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
    ssh.exe reenvía los bytes tal cual los produce la PC remota. cmd.exe en un
    Windows en español escribe en la code page OEM (cp850), salvo que se haya
    hecho `chcp 65001` o el programa emita UTF-8 por su cuenta. Se intenta UTF-8
    estricto primero y, si falla, cp850 (que acepta cualquier byte).
    """
    if not datos:
        return ""
    try:
        texto = datos.decode("utf-8-sig")
    except UnicodeDecodeError:
        texto = datos.decode("cp850", errors="replace")
    return texto.replace("\r\n", "\n")


def _ssh(comando_remoto: str, timeout: int) -> tuple[bytes, bytes, int | None]:
    """Corre `ssh destino <comando_remoto>` y devuelve (stdout, stderr, código). Código None = timeout."""
    ssh = shutil.which("ssh")
    if ssh is None:
        raise HTTPException(500, "No se encontró ssh en el PATH de esta máquina")

    # Lista de argumentos sin shell=True: así `&&`, `|`, etc. los interpreta el
    # cmd.exe remoto y no el de la notebook.
    argumentos = [
        ssh,
        "-o", "BatchMode=yes",      # nunca pedir contraseña: fallar en vez de colgarse
        "-o", "ConnectTimeout=10",
        SSH_DESTINO,
        comando_remoto,
    ]
    try:
        proc = subprocess.run(argumentos, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or b"", exc.stderr or b"", None


@app.post("/api/ejecutar")
def ejecutar(pedido: PedidoEjecucion):
    inicio = time.perf_counter()
    stdout, stderr, codigo = _ssh(pedido.comando, TIMEOUT_SEGUNDOS)
    return {
        "comando": pedido.comando,
        "stdout": _decodificar(stdout),
        "stderr": _decodificar(stderr),
        "codigo_salida": codigo,
        "timeout": codigo is None,
        "duracion_ms": round((time.perf_counter() - inicio) * 1000),
    }


# --- Explorador de archivos ---------------------------------------------------

# Es el pipeline `Get-ChildItem | Select-Object Name, IsFolder | ConvertTo-Json`,
# con los arreglos que necesita para no romperse con rutas reales:
#  - Viaja como -EncodedCommand y la ruta, en base64: el cmd.exe remoto no
#    interpreta nada (% ^ & ") y un nombre con ' o ’ no corta el string.
#  - -LiteralPath: los corchetes [ ] de un nombre no se toman como comodines.
#  - @(...) en -InputObject: siempre es un array, aunque haya 1 elemento o ninguno.
#  - Lo no-ASCII sale como \uXXXX: no depende de la code page de la consola remota.
#  - Los errores también salen como JSON por stdout, con el mensaje de Windows.
_SCRIPT_EXPLORAR = r"""
$ProgressPreference = 'SilentlyContinue'
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
$json = ConvertTo-Json -InputObject $r -Depth 4 -Compress
[regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
"""


def _comando_explorar(ruta: str) -> str:
    ruta_b64 = base64.b64encode(ruta.encode("utf-8")).decode("ascii")
    script = _SCRIPT_EXPLORAR.replace("__RUTA_B64__", ruta_b64)
    script_b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {script_b64}"


@app.post("/api/explorar")
def explorar(pedido: PedidoExplorar):
    ruta = (pedido.path or "").strip() or RUTA_INICIAL_EXPLORADOR
    if re.fullmatch(r"[A-Za-z]:", ruta):  # "C:" a secas sería el directorio actual de C:
        ruta += "\\"

    stdout, stderr, codigo = _ssh(_comando_explorar(ruta), TIMEOUT_EXPLORAR)
    if codigo is None:
        raise HTTPException(504, f"La PC remota no respondió en {TIMEOUT_EXPLORAR} s")
    try:
        r = json.loads(stdout)
    except ValueError:
        # Sin JSON: falló ssh (red, clave, host key) o PowerShell no llegó a correr.
        detalle = _decodificar(stderr).strip() or f"Respuesta inválida de la PC remota (código {codigo})"
        raise HTTPException(502, detalle)

    if not r["ok"]:
        raise HTTPException(404 if r["no_existe"] else 400, r["error"])
    path = r["path"] if len(r["path"]) <= 3 else r["path"].rstrip("\\")  # "C:\" conserva su barra
    items = sorted(r["items"], key=lambda i: (not i["IsFolder"], i["Name"].casefold()))
    return {"path": path, "padre": r["padre"], "items": items}


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
