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

import json
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


@app.post("/api/ejecutar")
def ejecutar(pedido: PedidoEjecucion):
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
        pedido.comando,
    ]

    inicio = time.perf_counter()
    try:
        proc = subprocess.run(
            argumentos,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=TIMEOUT_SEGUNDOS,
        )
        stdout, stderr, codigo, timeout = proc.stdout, proc.stderr, proc.returncode, False
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, codigo, timeout = exc.stdout, exc.stderr, None, True

    return {
        "comando": pedido.comando,
        "stdout": _decodificar(stdout),
        "stderr": _decodificar(stderr),
        "codigo_salida": codigo,
        "timeout": timeout,
        "duracion_ms": round((time.perf_counter() - inicio) * 1000),
    }


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
