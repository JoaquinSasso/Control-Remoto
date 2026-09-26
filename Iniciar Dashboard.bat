@echo off
rem Launcher del Dashboard SSH: instala dependencias si faltan, levanta el
rem server y abre el navegador cuando esta listo.
rem Cerrar esta ventana (o Ctrl+C) detiene el server.

title Dashboard SSH
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] No se encontro Python en el PATH.
    pause
    exit /b 1
)

python -c "import fastapi, uvicorn" >nul 2>nul
if errorlevel 1 (
    echo Instalando dependencias...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Fallo la instalacion de dependencias.
        pause
        exit /b 1
    )
)

python app.py --abrir

rem Si el server termino por un error (p. ej. puerto ocupado), dejar el mensaje visible.
if errorlevel 1 pause
