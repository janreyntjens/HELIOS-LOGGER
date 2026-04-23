# HELIOS LOGGER

GUI tool om errors en alerts van LED processors (Helios) te loggen via WebSocket.

## Stack
- Python 3.x + PySide6 (Qt)
- QWebSocket → `ws://<ip>/api/v1/data/rpc/websocket`
- Ingebouwde HTTP server als remote monitor (auto-refresh HTML)
- PyInstaller voor `.exe` builds

## Setup

```powershell
pip install PySide6 requests
python LED_Logger.py
```

## Configuratie

Kopieer `config.example.json` naar `config.json` en pas IP's en namen aan:

```json
{
    "processors": [
        { "name": "Processor 1", "ip": "192.168.1.10", "type": "Helios" }
    ]
}
```

`config.json` en `history.json` zitten in `.gitignore` (lokale data).

## Build (Windows .exe)

```powershell
pip install pyinstaller
pyinstaller LED_Logger.spec
```

Output komt in `dist/` (niet meegecommit).

## Bestanden

| Bestand | Doel |
|---|---|
| `LED_Logger.py` | Hoofdscript (GUI + websocket + http server) |
| `config.example.json` | Voorbeeld configuratie |
| `LED_Logger.spec` | PyInstaller build recept |
| `logo.ico` / `bglogo.png` | Assets |
