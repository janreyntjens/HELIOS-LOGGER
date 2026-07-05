import sys
import os
import time
import json
import socket
import traceback
import ctypes
import base64
import hashlib
import hmac
import html as html_escape
import ipaddress
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

# --- VEILIGE IMPORT ---
# --- GEKORRIGEERDE IMPORT (Regel 16 t/m 25) ---
try:
    import requests
    import urllib3
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
        QFrame, QLabel, QPushButton, QTextEdit, QMessageBox, QDialog,
        QLineEdit, QListWidget, QListWidgetItem, QProgressBar, QSizePolicy, 
        QComboBox, QScrollArea, QTabWidget, QTreeWidget, QTreeWidgetItem, 
        QHeaderView, QSplitter, QTableWidget, QTableWidgetItem, QCheckBox
    )
    from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QUrl, QObject, QMetaObject
    from PySide6.QtGui import QPalette, QColor, QIcon, QFont
    from PySide6.QtWebSockets import QWebSocket
    from PySide6.QtNetwork import QAbstractSocket, QNetworkInterface
except ImportError as e:
    import ctypes
    ctypes.windll.user32.MessageBoxW(0, f"Error: {e}\nRun: pip install PySide6 requests", "Startup Error", 0x10)
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONSTANTEN ---
APP_NAME = "LED Logger"
VERSION = "1.1.0-beta"
LOGO_FILE = "logo.ico"  # <--- HIER ZAT DE FOUT (ontbrekend aanhalingsteken)
if getattr(sys, "frozen", False):
    APP_BASE_DIR = os.path.dirname(sys.executable)
else:
    APP_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(APP_BASE_DIR, "config.json")
HISTORY_FILE = os.path.join(APP_BASE_DIR, "history.json")
WEB_DEFAULT_USERNAME = "admin"
WEB_DEFAULT_PASSWORD = "1234"
WINDOWS_APP_USER_MODEL_ID = "janreyntjens.LEDLogger"


def hash_password(password):
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()

def resource_path(relative_path):
    """Geeft het juiste pad terug, of we nu vanuit .py of vanuit een PyInstaller .exe draaien."""
    try:
        base_path = sys._MEIPASS  # PyInstaller tijdelijke folder
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def save_config(data):
    """Slaat de configuratie op naar config.json."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Save error: {e}")

def load_json(file, default):
    if not os.path.exists(file): return default
    try:
        with open(file, 'r') as f: return json.load(f)
    except: return default

def save_json(file, data):
    try:
        with open(file, 'w') as f: json.dump(data, f, indent=4)
    except: pass

def set_windows_app_user_model_id():
    """Helps Windows map the running process to the packaged .exe icon in the taskbar."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_USER_MODEL_ID)
    except Exception:
        pass

# ==========================================
#       MODULES
# ==========================================

class LogWebServer(BaseHTTPRequestHandler):
    log_data = []  
    device_statuses = {}  # Nieuw: houdt status per IP bij
    last_clear_time = 0  # Track wanneer laatste clear was
    auth_username = WEB_DEFAULT_USERNAME
    auth_password_hash = hash_password(WEB_DEFAULT_PASSWORD)

    @classmethod
    def configure_auth(cls, username, password_hash):
        cls.auth_username = str(username or WEB_DEFAULT_USERNAME).strip() or WEB_DEFAULT_USERNAME
        cls.auth_password_hash = str(password_hash or hash_password(WEB_DEFAULT_PASSWORD))

    def log_message(self, format, *args):
        # In windowed .exe builds stderr may be unavailable; suppress default handler logging.
        return

    def _is_authorized(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8")
            if ":" not in raw:
                return False
            username, password = raw.split(":", 1)
            if username != self.auth_username:
                return False
            return hmac.compare_digest(hash_password(password), self.auth_password_hash)
        except Exception:
            return False

    def _send_auth_required(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="LED Logger Remote Monitor"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Authentication required")

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(int(status_code))
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.send_header("Content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    @staticmethod
    def _is_valid_mac(value):
        return bool(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", str(value or "").strip().lower()))

    @staticmethod
    def _set_helios_identify_http(ip, mac, enabled):
        payload = {
            "dev": {
                "receivers": {
                    mac: {
                        "identifyEnabled": bool(enabled)
                    }
                }
            }
        }
        url = f"http://{ip}/api/v1/data"
        for method in ("POST", "PATCH"):
            try:
                resp = requests.request(method, url, json=payload, timeout=1.5)
                if not (200 <= int(resp.status_code) < 300):
                    continue

                try:
                    data = resp.json() if resp.content else {}
                    got = (
                        data.get("dev", {})
                        .get("receivers", {})
                        .get(mac, {})
                        .get("identifyEnabled")
                    )
                    if isinstance(got, bool):
                        return got == bool(enabled)
                except Exception:
                    pass

                try:
                    read = requests.get(f"http://{ip}/api/v1/public?dev.receivers.{mac}", timeout=1.5)
                    if 200 <= int(read.status_code) < 300:
                        data = read.json() if read.content else {}
                        got = (
                            data.get("dev", {})
                            .get("receivers", {})
                            .get(mac, {})
                            .get("identifyEnabled")
                        )
                        if isinstance(got, bool):
                            return got == bool(enabled)
                except Exception:
                    pass
            except Exception:
                continue
        return False

    def do_POST(self):
        try:
            if not self._is_authorized():
                self._send_auth_required()
                return

            path = self.path.split("?", 1)[0]
            if path != "/identify":
                self._send_json(404, {"ok": False, "error": "Not found"})
                return

            data = self._read_json_body()
            if not isinstance(data, dict):
                self._send_json(400, {"ok": False, "error": "Invalid JSON payload"})
                return

            ip = str(data.get("ip", "")).strip()
            mac = str(data.get("mac", "")).strip().lower().replace("-", ":")
            enabled = bool(data.get("enabled", False))

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "Invalid IP"})
                return

            if not self._is_valid_mac(mac):
                self._send_json(400, {"ok": False, "error": "Invalid MAC"})
                return

            ok = self._set_helios_identify_http(ip, mac, enabled)
            if ok:
                self._send_json(200, {"ok": True, "state": enabled})
            else:
                self._send_json(502, {"ok": False, "error": "Identify command failed"})
        except Exception as e:
            self._send_json(500, {"ok": False, "error": str(e)})

    def do_GET(self):
        try:
            if not self._is_authorized():
                self._send_auth_required()
                return

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            # Bereken statistieken
            total = len(self.device_statuses)
            online = sum(1 for s in self.device_statuses.values() if s in ["ok", "error"])
            status_color = "#2ecc71" if online == total and total > 0 else "#f1c40f" if online > 0 else "#e74c3c"

            # Snellere refresh direct na een clear
            refresh_interval = 2 if (time.time() - self.last_clear_time) < 10 else 5

            page_html = f"""
            <html>
            <head>
                <title>{APP_NAME} Remote Monitor</title>
                <meta http-equiv="refresh" content="{refresh_interval}">
                <style>
                    body {{ background-color: #0f0f0f; color: #ececec; font-family: 'Segoe UI', sans-serif; padding: 30px; margin: 0; }}

                    /* Custom Dark Scrollbar */
                    ::-webkit-scrollbar {{ width: 12px; }}
                    ::-webkit-scrollbar-track {{ background: #1a1a1a; }}
                    ::-webkit-scrollbar-thumb {{ background: #333; border-radius: 6px; border: 3px solid #1a1a1a; }}

                    .header {{
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        border-bottom: 2px solid #2a82da;
                        padding-bottom: 15px;
                        margin-bottom: 20px;
                    }}

                    h2 {{ color: #2a82da; margin: 0; letter-spacing: 1px; }}

                    /* Status Indicator Style */
                    .status-bar {{
                        background: #181818;
                        padding: 10px 20px;
                        border-radius: 20px;
                        border: 1px solid #333;
                        font-weight: bold;
                        display: flex;
                        align-items: center;
                        gap: 10px;
                    }}
                    .dot {{ height: 12px; width: 12px; background-color: {status_color}; border-radius: 50%; display: inline-block; }}

                    .entry {{ padding: 8px 12px; background: #181818; border-radius: 4px; margin-bottom: 4px; border-left: 4px solid #333; font-family: 'Consolas', monospace; }}
                    .time {{ color: #666; font-size: 12px; margin-right: 10px; }}
                    .device {{ color: #9aa4b2; font-size: 12px; margin-right: 10px; }}
                    .meta {{ color: #8e98a8; font-size: 12px; margin-right: 10px; }}
                    .meta .kv {{ margin-right: 8px; }}
                    .red {{ border-left-color: #e74c3c; color: #ff6b6b; font-weight: bold; }}
                    .orange {{ border-left-color: #ff9800; color: #ff9800; font-weight: bold; }}
                    .green {{ border-left-color: #2ecc71; color: #2ecc71; }}
                    .system {{ border-left-color: #777; color: #b7b7b7; font-style: italic; }}
                    .id-toggle {{ float: right; display: inline-flex; align-items: center; gap: 6px; color: #9aa4b2; font-size: 12px; }}
                    .id-toggle input {{ width: 14px; height: 14px; accent-color: #2ecc71; cursor: pointer; }}
                    .id-toggle span {{ user-select: none; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>{APP_NAME} Live LOG</h2>
                    <div class="status-bar">
                        <span class="dot"></span>
                        SYSTEM ONLINE: {online} / {total} DEVICES
                    </div>
                </div>
                <div id="logs">
            """
            for entry in self.log_data[-100:]:
                try:
                    if not isinstance(entry, dict):
                        continue
                    color_class = "system" if entry.get("ip") == "SYSTEM" else entry.get("color", "gray")
                    ts = html_escape.escape(str(entry.get("time", "--:--:--")))
                    msg_raw = str(entry.get("msg", ""))
                    msg = html_escape.escape(msg_raw)
                    ip_raw = str(entry.get("ip", "") or "").strip()

                    identify_html = ""
                    receiver_info = entry.get("receiver_info", {}) if isinstance(entry.get("receiver_info", {}), dict) else {}
                    mac_raw = str(receiver_info.get("mac", "") or "").strip().lower().replace("-", ":")
                    sfp_raw = str(receiver_info.get("sfp", "") or "").strip()
                    output_raw = str(receiver_info.get("output", "") or "").strip()
                    tile_raw = str(receiver_info.get("chain_pos", "") or "").strip()
                    device_txt = "SYSTEM" if ip_raw == "SYSTEM" else (ip_raw or "-")
                    device_html = f'<span class="device">[{html_escape.escape(device_txt)}]</span>'

                    meta_parts = []
                    if sfp_raw and sfp_raw != "-":
                        meta_parts.append(f'<span class="kv">OPT:{html_escape.escape(sfp_raw)}</span>')
                    if output_raw and output_raw != "-":
                        meta_parts.append(f'<span class="kv">PORT:{html_escape.escape(output_raw)}</span>')
                    if tile_raw and tile_raw != "-":
                        meta_parts.append(f'<span class="kv">TILE:{html_escape.escape(tile_raw)}</span>')
                    meta_html = f'<span class="meta">{"".join(meta_parts)}</span>' if meta_parts else ""

                    if ip_raw and ip_raw != "SYSTEM" and self._is_valid_mac(mac_raw):
                        ip_attr = html_escape.escape(ip_raw, quote=True)
                        mac_attr = html_escape.escape(mac_raw, quote=True)
                        identify_html = (
                            f'<label class="id-toggle">'
                            f'<input class="identify-cb" type="checkbox" data-ip="{ip_attr}" data-mac="{mac_attr}">'
                            f'<span>ID</span>'
                            f'</label>'
                        )

                    page_html += f'<div class="entry {color_class}"><span class="time">[{ts}]</span>{device_html}{meta_html} {msg}{identify_html}</div>'
                except Exception:
                    continue

            page_html += """
                </div>
                <script>
                    (() => {
                        const keyPrefix = 'idstate:';
                        const controls = document.querySelectorAll('.identify-cb');
                        controls.forEach((cb) => {
                            const ip = cb.dataset.ip || '';
                            const mac = cb.dataset.mac || '';
                            if (!ip || !mac) return;
                            const storageKey = keyPrefix + ip + '|' + mac;
                            const saved = localStorage.getItem(storageKey);
                            if (saved === '1') cb.checked = true;

                            cb.addEventListener('change', async () => {
                                const enabled = !!cb.checked;
                                cb.disabled = true;
                                try {
                                    const res = await fetch('/identify', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ ip, mac, enabled })
                                    });
                                    let data = {};
                                    try { data = await res.json(); } catch (_) {}
                                    if (!res.ok || !data.ok) {
                                        throw new Error((data && data.error) ? data.error : 'Identify command failed');
                                    }
                                    localStorage.setItem(storageKey, enabled ? '1' : '0');
                                } catch (err) {
                                    cb.checked = !enabled;
                                    alert('Identify failed: ' + (err && err.message ? err.message : 'unknown error'));
                                } finally {
                                    cb.disabled = false;
                                }
                            });
                        });
                    })();
                </script>
            </body>
            </html>
            """
            self.wfile.write(page_html.encode("utf-8"))
        except Exception as e:
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"Remote monitor error: {e}".encode("utf-8", errors="replace"))
            except Exception:
                pass

def severity_to_color(severity):
    """Map Helios severity levels to log colors."""
    sev = str(severity).lower().strip() if severity else ""
    
    # Debug: log what we receive
    # print(f"DEBUG: severity='{severity}' -> '{sev}'")
    
    # 'none' means alert cleared/resolved
    if sev in ["none", "null"]:
        return "green"
    if sev in [""]:
        return "gray"
    
    # Helios severity mapping
    if sev in ["critical"]: 
        return "red"
    if sev in ["warning", "error"]: 
        return "orange"
    if sev in ["info", "notice"]: 
        return "green"
    
    # Unknown severity
    return "gray"

def normalize_log_color(color, ip=""):
    """Force logs into 4 colors: system=gray, recover=green, warning=orange, error=red."""
    if str(ip or "").strip().upper() == "SYSTEM":
        return "gray"

    c = str(color or "").strip().lower()
    if c in ("red", "error", "critical"):
        return "red"
    if c in ("orange", "warning", "warn", "yellow"):
        return "orange"
    if c in ("green", "recover", "ok", "success"):
        return "green"
    return "gray"

class HeliosSocket(QObject):
    error_detected = Signal(str, str, str)

    def __init__(self, ip, name, ws_path="/api/v1/data/rpc/websocket", parent=None):
        super().__init__(parent)
        self.ip = ip.strip()
        self.name = name
        self.active_errors = set()
        
        self.ws = QWebSocket()
        path = str(ws_path or "/api/v1/data/rpc/websocket").strip()
        if not path.startswith("/"):
            path = "/" + path
        self.url = f"ws://{self.ip}{path}"
        self.ws.textMessageReceived.connect(self.on_message)
        
        self.retry_timer = QTimer(self)
        self.retry_timer.timeout.connect(self.check_connection)
        self.retry_timer.start(5000) 
        self.check_connection()

    def check_connection(self):
        if self.ws.state() == QAbstractSocket.UnconnectedState:
            self.ws.open(QUrl(self.url))

    def on_message(self, message):
        try:
            data = json.loads(message)
            params = data.get("params", {})
            current_message_errors = {}

            if "sys" in params:
                for k, v in params["sys"].get("alerts", {}).items():
                    current_message_errors[k] = (self.format_error(k, v), v)
            if "dev" in params:
                for k, v in params["dev"].get("ingest", {}).get("alerts", {}).items():
                    current_message_errors[k] = (self.format_error(k, v), v)

            if current_message_errors:
                for err_id, (msg, raw_data) in current_message_errors.items():
                    if err_id not in self.active_errors:
                        color, msg = self._resolve_helios_alert_style(err_id, msg, raw_data)
                        self.error_detected.emit(color, f"{self.name}: {msg}", self.ip)
                        self.active_errors.add(err_id)
            
            if "sys" in params or "dev" in params:
                for old_err in list(self.active_errors):
                    if old_err not in current_message_errors:
                        self.active_errors.remove(old_err)
        except: pass

    def _resolve_helios_alert_style(self, alert_key, formatted_msg, raw_data):
        key = str(alert_key or "").strip().lower()
        if not isinstance(raw_data, dict):
            text = str(raw_data or "").strip().lower()
            full_text = str(formatted_msg or "").strip().lower()

            if text in ("none", "null") or full_text.endswith("] none") or full_text.endswith("] null"):
                if not formatted_msg.lower().startswith("recover:"):
                    return "green", f"Recover: {formatted_msg}"
                return "green", formatted_msg

            if key.startswith("ethdrop") and "dropped link" in full_text:
                m = re.search(r"dropped\s+link\s*:\s*(\d+)", full_text, flags=re.IGNORECASE)
                if m:
                    try:
                        if int(m.group(1)) > 0:
                            return "red", formatted_msg
                    except ValueError:
                        pass
                return "red", formatted_msg

            if key == "tilebackupmissing" and "backup missing" in full_text:
                return "red", formatted_msg

            return "orange", formatted_msg

        severity = raw_data.get("severity", "error")
        color = severity_to_color(severity)

        brief = str(raw_data.get("brief", "")).strip()
        desc = str(raw_data.get("desc", "")).strip()
        brief_l = brief.lower()
        desc_l = desc.lower()

        # Helios uses 'None' for cleared/resolved alerts.
        if brief_l in ("none", "null") or desc_l in ("none", "null"):
            if not formatted_msg.lower().startswith("recover:"):
                return "green", f"Recover: {formatted_msg}"
            return "green", formatted_msg

        # ethDrop alerts: any dropped link count > 0 is an active fault.
        if key.startswith("ethdrop") and ("dropped link" in brief_l or "dropped link" in desc_l):
            dropped = None
            src_txt = brief if "dropped link" in brief_l else desc
            m = re.search(r"dropped\s+link\s*:\s*(\d+)", src_txt, flags=re.IGNORECASE)
            if m:
                try:
                    dropped = int(m.group(1))
                except ValueError:
                    dropped = None

            if dropped is not None:
                if dropped > 0:
                    return "red", formatted_msg
                if not formatted_msg.lower().startswith("recover:"):
                    return "green", f"Recover: {formatted_msg}"
                return "green", formatted_msg

            # If we cannot parse count but got a dropped-link alert, fail safe to red.
            return "red", formatted_msg

        # tileBackupMissing with explicit missing state should stay fault (red).
        if key == "tilebackupmissing" and ("backup missing" in brief_l or "backup missing" in desc_l):
            return "red", formatted_msg

        return color, formatted_msg

    def format_error(self, key, val):
        parts = []
        if isinstance(val, dict):
            brief = str(val.get("brief", "")).strip()
            desc = str(val.get("desc", "")).strip()
            brief_l = brief.lower()
            desc_l = desc.lower()
            show_key = brief_l in ("none", "null") or desc_l in ("none", "null")

            if show_key:
                parts.append(f"[{key}]")
            if brief: parts.append(brief)
            if desc and desc != brief: parts.append(f"| {desc}")
            if not parts:
                parts.append(str(key))
        else:
            value_txt = str(val).strip()
            value_l = value_txt.lower()
            if value_l in ("none", "null"):
                parts.append(f"[{key}] {value_txt}")
            else:
                parts.append(value_txt if value_txt else str(key))
        return " ".join(parts)

    def send_receiver_identify(self, receiver_mac, enabled):
        """Send identify toggle for a receiver MAC over the active Helios websocket."""
        try:
            if self.ws.state() != QAbstractSocket.ConnectedState:
                return False
            mac = str(receiver_mac or "").strip().lower()
            if not mac:
                return False
            payload = {
                "jsonrpc": "2.0",
                "id": int(time.time() * 1000) % 1000000,
                "method": "set",
                "params": {
                    "dev": {
                        "receivers": {
                            mac: {
                                "identifyEnabled": bool(enabled)
                            }
                        }
                    }
                }
            }
            self.ws.sendTextMessage(json.dumps(payload))
            return True
        except Exception:
            return False

    def stop(self):
        self.retry_timer.stop()
        self.ws.close()


BROMPTON_POLL_INTERVAL_SEC = 3
BROMPTON_INPUT_STATUS_CANDIDATE_PATHS = (
    "input",
    "input/all/status",
    "input/status",
    "input/source/status",
    "input/sources/status",
    "devices/input/status",
    "devices/inputs/status",
)
BROMPTON_FAN_RPM_MIN = {
    "case.one": 1000,
    "case.two": 1000,
    "fpga": 3000,
}
BROMPTON_TEMP_WARN_C = {
    "ambient": 45,
    "cpu": 70,
    "gpu": 70,
    "fpga": 75,
    "main": 65,
    "psu": 70,
}


class BromptonSocket(QObject):
    """HTTP API monitor voor Brompton Tessera processors."""
    error_detected = Signal(str, str, str)  # color, message, ip

    def __init__(self, ip, name, poll_interval=BROMPTON_POLL_INTERVAL_SEC, parent=None):
        super().__init__(parent)
        self.ip = ip.strip()
        self.name = name
        self.base_url = f"http://{self.ip}/api"
        self.last_seen_ok = False
        self._state = {}
        self.active_errors = set()
        self.poll_timer = None

        try:
            self.poll_interval_sec = max(2, int(poll_interval))
        except (TypeError, ValueError):
            self.poll_interval_sec = BROMPTON_POLL_INTERVAL_SEC

        # Sommige Tessera setups antwoorden op HTTPS of geven non-JSON payloads terug.
        self.base_urls = [f"http://{self.ip}/api", f"https://{self.ip}/api"]

    @Slot()
    def start_polling(self):
        if self.poll_timer is not None:
            return
        self.poll_timer = QTimer()
        self.poll_timer.setInterval(self.poll_interval_sec * 1000)
        self.poll_timer.timeout.connect(self.poll_health)
        QTimer.singleShot(150, self.poll_health)
        self.poll_timer.start()

    def _api_get(self, path, timeout=1.0):
        """Return (reachable, value, status_code, used_url)."""
        for base in self.base_urls:
            url = f"{base}/{path}"
            try:
                resp = requests.get(url, timeout=timeout, verify=False)
            except Exception:
                continue

            status = int(resp.status_code)

            # Device reageert wel; ook bij auth/404 blijven we dit als reachable zien.
            if status in (401, 403, 404):
                return True, None, status, url

            if status != 200:
                continue

            if not resp.content:
                return True, {}, status, url

            # JSON indien mogelijk, anders plain text teruggeven.
            try:
                return True, resp.json(), status, url
            except Exception:
                txt = (resp.text or "").strip()
                return True, txt, status, url

        return False, None, None, None

    def _first_scalar(self, payload, preferred_key=None):
        if isinstance(payload, (int, float, str, bool)):
            return payload
        if isinstance(payload, dict):
            if preferred_key and preferred_key in payload:
                return payload.get(preferred_key)
            # Negeer typische response wrapper velden en pak eerste scalar waarde.
            for k, v in payload.items():
                if k in ("response-code", "response", "status"):
                    continue
                if isinstance(v, (int, float, str, bool)):
                    return v
            for v in payload.values():
                if isinstance(v, (int, float, str, bool)):
                    return v
        return None

    def _to_number_or_text(self, value):
        if value is None:
            return None
        if isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, str):
            v = value.strip()
            if not v:
                return None
            try:
                if "." in v:
                    return float(v)
                return int(v)
            except (ValueError, TypeError):
                return v
        return value

    def _to_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _to_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(int(value))
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("true", "1", "on", "enabled", "active", "ok"):
                return True
            if v in ("false", "0", "off", "disabled", "inactive", "failed"):
                return False
        return None

    def _normalize_input_status(self, value):
        if value is None:
            return None
        if isinstance(value, bool):
            return "connected" if value else "disconnected"
        if isinstance(value, (int, float)):
            i = int(value)
            if i in (0, 1):
                return "connected" if i else "disconnected"
            return str(i)

        txt = str(value).strip().lower().replace("_", " ").replace("-", " ")
        if not txt:
            return None
        if txt in ("true", "yes", "on", "up"):
            return "connected"
        if txt in ("false", "no", "off", "down"):
            return "disconnected"
        return txt

    def _looks_like_input_name(self, key):
        k = str(key or "").strip().lower().replace("_", "").replace("-", "")
        if not k:
            return False
        if k.startswith("input") and any(ch.isdigit() for ch in k):
            return True
        if k.startswith("in") and k[2:].isdigit():
            return True
        for prefix in ("hdmi", "dp", "dvi", "sdi", "source"):
            if k.startswith(prefix):
                return True
        return False

    def _normalize_input_name(self, name, fallback_index=None):
        txt = str(name or "").strip()
        if not txt and fallback_index is not None:
            txt = f"Input {fallback_index + 1}"
        if not txt:
            return None

        raw = txt.replace("_", " ").replace("-", " ").strip()
        low = raw.lower()
        if low.startswith("in") and raw[2:].isdigit():
            return f"Input {int(raw[2:])}"
        if low.startswith("input"):
            tail = raw[5:].strip()
            if tail.isdigit():
                return f"Input {int(tail)}"
        return raw

    def _extract_input_status_from_item(self, item):
        if not isinstance(item, dict):
            return self._normalize_input_status(item)

        for key in ("status", "state", "connection", "signal", "link", "connected", "present", "active", "locked", "value"):
            if key not in item:
                continue
            raw = item.get(key)
            if isinstance(raw, bool):
                if key == "active":
                    return "active" if raw else "inactive"
                return "connected" if raw else "disconnected"
            if isinstance(raw, (int, float)):
                i = int(raw)
                if key == "active":
                    return "active" if i else "inactive"
                if i in (0, 1):
                    return "connected" if i else "disconnected"
            normalized = self._normalize_input_status(raw)
            if normalized is not None:
                return normalized
        return None

    def _extract_input_status_map(self, payload):
        found = {}

        def add_status(name, status, fallback_index=None):
            norm_name = self._normalize_input_name(name, fallback_index=fallback_index)
            norm_status = self._normalize_input_status(status)
            if norm_name and norm_status is not None:
                found[norm_name] = norm_status

        # Fallback for Tessera /api/input payloads where status is implicit in metadata.
        root = payload
        if isinstance(root, dict) and isinstance(root.get("input"), dict):
            root = root.get("input")
        if isinstance(root, dict):
            ports = root.get("ports")
            if isinstance(ports, dict):
                for port_type, port_group in ports.items():
                    if not isinstance(port_group, dict):
                        continue
                    for port_idx, port_data in port_group.items():
                        if not isinstance(port_data, dict):
                            continue

                        status_value = None
                        meta = port_data.get("meta-data")
                        if isinstance(meta, dict):
                            resolution = meta.get("resolution")
                            refresh = meta.get("refresh-rate")
                            width = None
                            height = None
                            if isinstance(resolution, dict):
                                width = self._to_int(resolution.get("width"))
                                height = self._to_int(resolution.get("height"))
                            refresh_i = self._to_int(refresh)

                            if width is not None and height is not None and refresh_i is not None:
                                if width > 0 and height > 0 and refresh_i > 0:
                                    status_value = "connected"
                                else:
                                    status_value = "no signal"

                        if status_value is None:
                            status_value = self._extract_input_status_from_item(port_data)
                        if status_value is None:
                            continue

                        idx_txt = str(port_idx).strip()
                        try:
                            idx_num = int(idx_txt)
                            port_name = f"{str(port_type).upper()} {idx_num + 1}"
                        except (TypeError, ValueError):
                            port_name = f"{str(port_type).upper()} {idx_txt}"
                        add_status(port_name, status_value)

        def walk(node):
            if isinstance(node, list):
                for idx, item in enumerate(node):
                    if isinstance(item, dict):
                        name = item.get("name") or item.get("input") or item.get("source") or item.get("label") or item.get("id")
                        status = self._extract_input_status_from_item(item)
                        if name is not None and status is not None:
                            add_status(name, status, fallback_index=idx)
                        walk(item)
                    else:
                        status = self._normalize_input_status(item)
                        if status is not None:
                            add_status(None, status, fallback_index=idx)
                return

            if not isinstance(node, dict):
                return

            if "name" in node:
                status = self._extract_input_status_from_item(node)
                if status is not None:
                    add_status(node.get("name"), status)

            for container_key in ("inputs", "input", "sources", "source", "ports"):
                child = node.get(container_key)
                if isinstance(child, (dict, list)):
                    walk(child)

            for key, value in node.items():
                if self._looks_like_input_name(key):
                    status = self._extract_input_status_from_item(value)
                    if status is not None:
                        add_status(key, status)
                    continue

                if isinstance(value, (dict, list)):
                    walk(value)

        walk(payload)
        return found

    def _input_change_style(self, old_status, new_status):
        new_txt = str(new_status or "").lower()
        old_txt = str(old_status or "").lower()
        bad_tokens = ("disconnect", "no signal", "fail", "loss", "down", "unplug")
        good_tokens = ("connect", "active", "ok", "up", "locked", "present")

        is_bad = any(token in new_txt for token in bad_tokens)
        was_bad = any(token in old_txt for token in bad_tokens)
        is_good = any(token in new_txt for token in good_tokens)

        if is_bad:
            return "Error", "red"
        if is_good and was_bad:
            return "Recover", "green"
        return "Info", "gray"

    def _parse_uptime_seconds(self, value):
        txt = str(value or "").strip().lower()
        if not txt:
            return None

        total = 0
        num = ""
        unit_map = {"d": 86400, "h": 3600, "m": 60, "s": 1}
        for ch in txt:
            if ch.isdigit():
                num += ch
                continue
            if ch in unit_map and num:
                total += int(num) * unit_map[ch]
                num = ""
            elif ch in (" ", ","):
                continue
            else:
                num = ""
        return total if total > 0 else None

    def _flatten_scalars(self, node, prefix=""):
        out = {}
        if isinstance(node, dict):
            for key, value in node.items():
                key_txt = str(key)
                new_prefix = f"{prefix}.{key_txt}" if prefix else key_txt
                out.update(self._flatten_scalars(value, new_prefix))
            return out
        if isinstance(node, list):
            for idx, value in enumerate(node):
                new_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                out.update(self._flatten_scalars(value, new_prefix))
            return out
        if prefix:
            out[prefix] = node
        return out

    def _extract_active_source(self, payload):
        root = payload
        if isinstance(root, dict) and isinstance(root.get("input"), dict):
            root = root.get("input")
        if not isinstance(root, dict):
            return None

        active = root.get("active")
        if not isinstance(active, dict):
            return None
        source = active.get("source")
        if not isinstance(source, dict):
            return None

        port_type = str(source.get("port-type") or source.get("type") or "").strip().upper()
        port_number = self._to_int(source.get("port-number"))
        if port_number is not None:
            port_number += 1
        if port_type and port_number is not None:
            return f"{port_type} {port_number}"
        if port_type:
            return port_type
        if port_number is not None:
            return f"Input {port_number}"
        return None

    def _extract_input_signal_map(self, payload):
        result = {}
        root = payload
        if isinstance(root, dict) and isinstance(root.get("input"), dict):
            root = root.get("input")
        if not isinstance(root, dict):
            return result

        ports = root.get("ports")
        if not isinstance(ports, dict):
            return result

        for port_type, port_group in ports.items():
            if not isinstance(port_group, dict):
                continue
            for port_idx, port_data in port_group.items():
                if not isinstance(port_data, dict):
                    continue
                idx_txt = str(port_idx).strip()
                try:
                    idx_num = int(idx_txt)
                    name = f"{str(port_type).upper()} {idx_num + 1}"
                except (TypeError, ValueError):
                    name = f"{str(port_type).upper()} {idx_txt}"

                meta = port_data.get("meta-data")
                if not isinstance(meta, dict):
                    continue

                resolution = meta.get("resolution") if isinstance(meta.get("resolution"), dict) else {}
                width = self._to_int(resolution.get("width"))
                height = self._to_int(resolution.get("height"))
                refresh = self._to_int(meta.get("refresh-rate"))
                bit_depth = self._to_int(meta.get("bit-depth"))
                sampling = str(meta.get("sampling") or "").strip().lower()

                hdr_fmt = ""
                hdr_meta = meta.get("hdr")
                if isinstance(hdr_meta, dict):
                    hdr_fmt = str(hdr_meta.get("format") or "").strip().lower()

                if width is not None and height is not None and refresh is not None and width > 0 and height > 0 and refresh > 0:
                    hdr_part = f", {hdr_fmt}" if hdr_fmt else ""
                    bd_part = f", {bit_depth}-bit" if bit_depth is not None and bit_depth > 0 else ""
                    samp_part = f", {sampling}" if sampling else ""
                    result[name] = f"{width}x{height}@{refresh}Hz{bd_part}{samp_part}{hdr_part}"
                else:
                    result[name] = "no signal"
        return result

    def _extract_network_state(self, payload):
        root = payload
        if isinstance(root, dict) and isinstance(root.get("output"), dict):
            root = root.get("output")
        if isinstance(root, dict) and isinstance(root.get("network"), dict):
            root = root.get("network")
        if not isinstance(root, dict):
            return {}

        out = {}
        failover = root.get("failover")
        if isinstance(failover, dict):
            settings = failover.get("settings") if isinstance(failover.get("settings"), dict) else {}
            state = failover.get("state") if isinstance(failover.get("state"), dict) else {}
            out["failover.enabled"] = self._to_bool(settings.get("enabled"))
            out["failover.role"] = str(settings.get("role") or "").strip().lower() or None
            out["failover.is_active"] = self._to_bool(state.get("is-active"))
            out["failover.partner_present"] = self._to_bool(state.get("is-partner-present"))

        genlock = root.get("genlock")
        if isinstance(genlock, dict):
            out["genlock.source"] = str(genlock.get("source") or "").strip().lower() or None
            out["genlock.internal_rate"] = self._to_int(genlock.get("internal-rate"))

        return out

    def _extract_system_state(self, payload):
        root = payload
        if isinstance(root, dict) and isinstance(root.get("system"), dict):
            root = root.get("system")
        if not isinstance(root, dict):
            return {}

        out = {
            "processor_name": str(root.get("processor-name") or "").strip() or None,
            "processor_type": str(root.get("processor-type") or "").strip() or None,
            "serial_number": str(root.get("serial-number") or "").strip() or None,
            "software_version": str(root.get("software-version") or "").strip() or None,
            "uptime_raw": str(root.get("uptime") or "").strip() or None,
        }

        out["uptime_seconds"] = self._parse_uptime_seconds(out.get("uptime_raw"))

        temp = root.get("temperature")
        if isinstance(temp, dict):
            for key, value in self._flatten_scalars(temp, "temperature").items():
                if isinstance(value, (int, float)):
                    out[key] = float(value)

        fan = root.get("fan")
        if isinstance(fan, dict):
            one = fan.get("case", {}).get("one") if isinstance(fan.get("case"), dict) else None
            two = fan.get("case", {}).get("two") if isinstance(fan.get("case"), dict) else None
            fpga = fan.get("fpga") if isinstance(fan.get("fpga"), dict) else None
            if isinstance(one, dict):
                out["fan.case.one.speed"] = self._to_int(one.get("speed"))
                out["fan.case.one.status"] = self._to_bool(one.get("status"))
            if isinstance(two, dict):
                out["fan.case.two.speed"] = self._to_int(two.get("speed"))
                out["fan.case.two.status"] = self._to_bool(two.get("status"))
            if isinstance(fpga, dict):
                out["fan.fpga.speed"] = self._to_int(fpga.get("speed"))
                out["fan.fpga.status"] = self._to_bool(fpga.get("status"))

        return out

    def _parse_loop_state_summary(self, raw_value):
        """Return (issues, seen_ok) for Tessera cable loop state payloads."""
        raw = str(raw_value or "").strip()
        if not raw:
            return None, False

        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            return None, False

        issues = []
        seen_ok = False
        for part in parts:
            left, sep, right = part.partition(":")
            status_txt = (left if sep else part).strip().lower().replace("_", "-")
            detail_txt = right.strip() if sep else ""

            if status_txt == "loop-found":
                seen_ok = True
                continue
            if status_txt == "no-loop-found":
                label = "No connection"
            elif status_txt == "incorrect-loop-found":
                label = "Incorrect loop"
            elif status_txt == "one-to-many-error":
                label = "One-to-many error"
            else:
                continue

            port = ""
            if "->" in detail_txt:
                port = detail_txt.split("->", 1)[0].strip()
            if port:
                issues.append(f"{label} ({port})")
            else:
                issues.append(label)

        if issues:
            return issues, False
        if seen_ok:
            return [], True
        return None, False

    def _compact_payload_text(self, payload, max_len=1100):
        try:
            txt = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        except Exception:
            txt = str(payload)
        if len(txt) > max_len:
            return txt[:max_len] + " ..."
        return txt

    @Slot()
    def trigger_test(self):
        """Emit a snapshot with key Tessera API values for this processor."""
        summary_paths = [
            "system",
            "devices/statistics",
            "input",
            "input/active",
            "output/network",
            "output/network/cable-redundancy",
            "output/network/cable-redundancy/loops/1/state",
            "output/network/cable-redundancy/loops/2/state",
            "output/network/cable-redundancy/loops/3/state",
            "output/network/cable-redundancy/loops/4/state",
        ]

        self.error_detected.emit(
            "gray",
            f"Info,Controller,{self.name},BROMPTON,{self.ip},--,Test started",
            self.ip,
        )

        any_ok = False
        for path in summary_paths:
            try:
                reachable, payload, status, _used_url = self._api_get(path, timeout=1.2)
            except Exception:
                reachable = False
                payload = None
                status = None

            if not reachable:
                continue
            if status in (401, 403):
                self.error_detected.emit(
                    "orange",
                    f"Warning,Controller,{self.name},BROMPTON,{self.ip},--,Test [{path}]: auth required ({status})",
                    self.ip,
                )
                continue
            if status == 404:
                continue

            any_ok = True
            value_txt = self._compact_payload_text(payload)
            self.error_detected.emit(
                "gray",
                f"Info,Controller,{self.name},BROMPTON,{self.ip},--,Test [{path}]: {value_txt}",
                self.ip,
            )

        if any_ok:
            self.error_detected.emit(
                "green",
                f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,Test complete",
                self.ip,
            )
        else:
            self.error_detected.emit(
                "red",
                f"Error,Controller,{self.name},BROMPTON,{self.ip},--,Test failed: no API responses",
                self.ip,
            )

    @Slot()
    def poll_health(self):
        failed = 0
        reachable_hits = 0
        auth_limited = False
        current = {}

        system_payload = None
        output_network_payload = None
        input_payload = None

        try:
            reachable, payload, status, _used_url = self._api_get("devices/statistics", timeout=0.8)
            if reachable:
                reachable_hits += 1
                if status in (401, 403):
                    auth_limited = True
                elif status not in (404,):
                    stats_root = payload
                    if isinstance(stats_root, dict) and isinstance(stats_root.get("devices"), dict):
                        stats_root = stats_root.get("devices")
                    if isinstance(stats_root, dict) and isinstance(stats_root.get("statistics"), dict):
                        stats_root = stats_root.get("statistics")
                    if isinstance(stats_root, dict):
                        current["error_count"] = self._to_int(stats_root.get("error-count"))
                        current["online_count"] = self._to_int(stats_root.get("online-count"))
                        current["associated_count"] = self._to_int(stats_root.get("associated-count"))
            else:
                failed += 1
        except Exception:
            failed += 1

        try:
            reachable, payload, status, _used_url = self._api_get("system", timeout=0.8)
            if reachable:
                reachable_hits += 1
                if status in (401, 403):
                    auth_limited = True
                elif status not in (404,):
                    system_payload = payload
                    system_state_seed = self._extract_system_state(payload)
                    current["software_version"] = system_state_seed.get("software_version")
                    current["fan_case_1"] = system_state_seed.get("fan.case.one.status")
                    current["fan_case_2"] = system_state_seed.get("fan.case.two.status")
                    current["fan_fpga"] = system_state_seed.get("fan.fpga.status")
            else:
                failed += 1
        except Exception:
            failed += 1

        if reachable_hits == 0:
            if not self.last_seen_ok:
                return
            self.last_seen_ok = False
            self.error_detected.emit("red", f"{self.name}: BROMPTON API unreachable", self.ip)
            return

        if not self.last_seen_ok:
            self.last_seen_ok = True
            self.error_detected.emit("green", f"{self.name}: BROMPTON API online", self.ip)

        if auth_limited:
            self.error_detected.emit(
                "orange",
                f"Warning,Controller,{self.name},BROMPTON,{self.ip},--,API requires authentication for some endpoints",
                self.ip,
            )

        prev_error_count = self._to_int(self._state.get("error_count"))
        curr_error_count = self._to_int(current.get("error_count"))
        if curr_error_count is not None and curr_error_count != prev_error_count:
            if curr_error_count > 0:
                severity = "Error"
                color = "red"
            else:
                severity = "Recover"
                color = "green"
            self.error_detected.emit(
                color,
                f"{severity},Controller,{self.name},BROMPTON,{self.ip},--,Devices reporting error: {curr_error_count}",
                self.ip,
            )

        prev_online_count = self._to_int(self._state.get("online_count"))
        curr_online_count = self._to_int(current.get("online_count"))
        if (
            curr_online_count is not None
            and prev_online_count is not None
            and curr_online_count != prev_online_count
        ):
            self.error_detected.emit(
                "gray",
                f"Info,Controller,{self.name},BROMPTON,{self.ip},--,Devices online count: {curr_online_count}",
                self.ip,
            )

        prev_assoc_count = self._to_int(self._state.get("associated_count"))
        curr_assoc_count = self._to_int(current.get("associated_count"))
        if curr_assoc_count is not None and prev_assoc_count is not None and curr_assoc_count != prev_assoc_count:
            delta = curr_assoc_count - prev_assoc_count
            if delta < 0:
                severity = "Error"
                color = "red"
                change_txt = f"{delta}"
            elif delta > 0:
                severity = "Recover"
                color = "green"
                change_txt = f"+{delta}"
            else:
                severity = "Info"
                color = "gray"
                change_txt = "0"
            self.error_detected.emit(
                color,
                f"{severity},Controller,{self.name},BROMPTON,{self.ip},--,Associated tiles changed: {prev_assoc_count} -> {curr_assoc_count} ({change_txt})",
                self.ip,
            )

        # Read richer blocks once per poll for source/failover/genlock/temperature/fan RPM/uptime/identity logs.
        try:
            reachable, payload, status, _used_url = self._api_get("output/network", timeout=0.8)
            if reachable and status not in (401, 403, 404):
                output_network_payload = payload
        except Exception:
            output_network_payload = None

        try:
            reachable, payload, status, _used_url = self._api_get("input", timeout=0.8)
            if reachable and status not in (401, 403, 404):
                input_payload = payload
        except Exception:
            input_payload = None

        if input_payload is not None:
            active_source = self._extract_active_source(input_payload)
            prev_active_source = self._state.get("active_source")
            if prev_active_source and active_source and prev_active_source != active_source:
                self.error_detected.emit(
                    "gray",
                    f"Info,Controller,{self.name},BROMPTON,{self.ip},--,Active input changed: {prev_active_source} -> {active_source}",
                    self.ip,
                )
            if active_source:
                self._state["active_source"] = active_source

            signal_map = self._extract_input_signal_map(input_payload)
            prev_signal_map = self._state.get("input_signal_map")
            if isinstance(prev_signal_map, dict):
                for input_name, signal_desc in signal_map.items():
                    old_desc = prev_signal_map.get(input_name)
                    if old_desc is None or old_desc == signal_desc:
                        continue
                    severity, color = self._input_change_style(old_desc, signal_desc)
                    self.error_detected.emit(
                        color,
                        f"{severity},Controller,{self.name},BROMPTON,{self.ip},--,Input format changed [{input_name}]: {old_desc} -> {signal_desc}",
                        self.ip,
                    )
            self._state["input_signal_map"] = signal_map

        if output_network_payload is not None:
            net_state = self._extract_network_state(output_network_payload)
            prev_net_state = self._state.get("network_state")
            if isinstance(prev_net_state, dict):
                for key, new_value in net_state.items():
                    old_value = prev_net_state.get(key)
                    if old_value == new_value or old_value is None or new_value is None:
                        continue
                    label_map = {
                        "failover.enabled": "Failover enabled",
                        "failover.role": "Failover role",
                        "failover.is_active": "Failover active",
                        "failover.partner_present": "Failover partner present",
                        "genlock.source": "Genlock source",
                        "genlock.internal_rate": "Genlock internal rate",
                    }
                    label = label_map.get(key, key)
                    txt_new = str(new_value).lower() if isinstance(new_value, bool) else str(new_value)
                    txt_old = str(old_value).lower() if isinstance(old_value, bool) else str(old_value)
                    severity, color = self._input_change_style(txt_old, txt_new)
                    self.error_detected.emit(
                        color,
                        f"{severity},Controller,{self.name},BROMPTON,{self.ip},--,{label} changed: {txt_old} -> {txt_new}",
                        self.ip,
                    )
            self._state["network_state"] = net_state

        if system_payload is not None:
            system_state = self._extract_system_state(system_payload)
            prev_system_state = self._state.get("system_state")
            if not isinstance(prev_system_state, dict):
                prev_system_state = {}

            # Identity drift detection.
            for key, label in (
                ("processor_name", "Processor name"),
                ("processor_type", "Processor type"),
                ("serial_number", "Serial number"),
                ("software_version", "Software version"),
            ):
                old_v = prev_system_state.get(key)
                new_v = system_state.get(key)
                if old_v and new_v and old_v != new_v:
                    self.error_detected.emit(
                        "orange",
                        f"Warning,Controller,{self.name},BROMPTON,{self.ip},--,{label} changed: {old_v} -> {new_v}",
                        self.ip,
                    )

            # Uptime reset = reboot indication.
            old_uptime = prev_system_state.get("uptime_seconds")
            new_uptime = system_state.get("uptime_seconds")
            if isinstance(old_uptime, int) and isinstance(new_uptime, int) and new_uptime + 30 < old_uptime:
                self.error_detected.emit(
                    "orange",
                    f"Warning,Controller,{self.name},BROMPTON,{self.ip},--,Processor reboot detected (uptime reset: {old_uptime}s -> {new_uptime}s)",
                    self.ip,
                )

            # Temperature threshold alerts + recover.
            for temp_key, warn_c in BROMPTON_TEMP_WARN_C.items():
                state_key = f"temperature.{temp_key}"
                temp_value = system_state.get(state_key)
                if not isinstance(temp_value, (int, float)):
                    continue
                err_id = f"temp:{temp_key}"
                was_active = err_id in self.active_errors
                if temp_value >= warn_c:
                    if not was_active:
                        self.active_errors.add(err_id)
                        self.error_detected.emit(
                            "red",
                            f"Error,Controller,{self.name},BROMPTON,{self.ip},--,High temperature {temp_key}: {temp_value:.1f}C (threshold {warn_c}C)",
                            self.ip,
                        )
                else:
                    if was_active and temp_value <= (warn_c - 2):
                        self.active_errors.discard(err_id)
                        self.error_detected.emit(
                            "green",
                            f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,Temperature normal {temp_key}: {temp_value:.1f}C",
                            self.ip,
                        )

            # Fan RPM anomaly alerts + recover.
            for fan_key, min_rpm in BROMPTON_FAN_RPM_MIN.items():
                rpm_key = f"fan.{fan_key}.speed"
                rpm_value = system_state.get(rpm_key)
                if not isinstance(rpm_value, int):
                    continue
                err_id = f"fanrpm:{fan_key}"
                was_active = err_id in self.active_errors
                if rpm_value < min_rpm:
                    if not was_active:
                        self.active_errors.add(err_id)
                        self.error_detected.emit(
                            "red",
                            f"Error,Controller,{self.name},BROMPTON,{self.ip},--,Fan RPM low {fan_key}: {rpm_value} (threshold {min_rpm})",
                            self.ip,
                        )
                else:
                    if was_active and rpm_value >= (min_rpm + 150):
                        self.active_errors.discard(err_id)
                        self.error_detected.emit(
                            "green",
                            f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,Fan RPM normal {fan_key}: {rpm_value}",
                            self.ip,
                        )

            self._state["system_state"] = system_state

        fan_labels = {
            "fan_case_1": "Case fan 1",
            "fan_case_2": "Case fan 2",
            "fan_fpga": "FPGA fan",
        }
        for fan_key, fan_label in fan_labels.items():
            prev = self._to_bool(self._state.get(fan_key))
            curr = self._to_bool(current.get(fan_key))
            if curr is None or curr == prev:
                continue
            err_id = f"fan:{fan_key}"
            if curr:
                self.active_errors.discard(err_id)
                self.error_detected.emit(
                    "green",
                    f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,{fan_label} status: normal",
                    self.ip,
                )
            else:
                self.active_errors.add(err_id)
                self.error_detected.emit(
                    "red",
                    f"Error,Controller,{self.name},BROMPTON,{self.ip},--,{fan_label} status: failed",
                    self.ip,
                )

        # Log status changes of Tessera inputs (connected/disconnected/active...) when available.
        input_status_map = {}
        preferred_path = self._state.get("input_status_path")
        candidate_paths = []
        if preferred_path:
            candidate_paths.append(preferred_path)
        for path in BROMPTON_INPUT_STATUS_CANDIDATE_PATHS:
            if path not in candidate_paths:
                candidate_paths.append(path)

        for path in candidate_paths:
            try:
                reachable, payload, status, _used_url = self._api_get(path, timeout=0.6)
            except Exception:
                continue
            if not reachable or status in (401, 403, 404):
                continue

            parsed = self._extract_input_status_map(payload)
            if not parsed:
                continue

            input_status_map = parsed
            self._state["input_status_path"] = path
            break

        if input_status_map:
            prev_input_status_map = self._state.get("input_status_map")
            if isinstance(prev_input_status_map, dict):
                for input_name, new_status in input_status_map.items():
                    old_status = prev_input_status_map.get(input_name)
                    if old_status is None or old_status == new_status:
                        continue
                    severity, color = self._input_change_style(old_status, new_status)
                    self.error_detected.emit(
                        color,
                        f"{severity},Controller,{self.name},BROMPTON,{self.ip},--,Input status changed [{input_name}]: {old_status} -> {new_status}",
                        self.ip,
                    )
            self._state["input_status_map"] = input_status_map

        # Tessera's cable redundancy loop state is the closest match for a network cable disconnect log.
        loop_numbers = self._state.get("cable_loop_numbers")
        if not isinstance(loop_numbers, list) or not loop_numbers:
            discovered_loops = []
            net_root = output_network_payload
            if isinstance(net_root, dict) and isinstance(net_root.get("output"), dict):
                net_root = net_root.get("output")
            if isinstance(net_root, dict) and isinstance(net_root.get("network"), dict):
                net_root = net_root.get("network")
            if isinstance(net_root, dict):
                cable = net_root.get("cable-redundancy") if isinstance(net_root.get("cable-redundancy"), dict) else {}
                loops = cable.get("loops") if isinstance(cable.get("loops"), dict) else {}
                for key in loops.keys():
                    try:
                        discovered_loops.append(int(key))
                    except (TypeError, ValueError):
                        continue
            loop_numbers = sorted(set(discovered_loops)) if discovered_loops else [1, 2]
            self._state["cable_loop_numbers"] = loop_numbers

        for loop_number in loop_numbers:
            loop_key = f"cable_loop_{loop_number}"
            loop_path = f"output/network/cable-redundancy/loops/{loop_number}/state"
            loop_err_id = f"cable_loop:{loop_number}"
            try:
                reachable, payload, status, _used_url = self._api_get(loop_path, timeout=0.6)
            except Exception:
                reachable = False
                payload = None
                status = None

            if not reachable:
                continue
            if status in (401, 403, 404):
                continue

            loop_state_raw = self._first_scalar(payload, preferred_key="state")
            issues, seen_ok = self._parse_loop_state_summary(loop_state_raw)
            if issues is None and not seen_ok:
                continue

            prev_issues = self._state.get(loop_key)
            if not isinstance(prev_issues, list):
                prev_issues = []

            current_issues = list(issues or [])
            prev_set = set(prev_issues)
            curr_set = set(current_issues)

            if prev_set == curr_set and ((bool(current_issues)) or seen_ok):
                continue

            self._state[loop_key] = current_issues
            if current_issues:
                self.active_errors.add(loop_err_id)
                for issue in current_issues:
                    if issue in prev_set:
                        continue
                    self.error_detected.emit(
                        "red",
                        f"Error,Controller,{self.name},BROMPTON,{self.ip},--,Cable redundancy loop {loop_number}: {issue}",
                        self.ip,
                    )

                for issue in prev_issues:
                    if issue in curr_set:
                        continue
                    self.error_detected.emit(
                        "green",
                        f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,Cable redundancy loop {loop_number}: resolved ({issue})",
                        self.ip,
                    )
            else:
                self.active_errors.discard(loop_err_id)
                if prev_issues or seen_ok:
                    self.error_detected.emit(
                        "green",
                        f"Recover,Controller,{self.name},BROMPTON,{self.ip},--,Cable redundancy loop {loop_number}: Cable redundancy loop ok",
                        self.ip,
                    )

        self._state.update(current)

    def stop(self):
        if self.poll_timer is not None:
            self.poll_timer.stop()

# ==========================================
#   NOVASTAR COEX (MX2000 Pro / MX40 Pro / MX6000 Pro / ...)
#   Werkt via SNMP v2c. Polt elke 10s de belangrijkste health OIDs
#   en luistert daarnaast op poort 162 voor TRAP events.
# ==========================================

# Belangrijkste OIDs (ENTERPRISE 319 = NovaStar)
COEX_OIDS = {
    "ctrl_model":          "1.3.6.1.4.1.319.10.10.1.2",
    "ctrl_fw":             "1.3.6.1.4.1.319.10.10.1.3",
    "ctrl_name":           "1.3.6.1.4.1.319.10.10.1.4",
    "ctrl_serial":         "1.3.6.1.4.1.319.10.10.1.6",
    "ctrl_ip":             "1.3.6.1.4.1.319.10.10.1.8",
    "genlock_status":      "1.3.6.1.4.1.319.10.10.10.9.1",   # 0=disconnected, 1=connected
    "monitor_status":      "1.3.6.1.4.1.319.10.200.6",        # 0=normal, 2=fault (overall)
    "input_src_status":    "1.3.6.1.4.1.319.10.10.50.2.1.2",  # 1=connected, 0=disconnected (IN1)
    "n_input_cards":       "1.3.6.1.4.1.319.10.100.4",
}

# Status mapping
COEX_STATUS_MAP = {0: ("normal", "green"), 1: ("warning", "orange"), 2: ("fault", "red")}
COEX_TRAP_PORT = 10162
COEX_BACKUP_API_DEFAULT_ENABLED = False  # Veilig standaard uit; per device opt-in via config.
COEX_BACKUP_API_POLL_INTERVAL_SEC = 120  # Lage frequentie om netwerkimpact minimaal te houden.
COEX_BACKUP_API_TIMEOUT_SEC = 0.8
COEX_BACKUP_API_DEFAULT_LOG_EVERY_POLL = False
COEX_BACKUP_API_DEFAULT_PORT = 8001

COEX_BACKUP_STATUS_LABELS = {
    108: "No Backup Processor",
    109: "primary in use, backup standby",
    110: "primary in use, backup in use",
    111: "primary in use, backup failed",
    112: "primary failed, backup standby",
    113: "primary failed, backup in use",
    114: "primary failed, backup failed",
}

class NovastarCoexSocket(QObject):
    """SNMP-based monitor voor Novastar COEX processors (MX2000 Pro etc.)."""
    error_detected = Signal(str, str, str)  # color, message, ip

    def __init__(
        self,
        ip,
        name,
        community="public",
        port_map=None,
        api_backup_enabled=False,
        api_backup_poll_interval=COEX_BACKUP_API_POLL_INTERVAL_SEC,
        api_backup_log_every_poll=COEX_BACKUP_API_DEFAULT_LOG_EVERY_POLL,
        api_backup_port=COEX_BACKUP_API_DEFAULT_PORT,
        parent=None,
    ):
        super().__init__(parent)
        self.ip = ip.strip()
        self.name = name
        self.community = community
        self.port_map = port_map if isinstance(port_map, dict) else {}
        self.api_backup_enabled = bool(api_backup_enabled)
        try:
            self.api_backup_poll_interval = max(5, int(api_backup_poll_interval))
        except (TypeError, ValueError):
            self.api_backup_poll_interval = COEX_BACKUP_API_POLL_INTERVAL_SEC
        self.api_backup_log_every_poll = bool(api_backup_log_every_poll)
        try:
            self.api_backup_port = int(api_backup_port)
        except (TypeError, ValueError):
            self.api_backup_port = COEX_BACKUP_API_DEFAULT_PORT
        self.active_errors = set()
        self.last_seen_ok = False
        self.trap_server_configured = False  # auto-configure trap target after first online
        self._eth_port_bits = {}  # key=(slot, port) -> laatste bitwaarde
        self._ctrl_name = name
        self._ctrl_model = name
        self._last_backup_status = None
        self._backup_poll_on_error_done = False  # eenmalige poll bij error

        if self.api_backup_enabled:
            mode_txt = "change-only"
            if self.api_backup_log_every_poll:
                mode_txt = "every-poll"
            self.error_detected.emit(
                "gray",
                f"{self.name}: COEX backup API monitor enabled ({mode_txt}, poll elke {self.api_backup_poll_interval}s, port {self.api_backup_port})",
                self.ip,
            )

        # Lazy import zodat de app ook werkt zonder pysnmp (alleen Helios)
        try:
            import asyncio
            from pysnmp.hlapi.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget,
                                              ContextData, ObjectType, ObjectIdentity, getCmd, setCmd)
            from pysnmp.proto.rfc1902 import OctetString as SnmpOctetString, Integer as SnmpInteger
            self._asyncio = asyncio
            self._snmp = dict(SnmpEngine=SnmpEngine, CommunityData=CommunityData,
                              UdpTransportTarget=UdpTransportTarget, ContextData=ContextData,
                              ObjectType=ObjectType, ObjectIdentity=ObjectIdentity,
                              getCmd=getCmd, setCmd=setCmd,
                              OctetString=SnmpOctetString, Integer=SnmpInteger)
            self._available = True
        except ImportError as e:
            self._available = False
            self.error_detected.emit("red", f"{self.name}: pysnmp not installed ({e}) - run 'pip install pysnmp<7'", self.ip)
            self._asyncio = None
            self._snmp = {}

        # Polling wordt in een eigen QThread gestart via start_polling().
        self.poll_timer = None
        try:
            last_octet = int(self.ip.split(".")[-1])
        except Exception:
            last_octet = 0
        self.initial_delay_ms = 400 + ((last_octet % 10) * 140)

    @Slot()
    def start_polling(self):
        if self.poll_timer is not None:
            return
        self.poll_timer = QTimer()
        self.poll_timer.setInterval(2000)  # elke 2s
        self.poll_timer.timeout.connect(self.poll_health)
        QTimer.singleShot(self.initial_delay_ms, self.poll_health)
        QTimer.singleShot(self.initial_delay_ms, self.poll_timer.start)

    def _poll_backup_status_api(self):
        """Poll backupStatus via HTTP API (geen interval check - direct aanroepen)"""
        if not self.api_backup_enabled:
            return

        # Bij errors: slechts 1 keer pollen
        if self._backup_poll_on_error_done:
            return  # Al gepolleerd bij deze error
        self._backup_poll_on_error_done = True

        try:
            url = f"http://{self.ip}:{self.api_backup_port}/api/v1/device/monitor/info"
            headers = {"Device-Key": f"{self.ip}:{self.api_backup_port}"}
            params = {"isNeedCabinetInfo": "false"}
            resp = requests.get(url, headers=headers, params=params, timeout=COEX_BACKUP_API_TIMEOUT_SEC)
            if resp.status_code != 200:
                if self.api_backup_log_every_poll:
                    self.error_detected.emit(
                        "gray",
                        f"Info,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,Backup status poll : HTTP {resp.status_code}",
                        self.ip,
                    )
                return

            payload = resp.json() if resp.content else {}
            if not isinstance(payload, dict):
                return

            data = payload.get("data", {}) if isinstance(payload.get("data", {}), dict) else {}
            backup_raw = data.get("backupStatus")

            # Sommige firmwareversies geven int (109..114), andere geven objecten terug.
            backup_status = None
            status_aux = None
            if isinstance(backup_raw, dict):
                # Prefer errCode wanneer aanwezig; dat bevat meestal de statuscode.
                for key in ("errCode", "code", "value", "status"):
                    if key in backup_raw:
                        try:
                            value_int = int(backup_raw.get(key))
                        except (ValueError, TypeError):
                            continue
                        if key == "status":
                            status_aux = value_int
                        else:
                            backup_status = value_int
                            break
                if backup_status is None:
                    backup_status = status_aux
            else:
                try:
                    backup_status = int(backup_raw)
                except (ValueError, TypeError):
                    backup_status = None

            if backup_status is None:
                if self.api_backup_log_every_poll:
                    self.error_detected.emit(
                        "gray",
                        f"Info,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,Backup status poll : unexpected payload {backup_raw}",
                        self.ip,
                    )
                return

            changed = (backup_status != self._last_backup_status)
            if not changed and not self.api_backup_log_every_poll:
                return

            self._last_backup_status = backup_status
            label = COEX_BACKUP_STATUS_LABELS.get(backup_status, "unknown")
            prefix = "Backup status changed" if changed else "Backup status poll"
            if status_aux is not None:
                label = f"{label}; status={status_aux}"
            self.error_detected.emit(
                "gray",
                f"Info,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,{prefix} : {label} ({backup_status})",
                self.ip,
            )
        except Exception as e:
            if self.api_backup_log_every_poll:
                self.error_detected.emit(
                    "gray",
                    f"Info,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,Backup status poll failed : {e}",
                    self.ip,
                )
            return

    @Slot()
    def trigger_backup_poll_on_error(self):
        """Run backup poll + immediate health poll in de COEX worker-thread."""
        self._backup_poll_on_error_done = False
        self._poll_backup_status_api()
        self.poll_health()

    def _run_async(self, coro):
        """Voer een coroutine uit in een tijdelijke event loop en ruim alle pending tasks netjes op.
        Dit voorkomt 'Task was destroyed but it is pending' warnings van pysnmp's AsyncioDispatcher."""
        asyncio = self._asyncio
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            try:
                # 1. Cancel alle nog hangende tasks
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()
                # 2. Wacht tot ze daadwerkelijk klaar zijn (cancellation propageren)
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                # 3. Shutdown async generators
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass

    def _snmp_get(self, oid, timeout=2):
        """Eenmalig SNMP GET. Geeft (value, error_str) terug. Sync wrapper rond asyncio."""
        if not self._available:
            return None, "pysnmp missing"
        try:
            S = self._snmp

            async def _do_get():
                target = S["UdpTransportTarget"]((self.ip, 161), timeout=timeout, retries=0)
                errInd, errStat, errIdx, varBinds = await S["getCmd"](
                    S["SnmpEngine"](),
                    S["CommunityData"](self.community, mpModel=1),
                    target,
                    S["ContextData"](),
                    S["ObjectType"](S["ObjectIdentity"](oid)),
                )
                return errInd, errStat, errIdx, varBinds

            errInd, errStat, errIdx, varBinds = self._run_async(_do_get())

            if errInd:
                return None, str(errInd)
            if errStat:
                return None, str(errStat.prettyPrint())
            for vb in varBinds:
                return vb[1].prettyPrint(), None
            return None, "no varbinds"
        except Exception as e:
            return None, str(e)

    def _snmp_set(self, oid, value, value_type="OctetString", timeout=2):
        """SNMP SET helper. value_type = 'OctetString' of 'Integer'."""
        if not self._available:
            return False, "pysnmp missing"
        try:
            S = self._snmp
            if value_type == "Integer":
                value_obj = S["Integer"](int(value))
            else:
                value_obj = S["OctetString"](str(value))

            async def _do_set():
                target = S["UdpTransportTarget"]((self.ip, 161), timeout=timeout, retries=0)
                errInd, errStat, errIdx, varBinds = await S["setCmd"](
                    S["SnmpEngine"](),
                    S["CommunityData"](self.community, mpModel=1),
                    target,
                    S["ContextData"](),
                    S["ObjectType"](S["ObjectIdentity"](oid), value_obj),
                )
                return errInd, errStat, errIdx, varBinds

            errInd, errStat, errIdx, varBinds = self._run_async(_do_set())

            if errInd:
                return False, str(errInd)
            if errStat:
                return False, str(errStat.prettyPrint())
            return True, None
        except Exception as e:
            return False, str(e)

    def _configure_trap_target(self):
        """Configureer COEX om SNMP traps naar deze PC te sturen."""
        # Detecteer eigen IP (richting de COEX)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.ip, 1))  # geen actuele connectie, alleen routing
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = None

        if not local_ip:
            return

        target = f"{local_ip}/{COEX_TRAP_PORT}"
        # SNMP Trap server (OID: 1.3.6.1.4.1.319.10.200.1, OctetString)
        ok1, err1 = self._snmp_set("1.3.6.1.4.1.319.10.200.1", target, "OctetString")
        # Trap reporting period (OID: 1.3.6.1.4.1.319.10.200.2, Integer)
        # 0 = direct/immediate events, 1 = samenvatten per minuut.
        ok2, err2 = self._snmp_set("1.3.6.1.4.1.319.10.200.2", 0, "Integer")
        # Trap On (OID: 1.3.6.1.4.1.319.10.200.4, Integer 1=On)
        ok3, err3 = self._snmp_set("1.3.6.1.4.1.319.10.200.4", 1, "Integer")
        # Trap Mode (OID: 1.3.6.1.4.1.319.10.200.5, Integer 1=Complex)
        # Complex mode is nodig voor detail-events (bijv. kabel los per scherm/poort).
        ok4, err4 = self._snmp_set("1.3.6.1.4.1.319.10.200.5", 1, "Integer")

        # Lees actuele trap target terug om vals-negatieve melding te voorkomen.
        current_target, read_err = self._snmp_get("1.3.6.1.4.1.319.10.200.1")
        target_is_set = (current_target == target)

        if ok1 and ok3:
            self.error_detected.emit("green",
                f"{self.name}: SNMP trap target auto-configured -> {target}", self.ip)
            self.trap_server_configured = True
        elif target_is_set:
            self.trap_server_configured = True
            self.error_detected.emit("green",
                f"{self.name}: Trap target al aanwezig op device -> {target}", self.ip)
        else:
            # Markeer als 'configured' om herhaalde foutmeldingen te voorkomen.
            self.trap_server_configured = True
            details = []
            if err1:
                details.append(f"200.1={err1}")
            if err2:
                details.append(f"200.2={err2}")
            if err3:
                details.append(f"200.4={err3}")
            if err4:
                details.append(f"200.5={err4}")
            if read_err:
                details.append(f"readback={read_err}")
            detail_txt = f" | details: {'; '.join(details)}" if details else ""
            self.error_detected.emit("gray",
                f"{self.name}: Auto-trap-config niet volledig gelukt (mogelijk firmware beperking of SNMP write-rechten). "
                f"Stel handmatig in via VMP (Trap server: {target}){detail_txt}", self.ip)

    @Slot()
    def poll_health(self):
        """Vraagt key OIDs op en emit alerts bij verandering."""
        # Reset poll-on-error flag als alle errors opgelost zijn
        if not self.active_errors:
            self._backup_poll_on_error_done = False

        if not self._available:
            return

        # 1. Reachability check via ctrl_model (werkt op alle COEX modellen)
        # Korte timeout hier voorkomt dat offline devices de GUI blokkeren.
        model, err = self._snmp_get(COEX_OIDS["ctrl_model"], timeout=0.35)

        # "noSuchName" / "noSuchObject" / "noSuchInstance" betekent: device antwoordt wél, alleen OID niet aanwezig
        # Dat zien we als ONLINE (alleen netwerk/timeout = offline)
        oid_missing_responses = ("nosuchname", "nosuchobject", "nosuchinstance")
        device_responding = (err is None) or any(s in str(err).lower() for s in oid_missing_responses)

        if not device_responding:
            err_id = "unreachable"
            if err_id not in self.active_errors:
                self.active_errors.add(err_id)
                self.error_detected.emit("red", f"{self.name}: SNMP unreachable ({err})", self.ip)
            self.last_seen_ok = False
            return

        # Device responds — clear unreachable
        if "unreachable" in self.active_errors:
            self.active_errors.discard("unreachable")

        if not self.last_seen_ok:
            self.last_seen_ok = True
            fw, _ = self._snmp_get(COEX_OIDS["ctrl_fw"])
            ctrl_name, _ = self._snmp_get(COEX_OIDS["ctrl_name"])
            if ctrl_name:
                self._ctrl_name = ctrl_name
                # Sync terug naar config-naam als de gebruiker geen eigen naam heeft ingesteld
                # (d.w.z. de naam begint met een generieke prefix of is leeg)
                generic_prefixes = ("Helios-", "COEX-", "BR-", "CL-", "DEV-")
                if not self.name or any(self.name.startswith(p) for p in generic_prefixes):
                    self.name = ctrl_name
                # Anders: behoud de gebruikersnaam als _ctrl_name voor berichtopmaak
                else:
                    self._ctrl_name = self.name
            if model:
                self._ctrl_model = model
            details = []
            if model: details.append(f"Model={model}")
            if ctrl_name: details.append(f"Name={ctrl_name}")
            if fw: details.append(f"FW={fw}")
            extra = " | ".join(details) if details else "responding to SNMP"
            self.error_detected.emit("green", f"{self.name}: Online | {extra}", self.ip)
            # Auto-configure trap target on first online detection
            if not self.trap_server_configured:
                self._configure_trap_target()

        # 2. Overall monitor status
        val, err = self._snmp_get(COEX_OIDS["monitor_status"])
        if err is None and val is not None:
            try:
                status_int = int(val)
                err_id = "overall_status"
                if status_int == 2:
                    if err_id not in self.active_errors:
                        self.active_errors.add(err_id)
                        self.error_detected.emit("red",
                            f"Error,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--, Status FAULT",
                            self.ip)
                elif status_int == 0:
                    if err_id in self.active_errors:
                        self.active_errors.discard(err_id)
                        self.error_detected.emit("green",
                            f"Recover,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--, Status NORMAL",
                            self.ip)
            except (ValueError, TypeError):
                pass

        # 3. Genlock status
        val, err = self._snmp_get(COEX_OIDS["genlock_status"])
        if err is None and val is not None:
            try:
                gl = int(val)
                err_id = "genlock"
                if gl == 0:
                    if err_id not in self.active_errors:
                        self.active_errors.add(err_id)
                        self.error_detected.emit("orange",
                            f"Warning,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--, Genlock: Source disconnected",
                            self.ip)
                else:
                    if err_id in self.active_errors:
                        self.active_errors.discard(err_id)
                        self.error_detected.emit("green",
                            f"Recover,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--, Genlock: Source connected",
                            self.ip)
            except ValueError:
                pass

        # 4. Input source status
        src_val, src_err = self._snmp_get(COEX_OIDS["input_src_status"])
        if src_err is None and src_val is not None:
            try:
                src_state = int(src_val)
                src_key = "_input_source_in1"
                prev_state = self._eth_port_bits.get(src_key)
                self._eth_port_bits[src_key] = src_state
                if prev_state is not None and src_state != prev_state:
                    in_label = "Input Source"
                    if src_state == 0:
                        self.error_detected.emit("red",
                            f"Error,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,{in_label}: Source disconnected",
                            self.ip)
                    else:
                        self.error_detected.emit("green",
                            f"Recover,Controller,{self._ctrl_name},{self._ctrl_model},{self.ip},--,{in_label}: Source connected",
                            self.ip)
            except (ValueError, TypeError):
                pass

        # 5. Receiving cards per ETH port — disconnect detectie via rc count
        # 5. Ethercon output events komen uitsluitend uit traps.
        # De OID 319.10.20.1.2.*.5 is geen betrouwbare per-poort linkstatus en
        # veroorzaakte foutieve "Eth Port1" labels bij andere poorten.

        # 6. API backup-status polling gebeurt al bovenaan deze methode.

    @Slot()
    def stop(self):
        try:
            if self.poll_timer is not None:
                self.poll_timer.stop()
        except Exception:
            pass


class CoexTrapListener(QThread):
    """Luistert op UDP poort voor SNMP traps van COEX processors.
    Eén instance voor de hele applicatie (poort kan maar 1x gebonden worden).
    """
    trap_received = Signal(str, str, str, str)  # color, message, source_ip, oid

    def __init__(self, port=COEX_TRAP_PORT, ip_names=None, parent=None):
        super().__init__(parent)
        self.port = port
        self.ip_names = ip_names or {}  # {ip: config_naam}
        self.running = True

    def run(self):
        """
        Raw UDP socket trap listener — werkt met elke community string (inclusief leeg).
        Decodeert SNMPv1 varbinds via pyasn1 en mapt bekende OIDs naar leesbare events.
        """
        import socket as _socket

        PORT_LINK_PREFIX       = "1.3.6.1.4.1.319.10.120."
        INPUT_CARD_PREFIX      = "1.3.6.1.4.1.319.10.110."
        CONTROLLER_INFO_PREFIX = "1.3.6.1.4.1.319.10.100."
        SCREEN_INFO_PREFIX     = "1.3.6.1.4.1.319.10.130."
        MULTIFUNCTION_PREFIX   = "1.3.6.1.4.1.319.10.30.7."
        MONITOR_STATUS_OID     = COEX_OIDS["monitor_status"]
        MX40_ALT_PREFIX_MAP = {
            "1.3.6.1.4.1.319.10.10.120.": PORT_LINK_PREFIX,
            "1.3.6.1.4.1.319.10.10.110.": INPUT_CARD_PREFIX,
            "1.3.6.1.4.1.319.10.10.100.": CONTROLLER_INFO_PREFIX,
            "1.3.6.1.4.1.319.10.10.130.": SCREEN_INFO_PREFIX,
        }
        MX40_TEMP_HOTSPOT_OID = "1.3.6.1.4.1.319.10.10.30.6.1.3.1.1"
        MX40_METRIC_PREFIX = "1.3.6.1.4.1.319.10.10.70."
        ip_names = self.ip_names  # {ip: config_naam}
        # Poortnamen zoals VMP ze toont (1-3 OPT, 4-6 Eth met globaal poortnummer)
        PORT_NAMES = {
            1: "OPT Port1", 2: "OPT Port2", 3: "OPT Port3",
            4: "Eth Port4", 5: "Eth Port5", 6: "Eth Port6",
        }
        SUPPRESS_OIDS = set()  # 130.N.1 wordt nu via SCREEN_INFO_PREFIX afgehandeld

        def _decode_varbinds(data: bytes):
            """Geeft lijst van (oid_str, val_str) terug uit raw SNMP packet."""
            try:
                from pysnmp.proto import api as snmp_api
                from pyasn1.codec.ber import decoder as ber_dec
                ver = int(snmp_api.decodeMessageVersion(data))
                p = snmp_api.protoModules[ver]
                msg, _ = ber_dec.decode(data, asn1Spec=p.Message())
                pdu = p.apiMessage.getPDU(msg)
                if ver == 0:
                    vbs = p.apiTrapPDU.getVarBinds(pdu)
                else:
                    vbs = p.apiPDU.getVarBinds(pdu)
                return [(str(o.prettyPrint()), str(v.prettyPrint())) for o, v in vbs]
            except Exception as e:
                return [("decode_error", str(e))]

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.port))
        except PermissionError:
            self.trap_received.emit("orange",
                f"SNMP trap listener: permission denied on port {self.port} (run as admin or use port>1024)",
                "SYSTEM", "")
            return
        except OSError as e:
            self.trap_received.emit("orange",
                f"SNMP trap listener: port {self.port} busy or unavailable ({e})", "SYSTEM", "")
            return

        sock.settimeout(2.0)
        self.trap_received.emit("green",
            f"SNMP trap listener active on UDP port {self.port}", "SYSTEM", "")

        # Bijhouden van laatste bekende cabinet-telling per (opt_out, eth_out, cabinet)
        # Gebruikt om richting (toename=connected / afname=disconnected) te bepalen
        _cabinet_counts = {}
        _eth_ports_connected_counts = {}
        _controller_connected_counts = {}
        _monitor_status_by_ip = {}
        _mx40_hotspot_state = {}
        _mx40_metric_state = {}

        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                continue

            src_ip = addr[0]
            proc_name = ip_names.get(src_ip, src_ip)  # gebruik config-naam ipv hardcoded
            varbinds = _decode_varbinds(data)

            events = []  # list of (color, msg, oid_str)
            raw_msgs = []
            for oid_str, val_str in varbinds:
                if oid_str in SUPPRESS_OIDS:
                    continue

                # MX40 hotspot payload (JSON). Log alleen bij wijziging om minuut-spam te vermijden.
                if oid_str == MX40_TEMP_HOTSPOT_OID:
                    try:
                        payload = json.loads(val_str)
                    except Exception:
                        raw_msgs.append(f"{oid_str}={val_str}")
                        continue

                    max_temp = payload.get("maxTemp")
                    hot_cabinets = payload.get("maxTempCabinets", [])
                    points = []
                    for c in hot_cabinets:
                        if isinstance(c, dict):
                            port = c.get("netPortIndex")
                            cab = c.get("cabinetIndex")
                            if port is not None and cab is not None:
                                points.append((int(port), int(cab)))
                    signature = (max_temp, tuple(sorted(points)))
                    prev_signature = _mx40_hotspot_state.get(src_ip)
                    _mx40_hotspot_state[src_ip] = signature

                    if signature != prev_signature:
                        if points:
                            loc_txt = ", ".join([f"Port{p}/Cab{c}" for p, c in points])
                        else:
                            loc_txt = "unknown cabinet"
                        events.append((
                            "gray",
                            f"Info,Controller,{proc_name},MX40,{src_ip},--, Max cabinet temperature {max_temp}C at {loc_txt}",
                            f"{oid_str}={val_str}",
                        ))
                    continue

                # MX40 periodieke metrics: suppress raw-spam, toon alleen betekenisvolle veranderingen.
                if oid_str.startswith(MX40_METRIC_PREFIX):
                    try:
                        value = float(val_str)
                    except (TypeError, ValueError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                        continue

                    key = (src_ip, oid_str)
                    prev_value = _mx40_metric_state.get(key)
                    _mx40_metric_state[key] = value

                    # Alleen loggen als de metric zichtbaar wijzigt.
                    if prev_value is not None and abs(value - prev_value) >= 2.0:
                        metric_name = oid_str.replace(MX40_METRIC_PREFIX, "70.")
                        events.append((
                            "gray",
                            f"Info,Controller,{proc_name},MX40,{src_ip},--, Telemetry {metric_name} changed to {value}",
                            f"{oid_str}={val_str}",
                        ))
                    continue

                normalized_oid = oid_str
                for alt_prefix, canonical_prefix in MX40_ALT_PREFIX_MAP.items():
                    if oid_str.startswith(alt_prefix):
                        normalized_oid = canonical_prefix + oid_str[len(alt_prefix):]
                        break

                if oid_str == MONITOR_STATUS_OID:
                    try:
                        status_val = int(val_str)
                    except (TypeError, ValueError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                        continue

                    prev_status = _monitor_status_by_ip.get(src_ip)
                    _monitor_status_by_ip[src_ip] = status_val

                    # 0=normal, 2=fault: log alleen bij wijziging om trap-heartbeat spam te vermijden.
                    if status_val == 2 and prev_status != 2:
                        events.append((
                            "red",
                            f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--, Status FAULT",
                            f"{oid_str}={val_str}",
                        ))
                    elif status_val == 0 and prev_status == 2:
                        events.append((
                            "green",
                            f"Recover,Controller,{proc_name},MX2000 Pro,{src_ip},--, Status NORMAL",
                            f"{oid_str}={val_str}",
                        ))
                    continue
                if normalized_oid.startswith(CONTROLLER_INFO_PREFIX):
                    try:
                        suffix = normalized_oid[len(CONTROLLER_INFO_PREFIX):]
                        parts = suffix.split(".")
                        if len(parts) == 1:
                            metric = parts[0]
                            if metric in ("1", "2", "3"):
                                # Mainboard abnormal: N=1 temp, 2 voltage, 3 fan
                                val = int(val_str)
                                label_map = {
                                    "1": "Mainboard temperature abnormal",
                                    "2": "Mainboard voltage abnormal",
                                    "3": "Mainboard fan abnormal",
                                }
                                desc = f"{label_map.get(metric, 'Mainboard abnormal')} : {val}"
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                    f"{oid_str}={val_str}"))
                            elif metric in ("4", "5", "6"):
                                # Connected card counters: daling of 0 = fout
                                val = int(val_str)
                                desc_map = {
                                    "4": "Input cards connected",
                                    "5": "Output cards connected",
                                    "6": "Expansion cards connected",
                                }
                                prev = _controller_connected_counts.get(metric)
                                _controller_connected_counts[metric] = val
                                color = "red" if (val == 0 or (prev is not None and val < prev)) else "green"
                                severity = "Error" if color == "red" else "Recover"
                                desc = f"{desc_map.get(metric, 'Cards connected')} : {val}"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                    f"{oid_str}={val_str}"))
                            elif metric == "7":
                                # Genlock: 0=not connected, 1=connected
                                gl = int(val_str)
                                if gl == 0:
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,Genlock connection status : disconnected",
                                        f"{oid_str}={val_str}"))
                                else:
                                    events.append(("green",
                                        f"Recover,Controller,{proc_name},MX2000 Pro,{src_ip},--,Genlock connection status : connected",
                                        f"{oid_str}={val_str}"))
                            elif metric == "8":
                                # Informative trap value (string)
                                events.append(("gray",
                                    f"Info,Controller,{proc_name},MX2000 Pro,{src_ip},--,SNMP Start Time : {val_str}",
                                    f"{oid_str}={val_str}"))
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        else:
                            raw_msgs.append(f"{oid_str}={val_str}")
                    except (ValueError, TypeError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                    continue
                if normalized_oid.startswith(INPUT_CARD_PREFIX):
                    try:
                        suffix = normalized_oid[len(INPUT_CARD_PREFIX):]
                        parts = suffix.split(".")
                        val = int(val_str)
                        # MIB: 110.N.Y  N=input card slot, Y=4 -> #bronnen, Y=1/2/3 -> temp/voltage/fan fout
                        if len(parts) == 2:
                            slot = int(parts[0])
                            metric = parts[1]
                            if metric == "4":
                                label = f"Input Card {slot}"
                                if val == 0:
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                        f"{label} - Input Source disconnected (sources: {val})",
                                        f"{oid_str}={val_str}"))
                                else:
                                    events.append(("green",
                                        f"Recover,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                        f"{label} - Input Source connected (sources: {val})",
                                        f"{oid_str}={val_str}"))
                            elif metric == "1":
                                label = f"Input Card {slot}"
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                    f"{label} - Temperature abnormal : {val}",
                                    f"{oid_str}={val_str}"))
                            elif metric == "2":
                                label = f"Input Card {slot}"
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                    f"{label} - Voltage abnormal : {val}",
                                    f"{oid_str}={val_str}"))
                            elif metric == "3":
                                label = f"Input Card {slot}"
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                    f"{label} - Fan abnormal : {val}",
                                    f"{oid_str}={val_str}"))
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        else:
                            raw_msgs.append(f"{oid_str}={val_str}")
                    except (ValueError, TypeError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                    continue
                if normalized_oid.startswith(PORT_LINK_PREFIX):
                    try:
                        suffix = normalized_oid[len(PORT_LINK_PREFIX):]
                        parts = suffix.split(".")
                        link_val = int(val_str)
                        # MIB structuur: 1.3.6.1.4.1.319.10.120.N.Y[.metric]
                        # N = output card slot (=OUT nummer)
                        # Y = Ethernet port index
                        # metric: 4=Eth ports connected, 5=recv cards, 6=temp fout, 7=voltage fout
                        if len(parts) == 3:
                            slot = int(parts[0])
                            eth  = int(parts[1])
                            metric = parts[2]
                            label = f"OUT{slot}/OPT Port{slot} - Eth Port{eth}"
                            key = (slot, eth, metric)
                            prev = _cabinet_counts.get(key)
                            _cabinet_counts[key] = link_val
                            if metric == "5":
                                desc = f"{label} - Receiving cards : {link_val}"
                                if prev is None:
                                    # Eerste event zonder baseline: niet stil zijn, toon expliciet alarm.
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc} (first event, baseline unknown)",
                                        f"{oid_str}={val_str}"))
                                else:
                                    color = "red" if link_val < prev else "green"
                                    severity = "Error" if color == "red" else "Recover"
                                    events.append((color,
                                        f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                        f"{oid_str}={val_str}"))
                            elif metric == "6":
                                desc = f"{label} - Receiving cards temp error : {link_val}"
                                color = "red" if link_val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                    f"{oid_str}={val_str}"))
                            elif metric == "7":
                                desc = f"{label} - Receiving cards voltage error : {link_val}"
                                color = "red" if link_val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                    f"{oid_str}={val_str}"))
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        elif len(parts) == 2:
                            slot = int(parts[0])
                            if parts[1] == "4":
                                label = f"OUT{slot}/OPT Port{slot}"
                                desc = f"{label} - Eth ports connected : {link_val}"
                                prev = _eth_ports_connected_counts.get(slot)
                                _eth_ports_connected_counts[slot] = link_val
                                if prev is None:
                                    # Eerste event zonder baseline: niet stil zijn, toon expliciet alarm.
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc} (first event, baseline unknown)",
                                        f"{oid_str}={val_str}"))
                                else:
                                    color = "red" if link_val < prev else "green"
                                    severity = "Error" if color == "red" else "Recover"
                                    events.append((color,
                                        f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                        f"{oid_str}={val_str}"))
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        else:
                            raw_msgs.append(f"{oid_str}={val_str}")
                    except (ValueError, IndexError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                    continue
                if normalized_oid.startswith(SCREEN_INFO_PREFIX):
                    try:
                        suffix = normalized_oid[len(SCREEN_INFO_PREFIX):]
                        parts = suffix.split(".")
                        # MIB: 130.N.1 = recv cards connected, 130.N.2 = temp abnormal, 130.N.3 = voltage abnormal
                        if len(parts) == 2:
                            screen = int(parts[0])
                            metric = parts[1]
                            val = int(val_str)
                            label = f"Screen {screen}"
                            if metric == "1":
                                prev = _cabinet_counts.get(("screen", screen, 1))
                                _cabinet_counts[("screen", screen, 1)] = val
                                desc = f"{label} - Receiving cards connected : {val}"
                                if prev is None:
                                    # Eerste event zonder baseline: niet stil zijn, toon expliciet alarm.
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc} (first event, baseline unknown)",
                                        f"{oid_str}={val_str}"))
                                else:
                                    color = "red" if val < prev else "green"
                                    severity = "Error" if color == "red" else "Recover"
                                    events.append((color,
                                        f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,{desc}",
                                        f"{oid_str}={val_str}"))
                            elif metric == "2":
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                    f"{label} - Receiving cards temperature abnormal : {val}",
                                    f"{oid_str}={val_str}"))
                            elif metric == "3":
                                color = "red" if val > 0 else "green"
                                severity = "Error" if color == "red" else "Recover"
                                events.append((color,
                                    f"{severity},Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                    f"{label} - Receiving cards voltage abnormal : {val}",
                                    f"{oid_str}={val_str}"))
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        else:
                            raw_msgs.append(f"{oid_str}={val_str}")
                    except (ValueError, TypeError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                    continue
                if oid_str.startswith(MULTIFUNCTION_PREFIX):
                    try:
                        suffix = oid_str[len(MULTIFUNCTION_PREFIX):]
                        parts = suffix.split(".")
                        # MIB: 30.7.N.1.Y.Z.1.M.1  -> power supply (0=Failed, 1=Normal)
                        # MIB: 30.7.N.1.Y.Z.2.M.1.1 -> light sensor status (0=Failed, 1=Normal)
                        # MIB: 30.7.N.1.Y.Z.2.M.1.2 -> light sensor brightness (LUX)
                        # parts: [N, 1, Y, Z, type, M, 1, ...]
                        if len(parts) >= 7 and parts[1] == "1":
                            slot_n = parts[0]
                            slot_y = parts[2]
                            slot_z = parts[3]
                            mf_type = parts[4]
                            m_idx = parts[5]
                            label = f"MF Card OUT{slot_n}/Eth{slot_y}/Card{slot_z}"
                            val = int(val_str)
                            if mf_type == "1" and len(parts) == 7:
                                # Power supply: 0=Failed, 1=Normal
                                if val == 0:
                                    events.append(("red",
                                        f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                        f"{label} - Power supply {m_idx} : Failed",
                                        f"{oid_str}={val_str}"))
                                else:
                                    events.append(("green",
                                        f"Recover,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                        f"{label} - Power supply {m_idx} : Normal",
                                        f"{oid_str}={val_str}"))
                            elif mf_type == "2" and len(parts) == 8:
                                sub = parts[7]
                                if sub == "1":
                                    # Light sensor status: 0=Failed, 1=Normal
                                    if val == 0:
                                        events.append(("red",
                                            f"Error,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                            f"{label} - Light sensor {m_idx} status : Failed",
                                            f"{oid_str}={val_str}"))
                                    else:
                                        events.append(("green",
                                            f"Recover,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                            f"{label} - Light sensor {m_idx} status : Normal",
                                            f"{oid_str}={val_str}"))
                                elif sub == "2":
                                    # Light sensor brightness in LUX
                                    events.append(("gray",
                                        f"Info,Controller,{proc_name},MX2000 Pro,{src_ip},--,"
                                        f"{label} - Light sensor {m_idx} brightness : {val} LUX",
                                        f"{oid_str}={val_str}"))
                                else:
                                    raw_msgs.append(f"{oid_str}={val_str}")
                            else:
                                raw_msgs.append(f"{oid_str}={val_str}")
                        else:
                            raw_msgs.append(f"{oid_str}={val_str}")
                    except (ValueError, TypeError, IndexError):
                        raw_msgs.append(f"{oid_str}={val_str}")
                    continue
                raw_msgs.append(f"{oid_str}={val_str}")

            for color, msg, oid in events:
                self.trap_received.emit(color, msg, src_ip, oid)
            # Toon TRAP_RAW alleen als er géén mappable event was (debug/onbekende OIDs)
            if raw_msgs and not events:
                self.trap_received.emit("gray", "TRAP_RAW: " + " | ".join(raw_msgs), src_ip,
                    " | ".join(raw_msgs))

        sock.close()

    def stop(self):
        self.running = False


class MonitorWorker(QThread):
    status_signal = Signal(str, str)
    alert_signal = Signal(str, str, str, dict)  # ip, color, message, receiver_info

    def __init__(self, processors):
        super().__init__()
        self.processors = processors
        self.running = True
        self.last_alerts = {}  # Track alerts per device
        self.force_scan_flag = False  # Trigger immediate scan
        self.helios_receiver_cache = {}
        self.helios_receiver_cache_ts = {}

    def update_processors(self, new_list):
        self.processors = new_list
        self.force_scan_flag = True  # Trigger immediate scan

    def force_scan(self):
        """Request immediate scan on next loop iteration."""
        self.force_scan_flag = True

    def _refresh_helios_receiver_cache(self, ip):
        now = time.time()
        last = float(self.helios_receiver_cache_ts.get(ip, 0.0))
        if now - last < 8.0:
            return
        self.helios_receiver_cache_ts[ip] = now

        try:
            resp = requests.get(f"http://{ip}/api/v1/public?dev.receivers", timeout=1.2)
            if int(resp.status_code) != 200:
                return
            payload = resp.json() if resp.content else {}
            receivers = payload.get("dev", {}).get("receivers", {}) if isinstance(payload, dict) else {}
            if not isinstance(receivers, dict):
                return

            mapped = {}
            for mac, details in receivers.items():
                if not isinstance(details, dict):
                    continue
                mac_norm = str(mac or "").strip().lower().replace("-", ":")
                if not mac_norm:
                    continue

                info = {"mac": str(mac), "sfp": "", "output": "", "chain_pos": ""}

                # Fiber output (OPT): typically distroBoxPort on Helios receiver entries.
                fiber = details.get("distroBoxPort", details.get("port"))
                if fiber not in (None, ""):
                    info["sfp"] = str(fiber)

                # Network port: typically switchPort.
                net_port = details.get("switchPort", details.get("output"))
                if net_port not in (None, ""):
                    info["output"] = str(net_port)

                # Tile number: prefer chain order on the network port.
                tile = details.get("string", details.get("position", details.get("index")))
                if tile not in (None, ""):
                    try:
                        info["chain_pos"] = str(int(tile) + 1)
                    except (TypeError, ValueError):
                        info["chain_pos"] = str(tile)
                else:
                    x = details.get("x")
                    y = details.get("y")
                    if isinstance(x, int) and isinstance(y, int) and x >= 0 and y >= 0:
                        info["chain_pos"] = f"{x},{y}"

                mapped[mac_norm] = info

            self.helios_receiver_cache[ip] = mapped
        except Exception:
            return

    def run(self):
        while self.running:
            if not self.processors:
                time.sleep(2)
                continue
            
            for proc in self.processors:
                if not self.running: break
                ip = proc.get("ip")
                name = proc.get("name", "Device")
                ptype = proc.get("type", "").lower()
                if not ip: continue
                # COEX en andere SNMP-gebaseerde devices worden niet via HTTP gemonitord
                if "coex" in ptype or "novastar" in ptype or "mx" in ptype or "brompton" in ptype:
                    continue
                try:
                    url = f"http://{ip}/health/alerts"
                    resp = requests.get(url, timeout=1.0)
                    
                    if resp.status_code == 200:
                        self.status_signal.emit(ip, "ok")  # Device is reachable!
                        try:
                            alerts = resp.json()
                            self._process_alerts(ip, name, alerts)
                        except Exception as e:
                            # JSON parsing failed, but device is still reachable
                            pass

                        try:
                            self._refresh_helios_receiver_cache(ip)
                            sys_resp = requests.get(f"http://{ip}/api/v1/public?sys.alerts", timeout=1.0)
                            if sys_resp.status_code == 200:
                                self._process_sys_alerts(ip, name, sys_resp.json())
                        except Exception:
                            pass
                    else:
                        self.status_signal.emit(ip, "error")
                except:
                    self.status_signal.emit(ip, "offline")
            
            time.sleep(3)

    def _process_alerts(self, ip, name, alerts_data):
        """Parse health/alerts JSON and emit new alerts."""
        current_alert_ids = set()
        alert_store_key = f"{ip}:health"
        
        # Parse alerts from the response
        if isinstance(alerts_data, dict):
            for severity_level, alert_list in alerts_data.items():
                if isinstance(alert_list, list):
                    for alert in alert_list:
                        if isinstance(alert, dict):
                            alert_id = alert.get("id", str(hash(str(alert))))
                            current_alert_ids.add(alert_id)
                            
                            # Check if this is a new alert
                            if alert_store_key not in self.last_alerts or alert_id not in self.last_alerts[alert_store_key]:
                                msg = alert.get("message", alert.get("desc", str(alert)))
                                color = severity_to_color(severity_level)
                                msg_txt = str(msg or "").strip()
                                msg_l = msg_txt.lower()
                                if msg_l in ("none", "null"):
                                    msg_txt = f"[{alert_id}] None"
                                    self.alert_signal.emit(ip, "green", f"{name}: Recover: {msg_txt}", "")
                                else:
                                    self.alert_signal.emit(ip, color, f"{name}: {msg_txt}", "")
        
        # Store this alert set for next iteration
        if alert_store_key not in self.last_alerts:
            self.last_alerts[alert_store_key] = set()
        self.last_alerts[alert_store_key] = current_alert_ids

    def _severity_number_to_color(self, severity):
        sev_txt = str(severity).strip().lower()
        if sev_txt in ("none", "null"):
            return "green"
        if sev_txt in ("info", "notice"):
            return "green"

        try:
            sev = int(severity)
        except:
            return "gray"
        if sev in [2, 3]:
            return "red"
        if sev == 4:
            return "orange"
        if sev == 5:
            return "green"
        return "gray"

    def _apply_display_alert_rules(self, alert_key, msg, color):
        key = str(alert_key or "").strip().lower()
        txt = str(msg or "").strip()
        txt_l = txt.lower()

        # Strip optional leading [alertKey] when testing semantic value.
        txt_core = re.sub(r"^\[[^\]]+\]\s*", "", txt_l).strip()

        if txt_core in ("none", "null"):
            if not txt.startswith("["):
                txt = f"[{alert_key}] {txt}"
            return "green", txt, True

        if key.startswith("ethdrop") and "dropped link" in txt_l:
            m = re.search(r"dropped\s+link\s*:\s*(\d+)", txt, flags=re.IGNORECASE)
            if m:
                try:
                    dropped = int(m.group(1))
                    if dropped > 0:
                        return "red", txt, False
                    return "green", txt, True
                except ValueError:
                    return "red", txt, False
            return "red", txt, False

        if key == "tilebackupmissing" and "backup missing" in txt_l:
            return "red", txt, False

        return color, txt, False

    def _process_sys_alerts(self, ip, name, sys_alerts_payload):
        """Parse sys.alerts payload and emit receiver-aware alerts with MAC addresses."""
        current_alert_ids = set()
        alert_store_key = f"{ip}:sys"

        if not isinstance(sys_alerts_payload, dict):
            return

        sys_obj = sys_alerts_payload.get("sys", {}) if isinstance(sys_alerts_payload.get("sys", {}), dict) else {}
        alerts_obj = sys_obj.get("alerts", {}) if isinstance(sys_obj.get("alerts", {}), dict) else {}

        for alert_key, alert_data in alerts_obj.items():
            if not isinstance(alert_data, dict):
                continue

            brief = str(alert_data.get("brief", "")).strip()
            desc = str(alert_data.get("desc", "")).strip()
            msg = brief or desc or str(alert_key)
            color = self._severity_number_to_color(alert_data.get("severity"))
            color, msg, is_recover = self._apply_display_alert_rules(alert_key, msg, color)

            devices = alert_data.get("devices", {}) if isinstance(alert_data.get("devices", {}), dict) else {}
            receivers = devices.get("receivers", {}) if isinstance(devices.get("receivers", {}), dict) else {}

            if receivers:
                for receiver_mac, receiver_details in receivers.items():
                    mac_norm = str(receiver_mac or "").strip().lower().replace("-", ":")
                    cached_info = self.helios_receiver_cache.get(ip, {}).get(mac_norm, {})

                    # Parse receiver details (SFP, output, chain position, etc.)
                    receiver_info = {
                        "mac": str(receiver_mac),
                        "sfp": str(cached_info.get("sfp", "")),
                        "output": str(cached_info.get("output", "")),
                        "chain_pos": str(cached_info.get("chain_pos", ""))
                    }
                    
                    if isinstance(receiver_details, dict):
                        # Probeer verschillende veldnamen die Helios direct in alert payload kan meesturen.
                        sfp_v = receiver_details.get("sfp", receiver_details.get("port", ""))
                        output_v = receiver_details.get("output", receiver_details.get("switch", ""))
                        chain_v = receiver_details.get("chain", receiver_details.get("position", receiver_details.get("index", "")))

                        if sfp_v not in (None, ""):
                            receiver_info["sfp"] = str(sfp_v)
                        if output_v not in (None, ""):
                            receiver_info["output"] = str(output_v)
                        if chain_v not in (None, ""):
                            receiver_info["chain_pos"] = str(chain_v)
                    
                    alert_id = f"{alert_key}:{receiver_mac}:{msg}"
                    current_alert_ids.add(alert_id)
                    if alert_store_key not in self.last_alerts or alert_id not in self.last_alerts[alert_store_key]:
                        if is_recover:
                            self.alert_signal.emit(ip, color, f"{name}: Recover: {msg}", receiver_info)
                        else:
                            self.alert_signal.emit(ip, color, f"{name}: {msg}", receiver_info)
            else:
                alert_id = f"{alert_key}:{msg}"
                current_alert_ids.add(alert_id)
                if alert_store_key not in self.last_alerts or alert_id not in self.last_alerts[alert_store_key]:
                    if is_recover:
                        self.alert_signal.emit(ip, color, f"{name}: Recover: {msg}", {})
                    else:
                        self.alert_signal.emit(ip, color, f"{name}: {msg}", {})

        self.last_alerts[alert_store_key] = current_alert_ids
    
    def stop(self):
        self.running = False
        self.wait()

class ScanWorker(QThread):
    progress_signal = Signal(int)
    found_signal = Signal(str, str, str)
    log_signal = Signal(str)
    finished_signal = Signal(int)

    def __init__(self, scan_mode="ALL"):
        super().__init__()
        self.scan_mode = str(scan_mode or "ALL").upper()

    def _wants_helios(self):
        return self.scan_mode in ("ALL", "HELIOS")

    def _wants_coex(self):
        return self.scan_mode in ("ALL", "COEX")

    def _wants_brompton(self):
        return self.scan_mode in ("ALL", "BROMPTON")

    def run(self):
        self.log_signal.emit("Netwerk scannen...")
        all_ips = set()
        try:
            host = socket.gethostname()
            _, _, ip_list = socket.gethostbyname_ex(host)
            for ip in ip_list: all_ips.add(ip)
        except: pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); all_ips.add(s.getsockname()[0]); s.close()
        except: pass

        valid_ips = [ip for ip in all_ips if not ip.startswith("127.") and ":" not in ip]
        if not valid_ips:
            self.log_signal.emit("Geen netwerk gevonden!")
            self.finished_signal.emit(0)
            return

        ips_to_scan = []
        scanned_subnets = []
        primary_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        # Scan ALLE subnets van alle netwerk-interfaces, niet alleen de internet-facing route.
        # Dit is nodig als de COEX op een ander subnet zit dan de internet-connectie.
        for local_ip in valid_ips:
            base = ".".join(local_ip.split('.')[:-1])
            if base in scanned_subnets:
                continue
            scanned_subnets.append(base)
            for i in range(1, 255):
                ips_to_scan.append(f"{base}.{i}")

        subnets_str = ", ".join(f"{b}.0/24" for b in scanned_subnets)
        self.log_signal.emit(f"Scanning: {subnets_str}")

        total = max(len(ips_to_scan), 1)
        found_count = 0
        found_ips = set()

        # FASE 1: HTTP scan (snel, parallel) — alleen Helios
        if self._wants_helios():
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = list(executor.map(self.check_ip_http, ips_to_scan))
                for i, result in enumerate(results):
                    self.progress_signal.emit(int((i/total)*50))  # tot 50%
                    if result:
                        self.found_signal.emit(result[0], result[1], result[2])
                        found_ips.add(result[0])
                        found_count += 1
        else:
            self.log_signal.emit("Helios scan overgeslagen (scanfilter)")
            self.progress_signal.emit(50)

        # FASE 2: SNMP scan (parallel, licht) — voor IPs die niet via HTTP gevonden zijn
        if self._wants_coex():
            self.log_signal.emit("SNMP scan voor Novastar COEX...")
            snmp_engine = self._make_snmp_engine()
            if snmp_engine is not None:
                remaining = [ip for ip in ips_to_scan if ip not in found_ips]
                if remaining:
                    with ThreadPoolExecutor(max_workers=64) as executor:
                        results = list(executor.map(lambda ip: self.check_ip_snmp(ip, snmp_engine), remaining))
                        for i, result in enumerate(results):
                            self.progress_signal.emit(50 + int((i/max(len(remaining),1))*50))
                            if result:
                                self.found_signal.emit(result[0], result[1], result[2])
                                found_ips.add(result[0])
                                found_count += 1
        else:
            self.log_signal.emit("COEX scan overgeslagen (scanfilter)")

        # FASE 3: HTTP scan voor BROMPTON API endpoints
        if self._wants_brompton():
            self.log_signal.emit("HTTP scan voor BROMPTON Tessera API...")
            remaining = [ip for ip in ips_to_scan if ip not in found_ips]
            if remaining:
                with ThreadPoolExecutor(max_workers=64) as executor:
                    results = list(executor.map(self.check_ip_brompton, remaining))
                    for i, result in enumerate(results):
                        self.progress_signal.emit(50 + int((i/max(len(remaining),1))*50))
                        if result:
                            self.found_signal.emit(result[0], result[1], result[2])
                            found_ips.add(result[0])
                            found_count += 1
        else:
            self.log_signal.emit("BROMPTON scan overgeslagen (scanfilter)")

        self.progress_signal.emit(100)
        self.finished_signal.emit(found_count)

    def _make_snmp_engine(self):
        """Probeer pysnmp imports; return dict met api refs of None."""
        try:
            import asyncio
            from pysnmp.hlapi.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget,
                                              ContextData, ObjectType, ObjectIdentity, getCmd)
            return {
                "asyncio": asyncio, "SnmpEngine": SnmpEngine, "CommunityData": CommunityData,
                "UdpTransportTarget": UdpTransportTarget, "ContextData": ContextData,
                "ObjectType": ObjectType, "ObjectIdentity": ObjectIdentity, "getCmd": getCmd
            }
        except ImportError:
            return None

    def check_ip_http(self, ip):
        try: 
            if requests.get(f"http://{ip}/health/alerts", timeout=0.8).status_code==200:
                name = self.fetch_processor_name(ip)
                return (ip, "Helios", name)
        except: pass
        return None

    def check_ip_brompton(self, ip):
        """Snelle probe voor Tessera API via read-only endpoints."""
        probe_paths = [
            "",
            "devices/statistics/online-count",
            "devices/statistics/error-count",
            "system/software/version",
        ]
        base_urls = [f"http://{ip}/api", f"https://{ip}/api"]
        try:
            for base in base_urls:
                for path in probe_paths:
                    sep = "" if not path else "/"
                    url = f"{base}{sep}{path}"
                    try:
                        resp = requests.get(url, timeout=0.8, verify=False)
                    except Exception:
                        continue
                    status = int(resp.status_code)

                    # 200 = direct match, 401/403 = endpoint bestaat maar auth nodig.
                    if status in (200, 401, 403):
                        detected_name = self.fetch_brompton_name(ip)
                        return (ip, "BROMPTON", detected_name)

                    # 404 op /api root niet als hit tellen, op andere paden kan firmware afhankelijk zijn.
                    if status == 404 and path:
                        continue
        except Exception:
            return None
        return None

    def check_ip_snmp(self, ip, S, timeout=0.15):
        """Snelle SNMP probe op ctrl_model OID. S = engine dict van _make_snmp_engine()."""
        asyncio = S["asyncio"]
        try:
            async def _do():
                target = S["UdpTransportTarget"]((ip, 161), timeout=timeout, retries=0)
                errInd, errStat, errIdx, varBinds = await S["getCmd"](
                    S["SnmpEngine"](), S["CommunityData"]("public", mpModel=1),
                    target, S["ContextData"](),
                    S["ObjectType"](S["ObjectIdentity"]("1.3.6.1.4.1.319.10.10.1.2")),  # ctrl_model
                    S["ObjectType"](S["ObjectIdentity"]("1.3.6.1.4.1.319.10.10.1.4"))   # ctrl_name
                )
                if errInd or errStat:
                    return None
                model = None
                ctrl_name = None
                for vb in varBinds:
                    oid = vb[0].prettyPrint()
                    val = vb[1].prettyPrint()
                    if oid.endswith(".10.10.1.2"):
                        model = val
                    elif oid.endswith(".10.10.1.4"):
                        ctrl_name = val
                return (model, ctrl_name)
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(_do())
            finally:
                # Cancel pending pysnmp dispatcher tasks om 'Task was destroyed' warnings te vermijden
                try:
                    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                    try:
                        loop.run_until_complete(loop.shutdown_asyncgens())
                    except Exception:
                        pass
                except Exception:
                    pass
                loop.close()
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass
            if not result:
                return None
            model, ctrl_name = result
            if not model:
                return None
            mu = model.upper()
            if any(mu.startswith(p) for p in ("MX", "CX", "KU", "VX")):
                detected_name = (ctrl_name or model or "").strip()
                return (ip, "Novastar_COEX", detected_name)
        except Exception:
            return None
        return None

    def check_ip(self, ip):
        # Backwards compat — niet meer gebruikt door run()
        return self.check_ip_http(ip)

    def fetch_processor_name(self, ip):
        try:
            resp = requests.get(f"http://{ip}/api/v1/public?sys.description", timeout=0.8)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and "sys" in data:
                    name = data["sys"].get("description", "")
                    name = self.clean_candidate(name)
                    if name:
                        return name
        except:
            pass

        try:
            host_name = socket.gethostbyaddr(ip)[0]
            host_name = self.clean_candidate(host_name)
            if host_name:
                return host_name
        except:
            pass

        return ""

    def fetch_brompton_name(self, ip):
        candidates = [
            "system/processor-name",
            "system/name",
            "presets/active/name",
        ]
        for path in candidates:
            try:
                resp = requests.get(f"http://{ip}/api/{path}", timeout=0.4)
                if resp.status_code != 200:
                    continue
                data = resp.json() if resp.content else {}
                if isinstance(data, dict):
                    for key in ("processor-name", "name"):
                        if key in data:
                            value = self.clean_candidate(str(data.get(key, "")))
                            if value:
                                return value
                    for value in data.values():
                        if isinstance(value, str):
                            value = self.clean_candidate(value)
                            if value:
                                return value
            except Exception:
                continue
        return ""

    def extract_name_from_payload(self, payload):
        """Not used anymore, kept for compatibility"""
        return ""

    def clean_candidate(self, value):
        if not isinstance(value, str):
            return ""
        cleaned = value.strip()
        if not cleaned:
            return ""
        if len(cleaned) > 100:
            return ""
        return cleaned

# --- GUI CLASSES ---

def display_type_label(ptype):
    p = str(ptype or "")
    if p == "Novastar_COEX":
        return "COEX"
    if p in ("Brompton", "BROMPTON"):
        return "BROMPTON"
    return p

class ProcessorCard(QFrame):
    clicked = Signal(str)
    def __init__(self, name, ip, ptype):
        super().__init__()
        self.ip = ip; self.name = name; self.ptype = ptype; self.status = "offline"; self.had_error = False; self.is_selected = False; self.is_highlighted = False
        self.setObjectName("ProcCard"); self.setFixedHeight(85); self.setCursor(Qt.PointingHandCursor)
        self.outer_layout = QVBoxLayout(self); self.outer_layout.setContentsMargins(2, 2, 2, 2); self.outer_layout.setSpacing(0)
        self.inner_frame = QFrame(); self.inner_frame.setObjectName("InnerCard")
        self.inner_layout = QVBoxLayout(self.inner_frame); self.inner_layout.setContentsMargins(15, 8, 10, 8); self.inner_layout.setSpacing(2)
        top = QHBoxLayout()
        n = QLabel(str(name)); n.setFont(QFont("Segoe UI", 11, QFont.Bold)); n.setStyleSheet("border:none; background:transparent; color:#fff;")
        t = QLabel(display_type_label(ptype).upper()); t.setFont(QFont("Segoe UI", 8, QFont.Bold)); t.setStyleSheet("border:none; color:#2a82da; background:#111; padding:2px 6px; border-radius:3px;")
        top.addWidget(n); top.addStretch(); top.addWidget(t); self.inner_layout.addLayout(top)
        i = QLabel(f'<a href="http://{ip}" style="color:#2a82da; text-decoration:underline;">{ip}</a>'); i.setFont(QFont("Consolas", 9)); i.setTextFormat(Qt.RichText); i.setTextInteractionFlags(Qt.LinksAccessibleByMouse); i.setOpenExternalLinks(True); i.setCursor(Qt.PointingHandCursor); i.setToolTip(f"Open http://{ip} in browser"); i.setStyleSheet("border:none; background:transparent;"); i.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred); self.inner_layout.addWidget(i)
        self.outer_layout.addWidget(self.inner_frame); self.update_style()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton: self.clicked.emit(self.ip)
        super().mousePressEvent(e)

    def set_status(self, s, force=False):
        # offline mag altijd gezet worden (netwerk weg); anders sticky error bewaren
        if not force and s == "ok" and self.had_error:
            self.status = "error"; self.update_style(); return
        self.status = s; self.update_style()

    def force_error(self): self.had_error = True; self.status = "error"; self.update_style()
    def set_offline(self): self.status = "offline"; self.update_style()
    def reset_error(self): self.had_error = False; self.status = "ok"; self.update_style()
    def set_selected(self, s): self.is_selected = s; self.update_style()
    def set_highlighted(self, highlighted):
        self.is_highlighted = highlighted
        self.update_style()
    def update_style(self):
        c = "#444"  # grijs = offline/onbekend
        if self.status == "ok": c = "#2ecc71"    # groen
        elif self.status == "error": c = "#e74c3c"  # rood
        b = "2px solid #2a82da" if self.is_selected else "2px solid transparent"
        if self.is_highlighted:
            bg = "#0a3a6a"
            border = "3px solid #2a82da"
        else:
            bg = "#1e1e1e"
            border = f"5px solid {c}"
        self.setStyleSheet(f"#ProcCard {{ border: {b}; background: transparent; border-radius: 6px; }}")
        self.inner_frame.setStyleSheet(f"#InnerCard {{ background: {bg}; border-left: {border}; border-radius: 3px; }}")

class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_processors=[], current_web_auth=None, current_web_server=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Processors")
        self.resize(950, 600)
        self.setMinimumSize(640, 420)
        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            target_w = min(950, max(640, avail.width() - 40))
            target_h = min(700, max(420, avail.height() - 60))
            self.resize(target_w, target_h)
        self.processors = list(current_processors)
        auth_data = current_web_auth if isinstance(current_web_auth, dict) else {}
        web_server_data = current_web_server if isinstance(current_web_server, dict) else {}
        self.current_web_username = str(auth_data.get("username", WEB_DEFAULT_USERNAME)).strip() or WEB_DEFAULT_USERNAME
        self.current_web_password_hash = str(auth_data.get("password_hash", hash_password(WEB_DEFAULT_PASSWORD)))
        self.current_bind_ip = str(web_server_data.get("bind_ip", "")).strip()
        self.edit_index = -1 
        
        self.setStyleSheet("QDialog { background-color: #121212; } QLabel { color: #eaeaea; font-family: 'Segoe UI'; } QLineEdit, QComboBox { background-color: #1e1e1e; border: 1px solid #333; border-radius: 5px; padding: 10px; color: #fff; } QListWidget { background-color: #1e1e1e; border: 1px solid #333; border-radius: 5px; color: #ddd; } QPushButton { background-color: #333; color: white; border-radius: 5px; padding: 10px; border: none; } QProgressBar { border: none; background-color: #111; height: 4px; } QProgressBar::chunk { background-color: #2a82da; }")
        
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        main = QVBoxLayout(content)
        main.setContentsMargins(30,30,30,30)
        main.setSpacing(25)
        
        main.addWidget(QLabel("DEVICE MANAGEMENT", styleSheet="font-size: 18px; font-weight: bold; color: #fff;"))
        
        split = QHBoxLayout()
        split.setSpacing(30)
        
        left = QVBoxLayout()
        left.addWidget(QLabel("Active Devices", styleSheet="font-weight: bold; color: #aaa;"))
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.refresh_list()
        left.addWidget(self.list_widget)
        
        btn_del = QPushButton("Remove Selected")
        btn_del.setAutoDefault(False)
        btn_del.setDefault(False)
        btn_del.setStyleSheet("background-color: #2c0b0b; color: #ff5555;")
        btn_del.clicked.connect(self.remove_processor)
        left.addWidget(btn_del)
        
        split.addLayout(left, 45)
        
        right = QVBoxLayout()
        right.setSpacing(15)
        self.lbl_action = QLabel("Add New Device", styleSheet="font-weight: bold; color: #aaa;")
        right.addWidget(self.lbl_action)
        self.inp_name = QLineEdit(); self.inp_name.setPlaceholderText("Name")
        self.inp_ip = QLineEdit(); self.inp_ip.setPlaceholderText("IP Address")
        self.inp_type = QComboBox(); self.inp_type.addItems(["HELIOS", "COEX", "BROMPTON"])
        
        right.addWidget(QLabel("Name:"))
        right.addWidget(self.inp_name)
        right.addWidget(QLabel("IP:"))
        right.addWidget(self.inp_ip)
        right.addWidget(QLabel("Type:"))
        right.addWidget(self.inp_type)
        
        btn_row = QHBoxLayout()
        self.btn_save = QPushButton("ADD DEVICE")
        self.btn_save.setAutoDefault(True)
        self.btn_save.setDefault(True)
        self.btn_save.setStyleSheet("background-color: #27ae60;")
        self.btn_save.clicked.connect(self.save_device)
        
        self.btn_cancel = QPushButton("Cancel Edit")
        self.btn_cancel.setAutoDefault(False)
        self.btn_cancel.setDefault(False)
        self.btn_cancel.setStyleSheet("background-color: #444; color: #aaa;")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self.cancel_edit)
        
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.btn_cancel)
        right.addLayout(btn_row)
        
        line = QFrame(); line.setFrameShape(QFrame.HLine); line.setStyleSheet("color: #333;")
        right.addWidget(line)
        right.addWidget(QLabel("Pro Scanner", styleSheet="font-weight: bold; color: #aaa; margin-top: 10px;"))

        right.addWidget(QLabel("Scan Target:"))
        self.cmb_scan_target = QComboBox()
        self.cmb_scan_target.addItems(["ALL", "BROMPTON", "HELIOS", "COEX"])
        self.cmb_scan_target.setCurrentText("ALL")
        right.addWidget(self.cmb_scan_target)
        
        sl = QHBoxLayout()
        self.btn_scan = QPushButton("SCAN NETWORK")
        self.btn_scan.setAutoDefault(False)
        self.btn_scan.setStyleSheet("background-color: #2a82da;")
        self.btn_scan.clicked.connect(self.start_scan)
        sl.addWidget(self.btn_scan)
        self.progress = QProgressBar(); self.progress.setTextVisible(False)
        sl.addWidget(self.progress)
        right.addLayout(sl)
        
        self.scan_lbl = QLabel("Ready."); self.scan_lbl.setStyleSheet("color: #666; font-style: italic;")
        right.addWidget(self.scan_lbl)

        line_auth = QFrame(); line_auth.setFrameShape(QFrame.HLine); line_auth.setStyleSheet("color: #333;")
        right.addWidget(line_auth)
        right.addWidget(QLabel("Web Interface Login", styleSheet="font-weight: bold; color: #aaa; margin-top: 10px;"))

        self.inp_web_user = QLineEdit(); self.inp_web_user.setPlaceholderText("Username")
        self.inp_web_user.setText(self.current_web_username)
        self.inp_web_pass = QLineEdit(); self.inp_web_pass.setEchoMode(QLineEdit.Password)
        self.inp_web_pass.setPlaceholderText("New password (leave empty to keep current)")

        right.addWidget(QLabel("Username:"))
        right.addWidget(self.inp_web_user)
        right.addWidget(QLabel("Password:"))
        right.addWidget(self.inp_web_pass)

        right.addWidget(QLabel("Webserver Adapter/IP:"))
        self.cmb_bind_ip = QComboBox()
        self.cmb_bind_ip.addItem("AUTO (best match)", "")
        selected_index = 0
        seen_ips = set()
        for iface in QNetworkInterface.allInterfaces():
            flags = iface.flags()
            if not (flags & QNetworkInterface.IsUp):
                continue
            if flags & QNetworkInterface.IsLoopBack:
                continue
            name = iface.humanReadableName() or iface.name()
            for entry in iface.addressEntries():
                ip = entry.ip().toString()
                if "." not in ip:
                    continue
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                idx = self.cmb_bind_ip.count()
                self.cmb_bind_ip.addItem(f"{name} ({ip})", ip)
                if self.current_bind_ip and ip == self.current_bind_ip:
                    selected_index = idx

        if self.current_bind_ip and selected_index == 0:
            self.cmb_bind_ip.addItem(f"Configured IP ({self.current_bind_ip})", self.current_bind_ip)
            selected_index = self.cmb_bind_ip.count() - 1

        self.cmb_bind_ip.setCurrentIndex(selected_index)
        right.addWidget(self.cmb_bind_ip)

        bind_hint = QLabel("Tip: select your Wi-Fi adapter here to view logs from anywhere in the venue.")
        bind_hint.setStyleSheet("color: #666; font-style: italic;")
        right.addWidget(bind_hint)
        right.addStretch()
        split.addLayout(right, 55)
        main.addLayout(split)
        
        footer = QHBoxLayout(); footer.addStretch()
        btn_close = QPushButton("SAVE & CLOSE")
        btn_close.setAutoDefault(False)
        btn_close.setFixedSize(180, 50)
        btn_close.clicked.connect(self.accept)
        footer.addWidget(btn_close)
        main.addLayout(footer)

        scroll.setWidget(content)
        root_layout.addWidget(scroll)

    def refresh_list(self):
        self.list_widget.clear()
        for p in self.processors:
            shown_type = display_type_label(p.get('type'))
            self.list_widget.addItem(f"{p.get('name')} | {shown_type} | {p.get('ip')}")

    def _type_to_display(self, ptype):
        t = str(ptype or "")
        if t == "Novastar_COEX":
            return "COEX"
        if t in ("Brompton", "BROMPTON"):
            return "BROMPTON"
        if t.lower() == "helios":
            return "HELIOS"
        return t.upper()

    def _display_to_type(self, shown_type):
        t = str(shown_type or "").upper()
        if t == "COEX":
            return "Novastar_COEX"
        if t == "BROMPTON":
            return "BROMPTON"
        if t == "HELIOS":
            return "Helios"
        return t

    def on_item_clicked(self, item):
        row = self.list_widget.row(item)
        data = self.processors[row]
        self.inp_name.setText(data.get("name", ""))
        self.inp_ip.setText(data.get("ip", ""))
        self.inp_type.setCurrentText(self._type_to_display(data.get("type", "Helios")))
        self.edit_index = row
        self.lbl_action.setText("Edit Device")
        self.btn_save.setText("UPDATE DEVICE")
        self.btn_save.setStyleSheet("background-color: #2a82da;")
        self.btn_cancel.setVisible(True)

    def cancel_edit(self):
        self.edit_index = -1
        self.inp_name.clear()
        self.inp_ip.clear()
        self.lbl_action.setText("Add New Device")
        self.btn_save.setText("ADD DEVICE")
        self.btn_save.setStyleSheet("background-color: #27ae60;")
        self.btn_cancel.setVisible(False)
        self.list_widget.clearSelection()

    def save_device(self):
        name = self.inp_name.text()
        ip = self.inp_ip.text()
        ptype = self._display_to_type(self.inp_type.currentText())
        if not name or not ip: return
        new_data = {"name": name, "ip": ip, "type": ptype}
        if self.edit_index >= 0: self.processors[self.edit_index] = new_data
        else: self.processors.append(new_data)
        self.refresh_list()
        self.cancel_edit()

    def remove_processor(self):
        selected_rows = sorted([self.list_widget.row(item) for item in self.list_widget.selectedItems()], reverse=True)
        if not selected_rows:
            return
        for row in selected_rows:
            if row >= 0:
                del self.processors[row]
        self.refresh_list()
        self.cancel_edit()

    def start_scan(self):
        self.btn_scan.setEnabled(False); self.btn_scan.setText("SCANNING...")
        scan_target = self.cmb_scan_target.currentText().strip().upper()
        self.scan_lbl.setText(f"Scanning subnets... ({scan_target})")
        self.scanner = ScanWorker(scan_mode=scan_target)
        self.scanner.progress_signal.connect(self.progress.setValue)
        self.scanner.found_signal.connect(self.on_found)
        self.scanner.log_signal.connect(self.scan_lbl.setText)
        self.scanner.finished_signal.connect(self.on_scan_finished)
        self.scanner.start()

    def on_found(self, ip, ptype, detected_name):
        detected_name = (detected_name or "").strip()
        prefix_map = {"Helios": "Helios", "Novastar_COEX": "COEX", "Brompton": "BR", "BROMPTON": "BR"}
        prefix = prefix_map.get(ptype, "DEV")
        fallback_name = f"{prefix}-{ip.split('.')[-1]}"

        existing = next((p for p in self.processors if p.get('ip') == ip), None)
        if existing:
            current_name = str(existing.get('name', '')).strip()
            generic_prefixes = ("Helios-", "COEX-", "BR-", "Brompton-", "BROMPTON-", "CL-", "DEV-")
            if detected_name and (not current_name or current_name.startswith(generic_prefixes)):
                existing['name'] = detected_name
            # Update type als die nog niet juist was
            if existing.get('type') != ptype and ptype != "Helios":
                existing['type'] = ptype
            self.refresh_list()
            return

        name = detected_name or fallback_name
        entry = {"name": name, "ip": ip, "type": ptype}
        if ptype == "Novastar_COEX":
            entry["snmp_community"] = "public"
        self.processors.append(entry)
        self.refresh_list()

    def on_scan_finished(self, count):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("SCAN NETWORK")
        self.progress.setValue(0)
        self.scan_lbl.setText(f"Found {count} devices.")

    def get_processors(self):
        return self.processors

    def get_web_auth(self):
        username = self.inp_web_user.text().strip() or WEB_DEFAULT_USERNAME
        password = self.inp_web_pass.text()
        password_hash = self.current_web_password_hash
        if password:
            password_hash = hash_password(password)
        return {"username": username, "password_hash": password_hash}

    def get_web_server_settings(self):
        bind_ip = str(self.cmb_bind_ip.currentData() or "").strip()
        return {"bind_ip": bind_ip}

# --- MAIN APP ---

class LEDLoggerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_json(CONFIG_FILE, {"processors": []})
        self._ensure_web_auth_config()
        self._ensure_web_server_config()
        self.history_data = load_json(HISTORY_FILE, [])
        self.processors = self.config["processors"]
        self.processor_widgets = {}; self.sockets = {}; self.coex_threads = {}; self.brompton_threads = {}; self.selected_ip = None; self.log_history = []
        self.helios_identify_state = {}
        self.helios_identify_checkboxes = {}
        self.live_group_expanded = {}
        self.log_row_meta = {}
        self.log_group_children = {}
        self.log_group_targets = {}
        self.group_identify_checkboxes = {}
        self.trap_listener = None
        self.web_server = None
        self.web_thread = None
        
        # Basis UI setup
        self.setup_ui()
        
        # Initialiseer data voor webserver
        LogWebServer.log_data = self.log_history
        LogWebServer.device_statuses = {p['ip']: "offline" for p in self.processors if 'ip' in p}
        self._apply_web_auth()

        # Start webserver en toon pas "active" als bind echt gelukt is.
        self.start_web_server()

        self.http_worker = MonitorWorker(self.processors)
        self.http_worker.status_signal.connect(self.update_visuals)
        self.http_worker.alert_signal.connect(self.on_alert_received)
        QTimer.singleShot(1000, self.http_worker.start)
        self.init_sockets()

        # Geen processors geconfigureerd → open automatisch Device Manager
        if not self.processors:
            QTimer.singleShot(500, self.open_settings)

    def _detect_local_ip(self):
        # Prefer the interface actually used to reach configured processors.
        for p in self.processors:
            target_ip = str(p.get("ip", "")).strip()
            if not target_ip:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((target_ip, 1))
                local_ip = s.getsockname()[0]
                s.close()
                if local_ip and local_ip != "0.0.0.0" and not local_ip.startswith("127."):
                    return local_ip
            except Exception:
                continue

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip and local_ip != "0.0.0.0":
                return local_ip
        except Exception:
            pass

        # Hostname can map to multiple adapters; prefer private, non-loopback IPv4.
        try:
            candidates = set()
            for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = entry[4][0]
                if ip and not ip.startswith("127."):
                    candidates.add(ip)

            private_candidates = []
            public_candidates = []
            for ip in candidates:
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr.is_private:
                        private_candidates.append(ip)
                    else:
                        public_candidates.append(ip)
                except ValueError:
                    continue

            if private_candidates:
                return sorted(private_candidates)[0]
            if public_candidates:
                return sorted(public_candidates)[0]
        except Exception:
            pass

        try:
            host_ip = socket.gethostbyname(socket.gethostname())
            if host_ip and not host_ip.startswith("127."):
                return host_ip
        except Exception:
            pass

        return "localhost"

    def start_web_server(self):
        """Start de remote monitor server en geef duidelijke status in de GUI."""
        configured_bind_ip = str(self.config.get("web_server", {}).get("bind_ip", "")).strip()
        bind_candidates = ["0.0.0.0"]
        if configured_bind_ip:
            bind_candidates = [configured_bind_ip, "0.0.0.0"]
        bind_candidates.append("127.0.0.1")

        # Unieke volgorde behouden
        unique_candidates = []
        for b in bind_candidates:
            if b not in unique_candidates:
                unique_candidates.append(b)
        bind_candidates = unique_candidates

        local_ip = configured_bind_ip if configured_bind_ip else self._detect_local_ip()
        preferred_ports = (8090, 8091, 8092, 8093, 8094)
        last_error = None

        for bind_ip in bind_candidates:
            for port in preferred_ports:
                try:
                    self.web_server = ThreadingHTTPServer((bind_ip, port), LogWebServer)
                    advert_ip = local_ip
                    if bind_ip != "0.0.0.0":
                        advert_ip = bind_ip
                    elif not advert_ip:
                        advert_ip = self._detect_local_ip()
                    url = f"http://{advert_ip}:{port}"
                    self.setWindowTitle(f"{APP_NAME} - {VERSION} | Remote Log: {url}")
                    self.set_remote_monitor_url(url)
                    self.add_log_entry("green", f"REMOTE MONITOR ACTIVE: {url}", "SYSTEM")
                    if configured_bind_ip and bind_ip == "0.0.0.0":
                        self.add_log_entry("orange", f"Configured bind IP {configured_bind_ip} unavailable; fallback to all adapters.", "SYSTEM")
                    if bind_ip == "127.0.0.1":
                        self.add_log_entry("orange", "Webserver draait enkel lokaal (127.0.0.1). Controleer firewall/adapterkeuze voor externe toegang.", "SYSTEM")
                    self.web_thread = threading.Thread(target=self.web_server.serve_forever, daemon=True)
                    self.web_thread.start()
                    return True
                except OSError as e:
                    last_error = e

        self.remote_monitor_url = ""
        self.setWindowTitle(f"{APP_NAME} - {VERSION} | Remote Log: unavailable")
        self.remote_url_label.setText('<span style="color:#ff8888;">Remote log unavailable</span>')
        self.remote_url_label.setToolTip(str(last_error) if last_error else "Unknown startup error")
        self.btn_copy_remote_url.setEnabled(False)
        err_txt = str(last_error) if last_error else "unknown startup error"
        self.add_log_entry("red", f"REMOTE MONITOR FAILED: {err_txt}", "SYSTEM")
        return False

    def restart_web_server(self):
        if self.web_server is not None:
            try:
                self.web_server.shutdown()
                self.web_server.server_close()
            except Exception:
                pass
        if self.web_thread is not None and self.web_thread.is_alive():
            try:
                self.web_thread.join(timeout=1.2)
            except Exception:
                pass
        self.web_server = None
        self.web_thread = None
        return self.start_web_server()

    def _ensure_web_auth_config(self):
        web_auth = self.config.get("web_auth")
        changed = False
        if not isinstance(web_auth, dict):
            web_auth = {}
            changed = True

        username = str(web_auth.get("username", "")).strip()
        if not username:
            web_auth["username"] = WEB_DEFAULT_USERNAME
            changed = True

        if not web_auth.get("password_hash"):
            web_auth["password_hash"] = hash_password(WEB_DEFAULT_PASSWORD)
            changed = True

        self.config["web_auth"] = web_auth
        if changed:
            save_config(self.config)

    def _ensure_web_server_config(self):
        web_server = self.config.get("web_server")
        changed = False
        if not isinstance(web_server, dict):
            web_server = {}
            changed = True

        bind_ip = str(web_server.get("bind_ip", "")).strip()
        if web_server.get("bind_ip", "") != bind_ip:
            web_server["bind_ip"] = bind_ip
            changed = True

        if "bind_ip" not in web_server:
            web_server["bind_ip"] = ""
            changed = True

        self.config["web_server"] = web_server
        if changed:
            save_config(self.config)

    def _apply_web_auth(self):
        web_auth = self.config.get("web_auth", {})
        LogWebServer.configure_auth(
            web_auth.get("username", WEB_DEFAULT_USERNAME),
            web_auth.get("password_hash", hash_password(WEB_DEFAULT_PASSWORD)),
        )

    def set_remote_monitor_url(self, url):
        self.remote_monitor_url = url
        self.remote_url_label.setText(f'<a href="{url}" style="color:#2a82da; text-decoration: none;">{url}</a>')
        self.remote_url_label.setToolTip(url)
        self.btn_copy_remote_url.setEnabled(True)

    def copy_remote_monitor_url(self):
        if not getattr(self, "remote_monitor_url", ""):
            return
        QApplication.clipboard().setText(self.remote_monitor_url)
        self.add_log_entry("green", "Remote monitor URL copied to clipboard.", "SYSTEM")

    def setup_ui(self):
        p = QPalette(); p.setColor(QPalette.Window, QColor("#121212")); p.setColor(QPalette.WindowText, QColor("#eaeaea")); p.setColor(QPalette.Base, QColor("#1e1e1e")); p.setColor(QPalette.AlternateBase, QColor("#121212")); p.setColor(QPalette.Text, QColor("#eaeaea")); p.setColor(QPalette.Button, QColor("#1e1e1e")); p.setColor(QPalette.ButtonText, QColor("#eaeaea")); self.setPalette(p)
        main = QWidget(); self.setCentralWidget(main); layout = QHBoxLayout(main); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)
        
        # Sidebar
        sidebar = QFrame(); sidebar.setFixedWidth(300); sidebar.setStyleSheet("background: #181818; border-right: 1px solid #2a2a2a;"); s_lay = QVBoxLayout(sidebar); s_lay.setContentsMargins(20,25,20,25)
        s_lay.addWidget(QLabel(APP_NAME, styleSheet="font-size: 18pt; font-weight: bold; color: #2a82da;")); s_lay.addWidget(QLabel("SYSTEM MONITOR", styleSheet="color: #666; font-size: 10px; letter-spacing: 1px;"))

        remote_row = QHBoxLayout()
        remote_icon = QLabel("🌐")
        remote_icon.setStyleSheet("color: #2a82da; font-size: 12px;")
        remote_row.addWidget(remote_icon)

        self.remote_url_label = QLabel('<a href="#" style="color:#2a82da; text-decoration: none;">Remote log unavailable</a>')
        self.remote_url_label.setTextFormat(Qt.RichText)
        self.remote_url_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.remote_url_label.setOpenExternalLinks(True)
        self.remote_url_label.setStyleSheet("color: #2a82da; font-size: 11px;")
        remote_row.addWidget(self.remote_url_label, 1)

        self.btn_copy_remote_url = QPushButton("📋")
        self.btn_copy_remote_url.setCursor(Qt.PointingHandCursor)
        self.btn_copy_remote_url.setToolTip("Copy remote monitor URL")
        self.btn_copy_remote_url.setFixedSize(28, 24)
        self.btn_copy_remote_url.setEnabled(False)
        self.btn_copy_remote_url.setStyleSheet("QPushButton { background: #252525; border-radius: 5px; } QPushButton:hover { background: #333; }")
        self.btn_copy_remote_url.clicked.connect(self.copy_remote_monitor_url)
        remote_row.addWidget(self.btn_copy_remote_url)

        s_lay.addLayout(remote_row)
        s_lay.addSpacing(18)
        btn_man = QPushButton("CONFIGURE DEVICES"); btn_man.setCursor(Qt.PointingHandCursor); btn_man.setStyleSheet("QPushButton { background: #252525; color: white; border-radius: 5px; padding: 12px; font-weight: bold; text-align: left; padding-left: 20px;} QPushButton:hover { background: #333; border-left: 2px solid #2a82da; }"); btn_man.clicked.connect(self.open_settings); s_lay.addWidget(btn_man); s_lay.addSpacing(30)
        
        # --- Sidebar STATUS OVERVIEW sectie ---
        s_lay.addWidget(QLabel("STATUS OVERVIEW", styleSheet="color: #555; font-size: 11px; font-weight: bold; margin-bottom: 5px;"))
        
        self.device_list = QListWidget()
        self.device_list.setDragDropMode(QListWidget.InternalMove)
        self.device_list.setSelectionMode(QListWidget.SingleSelection)
        self.device_list.setSpacing(2)  # Minimale ruimte tussen kaartjes voor een strakke look
        
        # Voorkom horizontale scrollbar en zorg voor strakke aansluiting
        self.device_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.device_list.setContentsMargins(0, 0, 0, 0)
        
        self.device_list.setStyleSheet("""
            QListWidget { 
                background: transparent; 
                border: none; 
                outline: none;
            }
            QListWidget::item { 
                background: transparent; 
                padding: 0px; 
                margin: 0px;
            }
        """)
        
        self.device_list.model().rowsMoved.connect(self.on_order_changed)
        s_lay.addWidget(self.device_list)
        
        self.rebuild_list()
        
        btn_clr = QPushButton("CLEAR LOG / SAVE SESSION"); btn_clr.setCursor(Qt.PointingHandCursor); btn_clr.setStyleSheet("QPushButton { background: #2c0b0b; color: #ff8888; border-radius: 5px; padding: 12px; font-weight: bold; } QPushButton:hover { background: #e74c3c; color: white; }"); btn_clr.clicked.connect(self.clear_log); s_lay.addWidget(btn_clr); layout.addWidget(sidebar)
        
        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: 0; } QTabBar::tab { background: #111; color: #666; padding: 10px 20px; border-top-left-radius: 5px; border-top-right-radius: 5px; margin-right: 2px; } QTabBar::tab:selected { background: #1e1e1e; color: #fff; border-top: 2px solid #2a82da; }")
        
        # Live Tab
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(9)
        self.log_table.setHorizontalHeaderLabels(["Time", "Device", "MAC", "ID", "OPT", "PORT", "TILE", "Message", "OID"])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.log_table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Interactive)
        self.log_table.setColumnWidth(8, 280)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setSelectionMode(QTableWidget.NoSelection)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.cellClicked.connect(self.on_log_table_cell_clicked)
        self.log_table.setStyleSheet("""
            QTableWidget { 
                background: #0f0f0f; 
                border: none; 
                color: #ddd; 
                gridline-color: #1a1a1a;
                font-family: Consolas; 
                font-size: 10pt;
            }
            QHeaderView::section {
                background: #181818;
                color: #888;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 9pt;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #1a1a1a;
            }
        """)
        self.tabs.addTab(self.log_table, "LIVE MONITOR")
        
        # History Tab
        hist_widget = QWidget()
        h_lay = QVBoxLayout(hist_widget); h_lay.setContentsMargins(20,20,20,20)
        self.history_tree = QTreeWidget(); self.history_tree.setHeaderLabels(["Date/Time", "Devices Affected", "Event Count"])
        self.history_tree.setSelectionMode(QTreeWidget.MultiSelection)
        self.history_tree.setStyleSheet("QTreeWidget { background: #111; border: 1px solid #333; color: #ddd; } QHeaderView::section { background: #222; color: #aaa; padding: 5px; border: none; }")
        self.history_tree.itemClicked.connect(self.on_history_click)
        self.history_detail = QTextEdit(); self.history_detail.setReadOnly(True); self.history_detail.setStyleSheet("background: #0f0f0f; border: 1px solid #333; color: #888; font-family: Consolas;")
        splitter = QSplitter(Qt.Vertical); splitter.addWidget(self.history_tree); splitter.addWidget(self.history_detail); splitter.setSizes([200, 400])
        h_lay.addWidget(splitter)
        btn_del_hist = QPushButton("REMOVE SELECTED HISTORY")
        btn_del_hist.setStyleSheet("background-color: #2c0b0b; color: #ff5555; padding: 10px; font-weight: bold; margin-top: 5px;")
        btn_del_hist.clicked.connect(self.remove_selected_history)
        h_lay.addWidget(btn_del_hist)
        self.tabs.addTab(hist_widget, "HISTORY / BASELINES")
        self.reload_history_tab()
        layout.addWidget(self.tabs)

    def init_sockets(self):
        for ip, sock in self.sockets.items():
            if not isinstance(sock, (NovastarCoexSocket, BromptonSocket)):
                sock.stop()
        for ip, t in self.coex_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        for ip, t in self.brompton_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, BromptonSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        self.coex_threads = {}
        self.brompton_threads = {}
        self.sockets = {}
        for p in self.processors:
            ip = p.get("ip")
            ptype = p.get("type", "").lower()
            if "helios" in ptype:
                sock = HeliosSocket(ip, p.get("name"), parent=self)
                sock.error_detected.connect(self.on_socket_error)
                self.sockets[ip] = sock
            elif "brompton" in ptype:
                poll_interval = p.get("brompton_poll_interval", BROMPTON_POLL_INTERVAL_SEC)
                sock = BromptonSocket(ip, p.get("name"), poll_interval=poll_interval, parent=None)
                sock.error_detected.connect(self.on_socket_error)
                self.sockets[ip] = sock
                t = QThread(self)
                sock.moveToThread(t)
                t.started.connect(sock.start_polling)
                t.finished.connect(sock.deleteLater)
                self.brompton_threads[ip] = t
                t.start()
            elif "coex" in ptype or "novastar" in ptype or "mx" in ptype:
                community = p.get("snmp_community", "public")
                port_map = p.get("coex_port_map", {})
                backup_api_enabled = p.get("coex_backup_api_enabled", COEX_BACKUP_API_DEFAULT_ENABLED)
                backup_api_poll_interval = p.get("coex_backup_api_poll_interval", COEX_BACKUP_API_POLL_INTERVAL_SEC)
                backup_api_log_every_poll = p.get("coex_backup_api_log_every_poll", COEX_BACKUP_API_DEFAULT_LOG_EVERY_POLL)
                backup_api_port = p.get("coex_backup_api_port", COEX_BACKUP_API_DEFAULT_PORT)
                sock = NovastarCoexSocket(
                    ip,
                    p.get("name"),
                    community=community,
                    port_map=port_map,
                    api_backup_enabled=backup_api_enabled,
                    api_backup_poll_interval=backup_api_poll_interval,
                    api_backup_log_every_poll=backup_api_log_every_poll,
                    api_backup_port=backup_api_port,
                    parent=None,
                )
                sock.error_detected.connect(self.on_socket_error)
                self.sockets[ip] = sock
                t = QThread(self)
                sock.moveToThread(t)
                t.started.connect(sock.start_polling)
                t.finished.connect(sock.deleteLater)
                self.coex_threads[ip] = t
                t.start()

        # Start trap listener één keer (niet per processor)
        has_coex = any("coex" in p.get("type", "").lower() or "novastar" in p.get("type", "").lower()
                       for p in self.processors)
        if has_coex:
            ip_names = {p['ip']: p.get('name', p['ip'])
                        for p in self.processors
                        if p.get('ip') and ("coex" in p.get("type","").lower() or "novastar" in p.get("type","").lower())}
            if not hasattr(self, "trap_listener") or self.trap_listener is None:
                self.trap_listener = CoexTrapListener(port=COEX_TRAP_PORT, ip_names=ip_names)
                self.trap_listener.trap_received.connect(self.on_trap_received)
                self.trap_listener.start()
            else:
                # Namen kunnen gewijzigd zijn in settings/scan; hou listener-map actueel.
                self.trap_listener.ip_names = ip_names

    def _processor_name_for_ip(self, ip):
        proc = next((p for p in self.processors if p.get("ip") == ip), None)
        if proc:
            name = str(proc.get("name", "")).strip()
            if name:
                return name
        sock = self.sockets.get(ip)
        if isinstance(sock, NovastarCoexSocket):
            name = str(getattr(sock, "name", "")).strip()
            if name:
                return name
        return ip

    def _processor_type_for_ip(self, ip):
        proc = next((p for p in self.processors if p.get("ip") == ip), None)
        if not proc:
            return ""
        return str(proc.get("type", "")).strip().lower()

    def _normalize_receiver_mac(self, mac_text):
        txt = str(mac_text or "").strip().lower().replace("-", ":")
        if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", txt):
            return txt
        return ""

    def _sync_identify_checkboxes(self, ip, mac, checked, source_checkbox=None):
        key = (str(ip or "").strip(), str(mac or "").strip().lower())
        widgets = self.helios_identify_checkboxes.get(key, [])
        alive = []
        for cb in widgets:
            try:
                if cb is source_checkbox:
                    alive.append(cb)
                    continue
                cb.blockSignals(True)
                cb.setChecked(bool(checked))
                cb.blockSignals(False)
                alive.append(cb)
            except Exception:
                continue
        self.helios_identify_checkboxes[key] = alive

    def _identify_target_from_entry(self, entry):
        ip_text = str(entry.get("ip", "") or "").strip()
        if not ip_text:
            return None
        if "helios" not in self._processor_type_for_ip(ip_text):
            return None
        receiver_info = entry.get("receiver_info", {}) if isinstance(entry.get("receiver_info", {}), dict) else {}
        mac_norm = self._normalize_receiver_mac(receiver_info.get("mac", ""))
        if not mac_norm:
            return None
        return (ip_text, mac_norm)

    def _sync_group_identify_checkbox(self, group_id):
        cb = self.group_identify_checkboxes.get(group_id)
        if cb is None:
            return
        targets = self.log_group_targets.get(group_id, [])
        if not targets:
            cb.blockSignals(True)
            cb.setChecked(False)
            cb.blockSignals(False)
            return

        checked = all(bool(self.helios_identify_state.get((ip, mac), False)) for ip, mac in targets)
        cb.blockSignals(True)
        cb.setChecked(checked)
        cb.blockSignals(False)

    def _refresh_group_checkboxes_for_target(self, ip, mac):
        target = (str(ip or "").strip(), str(mac or "").strip().lower())
        for group_id, targets in self.log_group_targets.items():
            if target in targets:
                self._sync_group_identify_checkbox(group_id)

    def _on_group_identify_toggled(self, group_id, checked, source_checkbox=None):
        targets = list(dict.fromkeys(self.log_group_targets.get(group_id, [])))
        if not targets:
            return

        previous = {t: bool(self.helios_identify_state.get(t, False)) for t in targets}
        for ip_txt, mac_txt in targets:
            self.helios_identify_state[(ip_txt, mac_txt)] = bool(checked)
            self._sync_identify_checkboxes(ip_txt, mac_txt, checked, source_checkbox=None)
            ok = self._set_helios_receiver_identify(ip_txt, mac_txt, bool(checked))
            if not ok:
                prev = previous[(ip_txt, mac_txt)]
                self.helios_identify_state[(ip_txt, mac_txt)] = prev
                self._sync_identify_checkboxes(ip_txt, mac_txt, prev, source_checkbox=None)

        self._sync_group_identify_checkbox(group_id)

    def _http_send_helios_identify(self, ip, mac, enabled):
        payload = {
            "dev": {
                "receivers": {
                    mac: {
                        "identifyEnabled": bool(enabled)
                    }
                }
            }
        }
        url = f"http://{ip}/api/v1/data"
        for method in ("POST", "PATCH"):
            try:
                resp = requests.request(method, url, json=payload, timeout=1.2)
                if not (200 <= int(resp.status_code) < 300):
                    continue

                # Prefer direct confirmation from response body.
                try:
                    data = resp.json() if resp.content else {}
                    got = (
                        data.get("dev", {})
                        .get("receivers", {})
                        .get(mac, {})
                        .get("identifyEnabled")
                    )
                    if isinstance(got, bool):
                        return got == bool(enabled)
                except Exception:
                    pass

                # Fallback readback when body is incomplete.
                try:
                    read = requests.get(f"http://{ip}/api/v1/public?dev.receivers.{mac}", timeout=1.2)
                    if 200 <= int(read.status_code) < 300:
                        data = read.json() if read.content else {}
                        got = (
                            data.get("dev", {})
                            .get("receivers", {})
                            .get(mac, {})
                            .get("identifyEnabled")
                        )
                        if isinstance(got, bool):
                            return got == bool(enabled)
                except Exception:
                    pass
            except Exception:
                continue
        return False

    def _set_helios_receiver_identify(self, ip, mac, enabled):
        sent = self._http_send_helios_identify(ip, mac, enabled)

        if sent:
            return True

        self.add_log_entry("orange", f"Identify command failed for {mac}", ip, receiver_info={"mac": mac})
        return False

    def _on_identify_checkbox_toggled(self, ip, mac, checked, source_checkbox=None):
        ip_txt = str(ip or "").strip()
        mac_txt = self._normalize_receiver_mac(mac)
        if not ip_txt or not mac_txt:
            return

        key = (ip_txt, mac_txt)
        self.helios_identify_state[key] = bool(checked)
        self._sync_identify_checkboxes(ip_txt, mac_txt, checked, source_checkbox=source_checkbox)
        ok = self._set_helios_receiver_identify(ip_txt, mac_txt, bool(checked))
        if not ok:
            self.helios_identify_state[key] = not bool(checked)
            self._sync_identify_checkboxes(ip_txt, mac_txt, not bool(checked), source_checkbox=None)

        self._refresh_group_checkboxes_for_target(ip_txt, mac_txt)

    def _inject_processor_name_in_csv(self, msg, ip):
        """Vervang het controller-name veld in CSV-achtige logs met de actuele ingestelde naam."""
        if ",Controller," not in msg:
            return msg
        parts = msg.split(",", 6)
        if len(parts) < 7:
            return msg
        if parts[1].strip() != "Controller":
            return msg
        parts[2] = self._processor_name_for_ip(ip)
        parts[4] = "--"
        return ",".join(parts)

    def _strip_ip_from_controller_csv(self, msg):
        """Verwijder dubbel IP uit Controller-berichten; het IP staat al in de Device-kolom."""
        if ",Controller," not in msg:
            return msg
        parts = msg.split(",", 6)
        if len(parts) < 7:
            return msg
        if parts[1].strip() != "Controller":
            return msg
        severity = parts[0].strip()
        name = parts[2].strip()
        desc = parts[6].strip().replace(" : ", ": ")
        return f"{severity}: {name} - {desc}"

    def _strip_display_prefix(self, msg):
        txt = str(msg or "")
        if txt.lower().startswith("display:"):
            return txt.split(":", 1)[1].strip()
        return txt

    def _normalize_recover_text(self, msg):
        txt = str(msg or "")
        txt = re.sub(r"\[?ethDrop0\]?", "Ethernet Link", txt, flags=re.IGNORECASE)
        txt = re.sub(r"\[?powFiberLow\]?", "Low fiber power", txt, flags=re.IGNORECASE)
        txt = re.sub(
            r"Recover:\s*\[tileBackupMissing\]\s*(?:None|null)",
            "Recover: Backup Missing",
            txt,
            flags=re.IGNORECASE,
        )
        txt = re.sub(
            r"Recover:\s*\[ethDrop0\]\s*(?:None|null)",
            "Recover: Ethernet Link",
            txt,
            flags=re.IGNORECASE,
        )
        txt = re.sub(
            r"Recover:\s*\[noInput\]\s*(?:None|null)",
            "Recover: No input",
            txt,
            flags=re.IGNORECASE,
        )
        return txt

    def _receiver_info_from_coex_trap(self, msg):
        """Vul SFP/OUT/POS kolommen voor COEX trapregels waar poortinformatie in de beschrijving zit."""
        if ",Controller," not in msg:
            return {}
        parts = msg.split(",", 6)
        if len(parts) < 7:
            return {}

        desc = parts[6].strip()
        info = {"mac": "", "sfp": "", "output": "", "chain_pos": ""}

        # Voorbeeld: OUT1/OPT Port1 - Eth Port5 - Receiving cards : 1
        if " - Eth Port" in desc and "/OPT Port" in desc:
            try:
                left, right = desc.split(" - Eth Port", 1)
                sfp_part = left.split("/OPT Port", 1)[1]
                info["sfp"] = sfp_part.strip()

                eth_part, _, value_part = right.partition(" - ")
                info["output"] = eth_part.strip()

                if " : " in value_part:
                    tail_value = value_part.rsplit(" : ", 1)[1].strip()
                    if tail_value.isdigit():
                        info["chain_pos"] = tail_value
            except (IndexError, ValueError):
                return {}

        return {k: v for k, v in info.items() if v}

    def on_trap_received(self, color, msg, ip, oid):
        """Forward SNMP trap naar de bestaande log."""
        msg = self._inject_processor_name_in_csv(msg, ip)
        receiver_info = self._receiver_info_from_coex_trap(msg)
        self.add_log_entry(color, msg, ip, receiver_info=receiver_info, oid=oid)

        # Sync Genlock trap-state met poll-state om dubbele meldingen te vermijden.
        sock = self.sockets.get(ip)
        if isinstance(sock, NovastarCoexSocket) and "genlock" in msg.lower():
            if color in ("red", "orange"):
                sock.active_errors.add("genlock")
            elif color == "green":
                sock.active_errors.discard("genlock")

        # Update processor balkje op basis van trap-kleur
        if ip in self.processor_widgets:
            card = self.processor_widgets[ip]
            if color == "red":
                card.force_error()
            elif color == "green":
                sock = self.sockets.get(ip)
                active = getattr(sock, "active_errors", set())
                if not active:
                    card.set_status("ok")

        # Poll backup status als er een ethercon (Eth port/Eth ports) error is
        if color == "red" and "eth port" in msg.lower():
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "trigger_backup_poll_on_error", Qt.QueuedConnection)
        
        # Traps bevatten niet altijd volledige context (bijv. HDMI status).
        # Doe daarom meteen een extra poll op dezelfde COEX, zodat poll-OIDs
        # (zoals input_src_status) direct ge-evalueerd worden.
        if msg.startswith("TRAP_RAW:"):
            if "1.3.6.1.4.1.319.10.10.70." in msg or "1.3.6.1.4.1.319.10.10.30.6.1.3.1.1" in msg:
                return
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "poll_health", Qt.QueuedConnection)

    def rebuild_list(self):
        self.device_list.clear()
        self.processor_widgets = {}
        # Reset de webserver statussen bij herbouw
        LogWebServer.device_statuses = {p['ip']: "offline" for p in self.processors if 'ip' in p}
        
        for p in self.processors:
            ip = p.get('ip')
            if not ip: continue
            card = ProcessorCard(p.get('name', 'Unknown'), ip, p.get('type', 'Helios'))
            card.setFixedHeight(80)
            card.clicked.connect(self.on_card_clicked)
            item = QListWidgetItem(self.device_list)
            from PySide6.QtCore import QSize
            item.setSizeHint(QSize(0, 80)) 
            self.device_list.addItem(item)
            self.device_list.setItemWidget(item, card)
            self.processor_widgets[ip] = card

    def on_order_changed(self, parent, start, end, destination, row):
        new_order = []
        for i in range(self.device_list.count()):
            item = self.device_list.item(i)
            card = self.device_list.itemWidget(item)
            if card:
                proc_data = next((p for p in self.processors if p.get('ip') == card.ip), None)
                if proc_data: new_order.append(proc_data)
        self.processors = new_order
        self.config["processors"] = self.processors
        save_config(self.config)
        self.add_log_entry("gray", "Device order updated and saved.", "SYSTEM")

    @Slot(str, str)
    def update_visuals(self, ip, status):
        if ip in self.processor_widgets: self.processor_widgets[ip].set_status(status, force=False)
        LogWebServer.device_statuses[ip] = status

    @Slot(str, str, str)
    def on_socket_error(self, color, msg, ip):
        if ip in self.processor_widgets:
            card = self.processor_widgets[ip]
            sock = self.sockets.get(ip)
            is_unreachable = "unreachable" in msg.lower() or "SNMP unreachable" in msg
            if is_unreachable:
                # Geen netwerk → grijs (overschrijft ook sticky error)
                card.set_offline()
            elif color == "green":
                # Online/Recover: groen zetten tenzij er nog actieve errors zijn
                active = getattr(sock, "active_errors", set())
                if not active:
                    card.set_status("ok")
                else:
                    card.force_error()  # er zijn nog open errors
            elif color == "red":
                card.force_error()
            elif color == "orange":
                # Warning: alleen uit offline halen, niet naar rood
                if card.status == "offline":
                    card.set_status("ok")
            elif color == "gray":
                # Informatieve melding, status niet aanpassen
                pass
        # Update webserver status op basis van de actuele kaartstatus (ook sticky).
        if ip in LogWebServer.device_statuses:
            card = self.processor_widgets.get(ip)
            if card is not None:
                if card.status == "error":
                    LogWebServer.device_statuses[ip] = "error"
                elif card.status == "ok":
                    LogWebServer.device_statuses[ip] = "ok"
            else:
                if color == "green":
                    LogWebServer.device_statuses[ip] = "ok"
                elif color == "red":
                    LogWebServer.device_statuses[ip] = "error"
        self.add_log_entry(color, msg, ip)

    @Slot(str, str, str, str)
    def on_alert_received(self, ip, color, msg, receiver_info):
        """Handle alert from MonitorWorker with proper color mapping."""
        self.add_log_entry(color, msg, ip, receiver_info)

    @Slot(str)
    def on_card_clicked(self, ip):
        self.selected_ip = None if self.selected_ip == ip else ip
        for p_ip, card in self.processor_widgets.items(): card.set_selected(p_ip == self.selected_ip)
        self.refresh_log_display()

    @Slot(str)
    def run_morning_test(self, target_ip=None):
        targets = []
        if target_ip:
            sock = self.sockets.get(target_ip)
            if isinstance(sock, BromptonSocket):
                targets = [target_ip]
            else:
                self.add_log_entry("orange", "Geselecteerde kaart is geen BROMPTON processor.", "SYSTEM")
                return
        elif self.selected_ip:
            sock = self.sockets.get(self.selected_ip)
            if isinstance(sock, BromptonSocket):
                targets = [self.selected_ip]
            else:
                self.add_log_entry("orange", "Selecteer een BROMPTON kaart of deselecteer om alle BROMPTON processors te testen.", "SYSTEM")
                return
        else:
            for ip, sock in self.sockets.items():
                if isinstance(sock, BromptonSocket):
                    targets.append(ip)

        if not targets:
            self.add_log_entry("orange", "Geen BROMPTON processor gevonden voor TEST.", "SYSTEM")
            return

        self.add_log_entry("gray", f"Test gestart voor {len(targets)} BROMPTON processor(s).", "SYSTEM")
        for ip in targets:
            sock = self.sockets.get(ip)
            if isinstance(sock, BromptonSocket):
                QMetaObject.invokeMethod(sock, "trigger_test", Qt.QueuedConnection)

    def add_log_entry(self, color, msg, ip, receiver_info=None, oid=""):
        color = normalize_log_color(color, ip)
        msg = self._strip_ip_from_controller_csv(msg)
        msg = self._normalize_recover_text(msg)
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "color": color,
            "msg": msg,
            "ip": ip,
            "receiver_info": receiver_info if receiver_info else {},
            "oid": oid
        }
        self.log_history.append(entry)
        if self.selected_ip is None or self.selected_ip == ip or ip == "SYSTEM": 
            self.refresh_log_display()

    def _entry_group_signature(self, entry):
        return (
            str(entry.get("ip", "") or ""),
            str(entry.get("color", "") or ""),
            str(entry.get("msg", "") or ""),
            str(entry.get("oid", "") or ""),
        )

    @Slot(int, int)
    def on_log_table_cell_clicked(self, row, _column):
        meta = self.log_row_meta.get(row)
        if not meta or meta.get("type") != "group_parent":
            return

        group_id = meta.get("group_id")
        if group_id is None:
            return

        expanded = bool(self.live_group_expanded.get(group_id, False))
        new_expanded = not expanded
        self.live_group_expanded[group_id] = new_expanded

        for child_row in self.log_group_children.get(group_id, []):
            self.log_table.setRowHidden(child_row, not new_expanded)

        count = int(meta.get("count", 0))
        time_item = self.log_table.item(row, 0)
        if time_item is not None:
            arrow = "▼" if new_expanded else "▶"
            time_item.setText(f"{arrow} {count}")

    def refresh_log_display(self):
        self.log_table.setUpdatesEnabled(False)
        self.log_table.setRowCount(0)
        self.helios_identify_checkboxes = {}
        self.log_row_meta = {}
        self.log_group_children = {}
        self.log_group_targets = {}
        self.group_identify_checkboxes = {}

        visible_entries = []
        for entry in self.log_history:
            if self.selected_ip is None or entry["ip"] == self.selected_ip or entry["ip"] == "SYSTEM":
                visible_entries.append(entry)

        groups = []
        for entry in visible_entries:
            sig = self._entry_group_signature(entry)
            if groups and groups[-1]["signature"] == sig:
                groups[-1]["entries"].append(entry)
            else:
                groups.append({"signature": sig, "entries": [entry]})

        for idx, group in enumerate(groups):
            entries = group["entries"]
            if len(entries) == 1:
                self.append_log_row(entries[0], auto_scroll=False)
                continue

            first = entries[0]
            group_id = (group["signature"], first.get("time", ""), idx)
            expanded = bool(self.live_group_expanded.get(group_id, False))

            parent_entry = dict(first)
            parent_entry["receiver_info"] = {}
            parent_row = self.append_log_row(parent_entry, auto_scroll=False, allow_identify=False)

            parent_time_item = self.log_table.item(parent_row, 0)
            if parent_time_item is not None:
                arrow = "▼" if expanded else "▶"
                parent_time_item.setText(f"{arrow} {len(entries)}")
                parent_time_item.setToolTip(f"Bulk log: {len(entries)} items")

            self.log_row_meta[parent_row] = {
                "type": "group_parent",
                "group_id": group_id,
                "count": len(entries),
            }

            group_targets = []
            for ge in entries:
                target = self._identify_target_from_entry(ge)
                if target and target not in group_targets:
                    group_targets.append(target)
            self.log_group_targets[group_id] = group_targets

            if group_targets:
                parent_id_box = QWidget()
                parent_id_layout = QHBoxLayout(parent_id_box)
                parent_id_layout.setContentsMargins(0, 0, 0, 0)
                parent_id_layout.setAlignment(Qt.AlignCenter)

                parent_id_cb = QCheckBox()
                parent_id_cb.setToolTip(f"Identify all in group ({len(group_targets)})")
                parent_id_cb.setStyleSheet(
                    "QCheckBox::indicator { width: 14px; height: 14px; }"
                    "QCheckBox::indicator:unchecked { border: 1px solid #666; background: #121212; }"
                    "QCheckBox::indicator:checked { border: 1px solid #2ecc71; background: #2ecc71; }"
                )
                parent_id_cb.stateChanged.connect(
                    lambda state, gid=group_id, cb=parent_id_cb:
                    self._on_group_identify_toggled(gid, int(state) != 0, source_checkbox=cb)
                )
                parent_id_layout.addWidget(parent_id_cb)
                self.log_table.setCellWidget(parent_row, 3, parent_id_box)
                self.group_identify_checkboxes[group_id] = parent_id_cb
                self._sync_group_identify_checkbox(group_id)

            child_rows = []
            for child_entry in entries:
                child_row = self.append_log_row(child_entry, auto_scroll=False)
                child_time_item = self.log_table.item(child_row, 0)
                if child_time_item is not None:
                    child_time_item.setText(f"  {child_time_item.text()}")
                self.log_row_meta[child_row] = {"type": "group_child", "group_id": group_id}
                child_rows.append(child_row)
                self.log_table.setRowHidden(child_row, not expanded)

            self.log_group_children[group_id] = child_rows

        self.log_table.setUpdatesEnabled(True)
        self.log_table.viewport().update()
        self.log_table.scrollToBottom()

    def append_log_row(self, entry, auto_scroll=True, allow_identify=True):
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        # Time
        time_item = QTableWidgetItem(entry["time"])
        time_item.setForeground(QColor("#888"))
        time_item.setTextAlignment(Qt.AlignCenter)
        self.log_table.setItem(row, 0, time_item)
        
        # Device (IP or SYSTEM)
        device_text = entry["ip"] if entry["ip"] else "SYSTEM"
        device_item = QTableWidgetItem(device_text)
        device_item.setForeground(QColor("#888"))
        device_item.setTextAlignment(Qt.AlignCenter)
        device_item.setToolTip(device_text)
        self.log_table.setItem(row, 1, device_item)
        
        # Receiver info (MAC, SFP, Output, Chain Position)
        receiver_info = entry.get("receiver_info", {})
        
        mac_text = receiver_info.get("mac", "-") if isinstance(receiver_info, dict) else "-"
        sfp_text = receiver_info.get("sfp", "-") if isinstance(receiver_info, dict) else "-"
        output_text = receiver_info.get("output", "-") if isinstance(receiver_info, dict) else "-"
        chain_text = receiver_info.get("chain_pos", "-") if isinstance(receiver_info, dict) else "-"
        
        # MAC
        mac_item = QTableWidgetItem(mac_text)
        mac_item.setForeground(QColor("#888") if mac_text != "-" else QColor("#444"))
        mac_item.setTextAlignment(Qt.AlignCenter)
        if mac_text and mac_text != "-":
            mac_item.setToolTip(mac_text)
        self.log_table.setItem(row, 2, mac_item)

        # Identify checkbox (Helios only, requires valid receiver MAC)
        ip_text = str(entry.get("ip", "") or "").strip()
        ptype = self._processor_type_for_ip(ip_text)
        mac_norm = self._normalize_receiver_mac(mac_text)
        if allow_identify and ip_text and mac_norm and "helios" in ptype:
            key = (ip_text, mac_norm)
            checked = bool(self.helios_identify_state.get(key, False))

            identify_box = QWidget()
            identify_layout = QHBoxLayout(identify_box)
            identify_layout.setContentsMargins(0, 0, 0, 0)
            identify_layout.setAlignment(Qt.AlignCenter)

            identify_cb = QCheckBox()
            identify_cb.setToolTip(f"Identify receiver {mac_norm}")
            identify_cb.setStyleSheet(
                "QCheckBox::indicator { width: 14px; height: 14px; }"
                "QCheckBox::indicator:unchecked { border: 1px solid #666; background: #121212; }"
                "QCheckBox::indicator:checked { border: 1px solid #2ecc71; background: #2ecc71; }"
            )
            identify_cb.blockSignals(True)
            identify_cb.setChecked(checked)
            identify_cb.blockSignals(False)
            identify_cb.stateChanged.connect(
                lambda state, ip_v=ip_text, mac_v=mac_norm, cb=identify_cb:
                self._on_identify_checkbox_toggled(ip_v, mac_v, int(state) != 0, source_checkbox=cb)
            )

            identify_layout.addWidget(identify_cb)
            self.log_table.setCellWidget(row, 3, identify_box)
            self.helios_identify_checkboxes.setdefault(key, []).append(identify_cb)
        else:
            id_item = QTableWidgetItem("-")
            id_item.setForeground(QColor("#444"))
            id_item.setTextAlignment(Qt.AlignCenter)
            self.log_table.setItem(row, 3, id_item)
        
        # SFP
        sfp_item = QTableWidgetItem(sfp_text)
        sfp_item.setForeground(QColor("#888") if sfp_text != "-" else QColor("#444"))
        sfp_item.setTextAlignment(Qt.AlignCenter)
        if sfp_text and sfp_text != "-":
            sfp_item.setToolTip(sfp_text)
        self.log_table.setItem(row, 4, sfp_item)
        
        # Output
        output_item = QTableWidgetItem(output_text)
        output_item.setForeground(QColor("#888") if output_text != "-" else QColor("#444"))
        output_item.setTextAlignment(Qt.AlignCenter)
        if output_text and output_text != "-":
            output_item.setToolTip(output_text)
        self.log_table.setItem(row, 5, output_item)
        
        # Chain Position
        chain_item = QTableWidgetItem(chain_text)
        chain_item.setForeground(QColor("#888") if chain_text != "-" else QColor("#444"))
        chain_item.setTextAlignment(Qt.AlignCenter)
        if chain_text and chain_text != "-":
            chain_item.setToolTip(chain_text)
        self.log_table.setItem(row, 6, chain_item)
        
        # Message
        if entry["color"] == "red":
            c = QColor("#ff5555")
        elif entry["color"] == "green":
            c = QColor("#2ecc71")
        elif entry["color"] == "orange":
            c = QColor("#ff9800")
        else:
            c = QColor("#bbbbbb")
        
        msg_item = QTableWidgetItem(entry["msg"])
        msg_item.setForeground(c)
        msg_item.setToolTip(str(entry["msg"]))
        self.log_table.setItem(row, 7, msg_item)

        # OID
        oid_text = entry.get("oid", "")
        oid_item = QTableWidgetItem(oid_text)
        oid_item.setForeground(QColor("#666666") if not oid_text else QColor("#aaaaaa"))
        if oid_text:
            oid_item.setToolTip(str(oid_text))
        self.log_table.setItem(row, 8, oid_item)
        
        if auto_scroll:
            self.log_table.scrollToBottom()

        return row

    def clear_log(self):
        """Slaat de huidige sessie op en start een schone lei."""
        if self.log_history:
            # 1. Maak de sessie aan
            session_name = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session = {
                "name": session_name, 
                "devices": "Multiple", 
                "count": len(self.log_history), 
                "logs": list(self.log_history) # Maak een kopie van de logs voor de geschiedenis
            }
            
            # 2. Opslaan in history.json
            self.history_data.insert(0, session)
            save_json(HISTORY_FILE, self.history_data)
            self.reload_history_tab()
            
            # 3. Maak de LIVE monitor leeg
            # Belangrijk: gebruik .clear() om de referentie voor de webserver levend te houden
            self.log_history.clear() 
            LogWebServer.last_clear_time = time.time()  # Notificeer webserver van clear
            self.log_table.setRowCount(0)
            
            # 4. Voeg de bevestiging toe aan de NIEUWE log
            self.add_log_entry("green", f"Previous session saved as {session_name}. New Baseline started.", "SYSTEM")
        else:
            # Als de log al leeg was, resetten we alleen visueel
            self.log_history.clear()
            LogWebServer.last_clear_time = time.time()  # Notificeer webserver van clear
            self.log_table.setRowCount(0)
            self.add_log_entry("gray", "Event log cleared. Ready.", "SYSTEM")
            
        # 5. Reset alle foutmeldingen op de processors
        for sock in self.sockets.values(): 
            sock.active_errors.clear()
            
        for card in self.processor_widgets.values(): 
            card.reset_error()

    def reload_history_tab(self):
        self.history_tree.clear()
        for session in self.history_data:
            item = QTreeWidgetItem([session["name"], session["devices"], str(session["count"])])
            item.setData(0, Qt.UserRole, session["logs"])
            self.history_tree.addTopLevelItem(item)

    def on_history_click(self, item, col):
        logs = item.data(0, Qt.UserRole)
        self.history_detail.clear()
        for entry in logs: self.history_detail.append(f"[{entry['time']}] {entry['ip']}: {entry['msg']}")

    def remove_selected_history(self):
        selected_items = self.history_tree.selectedItems()
        if not selected_items: return
        reply = QMessageBox.question(self, "Delete", f"Delete {len(selected_items)} sessions?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            for item in selected_items:
                name = item.text(0)
                self.history_data = [s for s in self.history_data if s['name'] != name]
                self.history_tree.takeTopLevelItem(self.history_tree.indexOfTopLevelItem(item))
            save_json(HISTORY_FILE, self.history_data)
            self.history_detail.clear()

    def open_settings(self):
        dlg = SettingsDialog(
            self,
            self.processors,
            self.config.get("web_auth", {}),
            self.config.get("web_server", {}),
        )
        if dlg.exec():
            old_processors = self.processors
            self.processors = dlg.get_processors(); self.config["processors"] = self.processors
            self.config["web_auth"] = dlg.get_web_auth()
            self.config["web_server"] = dlg.get_web_server_settings()
            save_config(self.config); self.http_worker.update_processors(self.processors)
            self._apply_web_auth()
            self.restart_web_server()
            self.http_worker.force_scan()  # Immediate scan!
            self.init_sockets(); self.rebuild_list()
            if old_processors != self.processors:
                self.add_log_entry("green", f"Processors updated. Scanning {len(self.processors)} devices...", "SYSTEM")

    def closeEvent(self, e):
        self.http_worker.stop()

        if self.web_server is not None:
            try:
                self.web_server.shutdown()
                self.web_server.server_close()
            except Exception:
                pass
        if self.web_thread is not None and self.web_thread.is_alive():
            try:
                self.web_thread.join(timeout=1.2)
            except Exception:
                pass

        for ip, sock in self.sockets.items():
            if not isinstance(sock, (NovastarCoexSocket, BromptonSocket)):
                sock.stop()
        for ip, t in self.coex_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        for ip, t in self.brompton_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, BromptonSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        super().closeEvent(e)

if __name__ == "__main__":
    set_windows_app_user_model_id()
    app = QApplication(sys.argv); app.setStyle("Fusion")
    app.setWindowIcon(QIcon(resource_path(LOGO_FILE)))
    window = LEDLoggerApp(); window.setWindowIcon(QIcon(resource_path(LOGO_FILE))); window.show(); sys.exit(app.exec())