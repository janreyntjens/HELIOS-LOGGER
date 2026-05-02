import sys
import os
import time
import json
import socket
import traceback
import base64
import hashlib
import hmac
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

# --- VEILIGE IMPORT ---
# --- GEKORRIGEERDE IMPORT (Regel 16 t/m 25) ---
try:
    import requests
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

# --- CONSTANTEN ---
APP_NAME = "LED Logger"
VERSION = "1.1.0-beta"
LOGO_FILE = "logo.ico"  # <--- HIER ZAT DE FOUT (ontbrekend aanhalingsteken)
CONFIG_FILE = "config.json"
HISTORY_FILE = "history.json"
WEB_DEFAULT_USERNAME = "admin"
WEB_DEFAULT_PASSWORD = "1234"


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

    def do_GET(self):
        if not self._is_authorized():
            self._send_auth_required()
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Bereken statistieken
        total = len(self.device_statuses)
        online = sum(1 for s in self.device_statuses.values() if s in ["ok", "error"])
        status_color = "#2ecc71" if online == total and total > 0 else "#f1c40f" if online > 0 else "#e74c3c"
        
        # Snellere refresh direct na een clear
        refresh_interval = 2 if (time.time() - self.last_clear_time) < 10 else 5

        html = f"""
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
                .red {{ border-left-color: #e74c3c; color: #ff6b6b; font-weight: bold; }}
                .green {{ border-left-color: #2ecc71; color: #2ecc71; }}
                .system {{ border-left-color: #2a82da; color: #2a82da; font-style: italic; }}
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
        for entry in reversed(self.log_data[-100:]):
            color_class = "system" if entry.get("ip") == "SYSTEM" else entry.get("color", "gray")
            html += f'<div class="entry {color_class}"><span class="time">[{entry["time"]}]</span> {entry["msg"]}</div>'
            
        html += "</div></body></html>"
        self.wfile.write(html.encode("utf-8"))

def severity_to_color(severity):
    """Map Helios severity levels to log colors."""
    sev = str(severity).lower().strip() if severity else ""
    
    # Debug: log what we receive
    # print(f"DEBUG: severity='{severity}' -> '{sev}'")
    
    # 'none' means alert cleared/resolved
    if sev in ["", "none", "null"]: 
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

class HeliosSocket(QObject):
    error_detected = Signal(str, str, str)

    def __init__(self, ip, name, parent=None):
        super().__init__(parent)
        self.ip = ip.strip()
        self.name = name
        self.active_errors = set()
        
        self.ws = QWebSocket()
        self.url = f"ws://{self.ip}/api/v1/data/rpc/websocket"
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
                        severity = raw_data.get("severity", "error") if isinstance(raw_data, dict) else "error"
                        color = severity_to_color(severity)
                        self.error_detected.emit(color, f"{self.name}: {msg}", self.ip)
                        self.active_errors.add(err_id)
            
            if "sys" in params or "dev" in params:
                for old_err in list(self.active_errors):
                    if old_err not in current_message_errors:
                        self.active_errors.remove(old_err)
        except: pass

    def format_error(self, key, val):
        parts = [f"[{key}]"]
        if isinstance(val, dict):
            brief = str(val.get("brief", "")).strip()
            desc = str(val.get("desc", "")).strip()
            if brief: parts.append(brief)
            if desc and desc != brief: parts.append(f"| {desc}")
        else:
            parts.append(str(val))
        return " ".join(parts)

    def stop(self):
        self.retry_timer.stop()
        self.ws.close()

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
                if oid_str.startswith(CONTROLLER_INFO_PREFIX):
                    try:
                        suffix = oid_str[len(CONTROLLER_INFO_PREFIX):]
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
                if oid_str.startswith(INPUT_CARD_PREFIX):
                    try:
                        suffix = oid_str[len(INPUT_CARD_PREFIX):]
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
                if oid_str.startswith(PORT_LINK_PREFIX):
                    try:
                        suffix = oid_str[len(PORT_LINK_PREFIX):]
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
                if oid_str.startswith(SCREEN_INFO_PREFIX):
                    try:
                        suffix = oid_str[len(SCREEN_INFO_PREFIX):]
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

    def update_processors(self, new_list):
        self.processors = new_list
        self.force_scan_flag = True  # Trigger immediate scan

    def force_scan(self):
        """Request immediate scan on next loop iteration."""
        self.force_scan_flag = True

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
                if "coex" in ptype or "novastar" in ptype or "mx" in ptype:
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
                                self.alert_signal.emit(ip, color, f"{name}: {msg}", "")
        
        # Store this alert set for next iteration
        if alert_store_key not in self.last_alerts:
            self.last_alerts[alert_store_key] = set()
        self.last_alerts[alert_store_key] = current_alert_ids

    def _severity_number_to_color(self, severity):
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

            devices = alert_data.get("devices", {}) if isinstance(alert_data.get("devices", {}), dict) else {}
            receivers = devices.get("receivers", {}) if isinstance(devices.get("receivers", {}), dict) else {}

            if receivers:
                for receiver_mac, receiver_details in receivers.items():
                    # Parse receiver details (SFP, output, chain position, etc.)
                    receiver_info = {
                        "mac": str(receiver_mac),
                        "sfp": "",
                        "output": "",
                        "chain_pos": ""
                    }
                    
                    if isinstance(receiver_details, dict):
                        # Debug print om te zien welke velden beschikbaar zijn
                        print(f"[DEBUG] Receiver {receiver_mac} details: {receiver_details}")
                        
                        # Probeer verschillende veldnamen die Helios zou kunnen gebruiken
                        receiver_info["sfp"] = str(receiver_details.get("sfp", receiver_details.get("port", "")))
                        receiver_info["output"] = str(receiver_details.get("output", receiver_details.get("switch", "")))
                        receiver_info["chain_pos"] = str(receiver_details.get("chain", receiver_details.get("position", receiver_details.get("index", ""))))
                    
                    alert_id = f"{alert_key}:{receiver_mac}:{msg}"
                    current_alert_ids.add(alert_id)
                    if alert_store_key not in self.last_alerts or alert_id not in self.last_alerts[alert_store_key]:
                        self.alert_signal.emit(ip, color, f"{name}: [{alert_key}] {msg}", receiver_info)
            else:
                alert_id = f"{alert_key}:{msg}"
                current_alert_ids.add(alert_id)
                if alert_store_key not in self.last_alerts or alert_id not in self.last_alerts[alert_store_key]:
                    self.alert_signal.emit(ip, color, f"{name}: [{alert_key}] {msg}", {})

        self.last_alerts[alert_store_key] = current_alert_ids
    
    def stop(self):
        self.running = False
        self.wait()

class ScanWorker(QThread):
    progress_signal = Signal(int)
    found_signal = Signal(str, str, str)
    log_signal = Signal(str)
    finished_signal = Signal(int)

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
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(self.check_ip_http, ips_to_scan))
            for i, result in enumerate(results):
                self.progress_signal.emit(int((i/total)*50))  # tot 50%
                if result:
                    self.found_signal.emit(result[0], result[1], result[2])
                    found_ips.add(result[0])
                    found_count += 1

        # FASE 2: SNMP scan (parallel, licht) — voor IPs die niet via HTTP gevonden zijn
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
                            found_count += 1

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
        i = QLabel(str(ip)); i.setFont(QFont("Consolas", 9)); i.setStyleSheet("border:none; background:transparent; color:#888;"); self.inner_layout.addWidget(i)
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
        self.processors = list(current_processors)
        auth_data = current_web_auth if isinstance(current_web_auth, dict) else {}
        web_server_data = current_web_server if isinstance(current_web_server, dict) else {}
        self.current_web_username = str(auth_data.get("username", WEB_DEFAULT_USERNAME)).strip() or WEB_DEFAULT_USERNAME
        self.current_web_password_hash = str(auth_data.get("password_hash", hash_password(WEB_DEFAULT_PASSWORD)))
        self.current_bind_ip = str(web_server_data.get("bind_ip", "")).strip()
        self.edit_index = -1 
        
        self.setStyleSheet("QDialog { background-color: #121212; } QLabel { color: #eaeaea; font-family: 'Segoe UI'; } QLineEdit, QComboBox { background-color: #1e1e1e; border: 1px solid #333; border-radius: 5px; padding: 10px; color: #fff; } QListWidget { background-color: #1e1e1e; border: 1px solid #333; border-radius: 5px; color: #ddd; } QPushButton { background-color: #333; color: white; border-radius: 5px; padding: 10px; border: none; } QProgressBar { border: none; background-color: #111; height: 4px; } QProgressBar::chunk { background-color: #2a82da; }")
        
        main = QVBoxLayout(self)
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
        self.inp_type = QComboBox(); self.inp_type.addItems(["HELIOS", "COEX"])
        
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

        bind_hint = QLabel("Tip: kies hier je Wi-Fi adapter om in de venue via dat netwerk de logs te bekijken.")
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

    def refresh_list(self):
        self.list_widget.clear()
        for p in self.processors:
            shown_type = display_type_label(p.get('type'))
            self.list_widget.addItem(f"{p.get('name')} | {shown_type} | {p.get('ip')}")

    def _type_to_display(self, ptype):
        t = str(ptype or "")
        if t == "Novastar_COEX":
            return "COEX"
        if t.lower() == "helios":
            return "HELIOS"
        return t.upper()

    def _display_to_type(self, shown_type):
        t = str(shown_type or "").upper()
        if t == "COEX":
            return "Novastar_COEX"
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
        self.scan_lbl.setText("Scanning subnets...")
        self.scanner = ScanWorker()
        self.scanner.progress_signal.connect(self.progress.setValue)
        self.scanner.found_signal.connect(self.on_found)
        self.scanner.log_signal.connect(self.scan_lbl.setText)
        self.scanner.finished_signal.connect(self.on_scan_finished)
        self.scanner.start()

    def on_found(self, ip, ptype, detected_name):
        detected_name = (detected_name or "").strip()
        prefix_map = {"Helios": "Helios", "Novastar_COEX": "COEX"}
        prefix = prefix_map.get(ptype, "DEV")
        fallback_name = f"{prefix}-{ip.split('.')[-1]}"

        existing = next((p for p in self.processors if p.get('ip') == ip), None)
        if existing:
            current_name = str(existing.get('name', '')).strip()
            generic_prefixes = ("Helios-", "COEX-", "BR-", "CL-", "DEV-")
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
        self.processor_widgets = {}; self.sockets = {}; self.coex_threads = {}; self.selected_ip = None; self.log_history = []
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
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels(["Time", "Device", "MAC", "OPT", "PORT", "TILE", "Message", "OID"])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.log_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Interactive)
        self.log_table.setColumnWidth(7, 280)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setSelectionMode(QTableWidget.NoSelection)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
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
            if not isinstance(sock, NovastarCoexSocket):
                sock.stop()
        for ip, t in self.coex_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        self.coex_threads = {}
        self.sockets = {}
        for p in self.processors:
            ip = p.get("ip")
            ptype = p.get("type", "").lower()
            if "helios" in ptype:
                sock = HeliosSocket(ip, p.get("name"), parent=self)
                sock.error_detected.connect(self.on_socket_error)
                self.sockets[ip] = sock
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

    def add_log_entry(self, color, msg, ip, receiver_info=None, oid=""):
        msg = self._strip_ip_from_controller_csv(msg)
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
            self.append_log_row(entry)

    def refresh_log_display(self):
        self.log_table.setUpdatesEnabled(False)
        self.log_table.setRowCount(0)
        for entry in self.log_history:
            if self.selected_ip is None or entry["ip"] == self.selected_ip or entry["ip"] == "SYSTEM":
                self.append_log_row(entry, auto_scroll=False)
        self.log_table.setUpdatesEnabled(True)
        self.log_table.viewport().update()
        self.log_table.scrollToBottom()

    def append_log_row(self, entry, auto_scroll=True):
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
        self.log_table.setItem(row, 1, device_item)
        
        # Receiver info (MAC, SFP, Output, Chain Position)
        receiver_info = entry.get("receiver_info", {})
        
        mac_text = receiver_info.get("mac", "-") if isinstance(receiver_info, dict) else "-"
        sfp_text = receiver_info.get("sfp", "-") if isinstance(receiver_info, dict) else "-"
        output_text = receiver_info.get("output", "-") if isinstance(receiver_info, dict) else "-"
        chain_text = receiver_info.get("chain_pos", "-") if isinstance(receiver_info, dict) else "-"
        
        # MAC
        mac_item = QTableWidgetItem(mac_text)
        mac_item.setForeground(QColor("#ff9800") if mac_text != "-" else QColor("#444"))
        mac_item.setTextAlignment(Qt.AlignCenter)
        self.log_table.setItem(row, 2, mac_item)
        
        # SFP
        sfp_item = QTableWidgetItem(sfp_text)
        sfp_item.setForeground(QColor("#2a82da") if sfp_text != "-" else QColor("#444"))
        sfp_item.setTextAlignment(Qt.AlignCenter)
        self.log_table.setItem(row, 3, sfp_item)
        
        # Output
        output_item = QTableWidgetItem(output_text)
        output_item.setForeground(QColor("#2a82da") if output_text != "-" else QColor("#444"))
        output_item.setTextAlignment(Qt.AlignCenter)
        self.log_table.setItem(row, 4, output_item)
        
        # Chain Position
        chain_item = QTableWidgetItem(chain_text)
        chain_item.setForeground(QColor("#2a82da") if chain_text != "-" else QColor("#444"))
        chain_item.setTextAlignment(Qt.AlignCenter)
        self.log_table.setItem(row, 5, chain_item)
        
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
        self.log_table.setItem(row, 6, msg_item)

        # OID
        oid_text = entry.get("oid", "")
        oid_item = QTableWidgetItem(oid_text)
        oid_item.setForeground(QColor("#666666") if not oid_text else QColor("#aaaaaa"))
        self.log_table.setItem(row, 7, oid_item)
        
        if auto_scroll:
            self.log_table.scrollToBottom()

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
            if not isinstance(sock, NovastarCoexSocket):
                sock.stop()
        for ip, t in self.coex_threads.items():
            sock = self.sockets.get(ip)
            if isinstance(sock, NovastarCoexSocket):
                QMetaObject.invokeMethod(sock, "stop", Qt.QueuedConnection)
            t.quit()
            t.wait(1200)
        super().closeEvent(e)

if __name__ == "__main__":
    app = QApplication(sys.argv); app.setStyle("Fusion")
    app.setWindowIcon(QIcon(resource_path(LOGO_FILE)))
    window = LEDLoggerApp(); window.setWindowIcon(QIcon(resource_path(LOGO_FILE))); window.show(); sys.exit(app.exec())