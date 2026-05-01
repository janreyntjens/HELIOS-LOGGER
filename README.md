# LED Logger - User Manual (for .exe)

This manual is intended for operators and technicians using LED Logger as a Windows app (.exe).

LED Logger monitors LED processors and shows live events in one overview:
- Helios via WebSocket/API
- Novastar COEX via SNMP polling plus SNMP traps
- Remote web monitor for viewing from other devices on the same network

## 1. What to include in the package

Minimum files to ship:
- LED_Logger.exe
- config.json (or config.example.json as a starter template)

Created automatically during use:
- history.json (saved sessions/baselines)

Tip:
- Keep the .exe and json files in the same folder.

## 2. System requirements

- Windows 10/11
- Network access to your processors
- Firewall access for:
  - TCP 8090 (remote monitor webpage)
  - UDP 10162 (SNMP traps for COEX)
  - UDP 161 outbound (SNMP polling to COEX)

## 3. First start

1. Start LED_Logger.exe.
2. If no devices are configured in config.json yet, Device Management opens automatically.
3. Add devices manually or use SCAN NETWORK.
4. Click SAVE and CLOSE.
5. Live events will appear in LIVE MONITOR.

## 4. Device types

Supported config types:
- Helios
- Novastar_COEX

In the UI these usually appear as:
- HELIOS
- COEX

## 5. Configuration file (config.json)

### 5.1 Basic example

```json
{
    "processors": [
        {
            "name": "Main Helios",
            "ip": "192.168.1.10",
            "type": "Helios"
        },
        {
            "name": "MX2000 Main",
            "ip": "192.168.1.20",
            "type": "Novastar_COEX",
            "snmp_community": "public"
        }
    ],
    "web_auth": {
        "username": "admin",
        "password_hash": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    }
}
```

### 5.2 Important fields

Per processor:
- name: display name in UI and logs
- ip: processor IP address
- type: Helios or Novastar_COEX

COEX options:
- snmp_community: usually public
- coex_backup_api_enabled: true/false
- coex_backup_api_port: default 8001
- coex_backup_api_poll_interval: interval in seconds
- coex_backup_api_log_every_poll: true/false

Web monitor login:
- web_auth.username
- web_auth.password_hash (SHA-256 hash, not plain text)

Notes:
- If web_auth is missing, defaults are created automatically.
- Default login is admin / 1234 until changed.

## 6. Using the app

### 6.1 LIVE MONITOR

Shows live events with columns:
- Time
- Device
- MAC
- OPT
- PORT
- TILE
- Message
- OID

Color meaning:
- Red: error/fault
- Orange: warning
- Green: recover/ok
- Gray: info/system

### 6.2 STATUS OVERVIEW (left panel)

- Green: ok
- Red: active error
- Gray: offline or unknown

Click a device card to filter logs for that device.

### 6.3 HISTORY / BASELINES

- CLEAR LOG / SAVE SESSION stores the current session in history.json.
- Then a new empty baseline starts immediately.
- In HISTORY you can review and remove sessions.

## 7. Remote monitor webpage

At startup, the app starts a webserver on port 8090.

You will see the URL in the app, for example:
- http://192.168.0.50:8090

Features:
- Basic Auth protection
- Auto refresh
- Latest events and global online status

Change login:
- Open CONFIGURE DEVICES
- Go to Web Interface Login
- Enter username and new password
- SAVE and CLOSE

## 8. COEX SNMP traps and auto configuration

For COEX, the app uses:
- SNMP polling (health checks)
- Trap listener on UDP 10162

On first online detection, the app tries to auto-configure on the COEX device:
- Trap target = your PC IP / 10162
- Trap reporting period
- Trap on/off setting

If this fails (firmware limitations or SNMP write permissions), the app logs an info message with manual VMP settings.

## 9. Network and firewall checklist

If no data appears, check:
1. PC and processors are in the same network/VLAN (or proper routing exists).
2. IP addresses in config.json are correct.
3. Windows Firewall allows LED_Logger.exe.
4. Required ports are open:
   - TCP 8090
   - UDP 10162
   - UDP 161 outbound
5. COEX SNMP community matches your config.

## 10. Common issues and fixes

Issue: Remote monitor does not open
- Check if port 8090 is available.
- Test locally with http://localhost:8090.
- Verify firewall rules.

Issue: COEX stays offline
- Ping the controller.
- Check SNMP community.
- Verify SNMP is enabled on the device.

Issue: No traps visible
- Check UDP 10162 inbound on the logger PC.
- Check trap target settings in VMP.
- Let the app detect the device online once so auto-config can run.

Issue: Remote monitor login unknown
- Set new credentials via CONFIGURE DEVICES > Web Interface Login.

## 11. Shipping the manual with the exe

Practical options for distribution:
- Keep this file as README.md in the same folder as LED_Logger.exe.
- Add the HTML version (MANUAL.html) for easy viewing in any browser.
- Optionally export to PDF for operators without markdown tools.

## 12. For developers (optional)

Only needed when running from source:

```powershell
pip install -r requirements.txt
python LED_Logger.py
```

Build the exe:

```powershell
pyinstaller LED_Logger.spec
```

