# LED Logger - Operator Manual

This guide is only for operators using the Windows executable.

## 1. What you need

- LED_Logger.exe

Created automatically by the app:
- config.json
- history.json

Optional:
- config.example.json (only if you want a prefilled template)

Keep all files in the same folder as LED_Logger.exe.

## 2. Quick start

1. Start LED_Logger.exe.
2. Open CONFIGURE DEVICES (opens automatically on first launch).
3. Add your processors manually or use SCAN NETWORK.
4. Click SAVE and CLOSE.
5. Watch events in LIVE MONITOR.

That is enough to run daily operations.

## 3. Daily operation

LIVE MONITOR shows all events in real time.

Color meaning:
- Red: error
- Orange: warning
- Green: recovered/ok
- Gray: info

STATUS OVERVIEW (left side):
- Green: ok
- Red: active issue
- Gray: offline/unknown

HISTORY / BASELINES:
- CLEAR LOG / SAVE SESSION stores current logs in history.json.
- A new empty baseline starts immediately.

## 4. Remote monitor

The app starts a web page on port 8090.

Examples:
- http://localhost:8090
- http://your-pc-ip:8090

If login was not changed yet, default is:
- Username: admin
- Password: 1234

To change login:
1. Open CONFIGURE DEVICES.
2. Go to Web Interface Login.
3. Save new username/password.

## 5. If something does not work

No remote page:
- Check port 8090.
- Test http://localhost:8090 on the logger PC.
- Allow LED_Logger.exe in Windows Firewall.

No COEX data:
- Check network reachability (ping).
- Check SNMP community on the COEX device.
- Allow UDP 10162 inbound and UDP 161 outbound.

No events at all:
- Verify devices are saved in CONFIGURE DEVICES.
- Confirm correct IP addresses.

