import socket, datetime

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 162))
print(f'[{datetime.datetime.now():%H:%M:%S}] Luistert op UDP 162... trek nu een kabel uit')
sock.settimeout(120)
try:
    while True:
        data, addr = sock.recvfrom(65535)
        t = datetime.datetime.now().strftime('%H:%M:%S')
        print(f'[{t}] TRAP van {addr[0]} - {len(data)} bytes')
        print(f'  hex: {data.hex()}')
        try:
            print(f'  txt: {data.decode("latin-1", errors="replace")}')
        except Exception:
            pass
        print()
except socket.timeout:
    print('Timeout - geen traps in 120s')
finally:
    sock.close()
    input('Druk Enter om te sluiten...')
