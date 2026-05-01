import socket
import datetime
from pysnmp.proto import api
from pyasn1.codec.ber import decoder as ber_decoder

LISTEN_PORT = 10163
TIMEOUT_S = 120


def decode_snmp(data: bytes):
    try:
        msg_ver = int(api.decodeMessageVersion(data))
        p_mod = api.protoModules[msg_ver]
        req_msg, _ = ber_decoder.decode(data, asn1Spec=p_mod.Message())
        pdu = p_mod.apiMessage.getPDU(req_msg)

        out = []
        out.append(f"SNMP version={msg_ver} pdu={pdu.__class__.__name__}")

        if msg_ver == 0:
            out.append(f"enterprise={p_mod.apiTrapPDU.getEnterprise(pdu).prettyPrint()}")
            out.append(f"agent={p_mod.apiTrapPDU.getAgentAddr(pdu).prettyPrint()}")
            out.append(f"generic={int(p_mod.apiTrapPDU.getGenericTrap(pdu))} specific={int(p_mod.apiTrapPDU.getSpecificTrap(pdu))}")
            vbs = p_mod.apiTrapPDU.getVarBinds(pdu)
        else:
            vbs = p_mod.apiPDU.getVarBinds(pdu)

        for oid, val in vbs:
            out.append(f"  {oid.prettyPrint()} = {val.prettyPrint()}")
        return "\n".join(out)
    except Exception as e:
        return f"decode error: {e}"


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", LISTEN_PORT))
sock.settimeout(TIMEOUT_S)
print(f"[{datetime.datetime.now():%H:%M:%S}] Listening UDP {LISTEN_PORT} for {TIMEOUT_S}s...")
print("Trigger now: unplug/replug Ethercon or HDMI/Genlock change")

count = 0
start = datetime.datetime.now()

try:
    while True:
        data, addr = sock.recvfrom(65535)
        count += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] Packet #{count} from {addr[0]}:{addr[1]} ({len(data)} bytes)")
        print("hex:", data.hex())
        print(decode_snmp(data))
except socket.timeout:
    elapsed = (datetime.datetime.now() - start).total_seconds()
    print(f"\nTimeout after {elapsed:.0f}s, packets={count}")
finally:
    sock.close()
