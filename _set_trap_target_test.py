import asyncio
import sys
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    OctetString,
    setCmd,
    getCmd,
)

COEX_IP = "192.168.0.46"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.230/10163"
OID = "1.3.6.1.4.1.319.10.200.1"


async def main():
    t = UdpTransportTarget((COEX_IP, 161), timeout=2, retries=0)

    eI, eS, eX, _ = await setCmd(
        SnmpEngine(),
        CommunityData("public", mpModel=1),
        t,
        ContextData(),
        ObjectType(ObjectIdentity(OID), OctetString(TARGET)),
    )
    print("SET errInd=", eI, " errStat=", eS.prettyPrint() if eS else None)

    eI, eS, eX, vbs = await getCmd(
        SnmpEngine(),
        CommunityData("public", mpModel=1),
        t,
        ContextData(),
        ObjectType(ObjectIdentity(OID)),
    )
    if eI:
        print("GET errInd=", eI)
    elif eS:
        print("GET errStat=", eS.prettyPrint())
    else:
        print("READBACK:", vbs[0][1].prettyPrint())


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(main())
finally:
    loop.close()
