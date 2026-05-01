import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    Integer,
    getCmd,
    setCmd,
)

IP = "192.168.0.46"
OID = "1.3.6.1.4.1.319.10.200.2"
NEW_VAL = 0


async def main():
    t = UdpTransportTarget((IP, 161), timeout=2, retries=0)

    eI, eS, eX, v = await getCmd(
        SnmpEngine(), CommunityData("public", mpModel=1), t, ContextData(),
        ObjectType(ObjectIdentity(OID))
    )
    if not eI and not eS:
        print("READ current:", v[0][1].prettyPrint())

    eI, eS, eX, _ = await setCmd(
        SnmpEngine(), CommunityData("public", mpModel=1), t, ContextData(),
        ObjectType(ObjectIdentity(OID), Integer(NEW_VAL))
    )
    if eI:
        print("SET errInd:", eI)
    elif eS:
        print("SET errStat:", eS.prettyPrint())
    else:
        print("SET OK:", NEW_VAL)

    eI, eS, eX, v = await getCmd(
        SnmpEngine(), CommunityData("public", mpModel=1), t, ContextData(),
        ObjectType(ObjectIdentity(OID))
    )
    if eI:
        print("READBACK errInd:", eI)
    elif eS:
        print("READBACK errStat:", eS.prettyPrint())
    else:
        print("READBACK:", v[0][1].prettyPrint())


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(main())
finally:
    loop.close()
