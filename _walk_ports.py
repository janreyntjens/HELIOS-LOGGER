import asyncio
from pysnmp.hlapi.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)

COEX_IP = "192.168.0.46"
BASES = [
    "1.3.6.1.4.1.319.10.120",
    "1.3.6.1.4.1.319.10.130",
    "1.3.6.1.4.1.319.10.10",
]


async def walk(base_oid):
    results = []
    t = UdpTransportTarget((COEX_IP, 161), timeout=2, retries=0)
    current = base_oid
    for _ in range(60):
        eI, eS, eX, vbs = await nextCmd(
            SnmpEngine(),
            CommunityData("public", mpModel=1),
            t,
            ContextData(),
            ObjectType(ObjectIdentity(current)),
        )
        if eI or eS:
            break
        if not vbs:
            break
        vb = vbs[0]
        oid_obj = vb[0]
        val = vb[1]
        oid_str = oid_obj.prettyPrint()
        if not oid_str.startswith(base_oid):
            break
        results.append((oid_str, val.prettyPrint()))
        current = oid_str
    return results


async def main():
    for base in BASES:
        print(f"\n--- Walk {base} ---")
        res = await walk(base)
        if res:
            for o, v in res:
                print(f"  {o} = {v}")
        else:
            print("  (geen resultaten)")


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(main())
finally:
    loop.close()
