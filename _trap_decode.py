data = bytes.fromhex('30470201000400a44006072b06010401823f4004c0a8002e0201000201004302012c30253010060b2b06010401823f0a7801040201003011060c2b06010401823f0a81020101020101')

def read_len(d, pos):
    l = d[pos]
    if l & 0x80:
        n = l & 0x7f
        val = 0
        for _ in range(n):
            pos += 1
            val = (val << 8) | d[pos]
        return val, pos+1
    return l, pos+1

def read_oid(d, pos, length):
    end = pos + length
    first = d[pos]
    result = [first // 40, first % 40]
    pos += 1
    while pos < end:
        val = 0
        while True:
            b = d[pos]; pos += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                break
        result.append(val)
    return '.'.join(map(str, result))

print('=== SNMP Trap Decode ===')
print('Version byte:', data[2], '(0=v1, 1=v2c)')
comm = data[4:4+data[3]].decode('latin-1')
print('Community:', repr(comm))

pos = 4 + data[3]
pdu_type = data[pos]; pos += 1
pdu_len, pos = read_len(data, pos)
print('PDU type: 0x{:02x}  (0xa4=SNMPv1 Trap, 0xa7=SNMPv2 Trap)'.format(pdu_type))

# Enterprise OID
oid_type = data[pos]; pos += 1
oid_len, pos = read_len(data, pos)
enterprise = read_oid(data, pos, oid_len)
pos += oid_len
print('Enterprise OID:', enterprise)

# Agent addr
pos += 1; addr_len, pos = read_len(data, pos)
agent_ip = '.'.join(str(data[pos+k]) for k in range(4))
pos += addr_len
print('Agent IP:', agent_ip)

# Generic trap
pos += 1; _, pos = read_len(data, pos)
generic = data[pos]; pos += 1
print('Generic trap:', generic, ' (0=coldStart,2=linkDown,3=linkUp,6=enterpriseSpecific)')

# Specific trap
pos += 1; _, pos = read_len(data, pos)
specific = data[pos]; pos += 1
print('Specific trap:', specific)

# Timestamp
pos += 1; ts_len, pos = read_len(data, pos); pos += ts_len

# Varbinds
print('=== Varbinds ===')
pos += 1; vbl_len, pos = read_len(data, pos)
vb_idx = 0
while pos < len(data):
    pos += 1; vb_len, pos = read_len(data, pos)
    vb_end = pos + vb_len
    pos += 1; ol, pos = read_len(data, pos)
    oid = read_oid(data, pos, ol); pos += ol
    vtype = data[pos]; pos += 1
    vlen, pos = read_len(data, pos)
    if vtype == 0x02:
        val = int.from_bytes(data[pos:pos+vlen], 'big', signed=True)
        print('  [{}] OID: {}'.format(vb_idx, oid))
        print('       VALUE: INTEGER =', val)
    else:
        print('  [{}] OID: {}, type=0x{:02x}, raw={}'.format(vb_idx, oid, vtype, data[pos:pos+vlen].hex()))
    pos = vb_end
    vb_idx += 1
    if pos >= len(data):
        break
