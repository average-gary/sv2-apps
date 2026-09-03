#!/usr/bin/env python3
"""Count every testnet4 coinbase output paid to wpkh(tpub.../0/*).

Pure stdlib: BIP32 unhardened derivation + bech32 + the mempool.space testnet4 API.
No dependencies, no node required.

    python3 scan-coinbases.py          # writes coinbases.json

Reproduces the block tally shown on https://average-gary.github.io/sv2-apps/
"""
import hashlib, hmac, json, sys, time, urllib.request

# --- secp256k1 ---
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def mul(pt, k):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def decompress(b):
    x = int.from_bytes(b[1:], 'big')
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if y % 2 != b[0] % 2: y = P - y
    return (x, y)

def compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')

# --- base58check ---
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58decode(s):
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    raw = n.to_bytes(82, 'big')[-82:]
    body, chk = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == chk, 'bad checksum'
    return body

# --- bech32 (BIP173) ---
CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def bech32_polymod(v):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for x in v:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ x
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk

def bech32_encode(hrp, data):
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return hrp + '1' + ''.join(CS[d] for d in data + [(polymod >> 5 * (5 - i)) & 31 for i in range(6)])

def convertbits(data, frm, to):
    acc = bits = 0; ret = []
    for b in data:
        acc = (acc << frm) | b; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & ((1 << to) - 1))
    if bits: ret.append((acc << (to - bits)) & ((1 << to) - 1))
    return ret

def p2wpkh(pub, hrp='tb'):
    h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    return bech32_encode(hrp, [0] + convertbits(h, 8, 5))

# --- BIP32 unhardened child derivation ---
def ckdpub(pub, cc, i):
    I = hmac.new(cc, pub + i.to_bytes(4, 'big'), hashlib.sha512).digest()
    k = int.from_bytes(I[:32], 'big')
    assert k < N
    return compress(add(mul(G, k), decompress(pub))), I[32:]

def parse_xpub(x):
    d = b58decode(x)
    return d[45:78], d[13:45]  # pubkey, chaincode

TPUB = ('tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77'
        'KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw')
BASE = 'https://mempool.space/testnet4/api'
GAP = 30  # stop after this many consecutive unused indices

def selfcheck():
    """Offline: derivation must reproduce the two published testnet4 addresses."""
    pub, cc = parse_xpub(TPUB)
    p0, c0 = ckdpub(pub, cc, 0)
    got = {i: p2wpkh(ckdpub(p0, c0, i)[0]) for i in (4, 5)}
    assert got[4] == 'tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x', got
    assert got[5] == 'tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp', got
    print('selfcheck ok:', got)

def get(path, retries=6):
    for a in range(retries):
        try:
            with urllib.request.urlopen(BASE + path, timeout=45) as r:
                return json.loads(r.read())
        except Exception as e:
            print('  retry %d %s: %s' % (a, path, e), flush=True)
            time.sleep(3 * (a + 1))
    raise SystemExit('failed: ' + path)

selfcheck()
if '--selfcheck' in sys.argv:
    raise SystemExit(0)

pub, cc = parse_xpub(TPUB)
pub0, cc0 = ckdpub(pub, cc, 0)
out = []
i = 0; miss = 0
while miss < GAP:
    cpub, _ = ckdpub(pub0, cc0, i)
    addr = p2wpkh(cpub)
    st = get('/address/' + addr)
    tot = st['chain_stats']['tx_count'] + st['mempool_stats']['tx_count']
    if tot == 0:
        miss += 1; i += 1
        print('idx %-4d %s  -' % (i - 1, addr), flush=True)
        continue
    miss = 0
    seen = set(); last = None; cbs = 0
    while True:
        page = get('/address/%s/txs/chain%s' % (addr, '/' + last if last else ''))
        if not page: break
        for tx in page:
            if tx['txid'] in seen: continue
            seen.add(tx['txid'])
            if not (tx['vin'] and tx['vin'][0].get('is_coinbase')): continue
            paid = sum(o['value'] for o in tx['vout'] if o.get('scriptpubkey_address') == addr)
            if not paid: continue
            cbs += 1
            out.append({'index': i, 'address': addr, 'txid': tx['txid'],
                        'height': tx['status'].get('block_height'),
                        'block_hash': tx['status'].get('block_hash'),
                        'time': tx['status'].get('block_time')})
        last = page[-1]['txid']
        time.sleep(0.1)
        if len(page) < 25: break
    print('idx %-4d %s  txs=%d coinbases=%d' % (i, addr, len(seen), cbs), flush=True)
    i += 1
    time.sleep(0.1)

out.sort(key=lambda r: (r['height'] or 0))
json.dump(out, open('coinbases.json', 'w'), indent=2)
hs = [r['height'] for r in out]
print('\nTOTAL COINBASES: %d   unique heights: %d   range %s..%s   indices used: %d' %
      (len(out), len(set(hs)), min(hs), max(hs), len(set(r['index'] for r in out))))
