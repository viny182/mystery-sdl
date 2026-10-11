#!/usr/bin/env python3
"""Dump the Mystery.dll scene tables to scene.json and build a self-contained viewer.html.

usage: python3 tools/dump_scene.py [Mystery.dll] [outdir]
Needs the built ./mystery (for the reference frame). Reads the DLL only; nothing is uploaded.
"""
import base64, json, os, struct, subprocess, sys, zlib

DLL = sys.argv[1] if len(sys.argv) > 1 else 'Mystery.dll'
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), 'out')
os.makedirs(OUT, exist_ok=True)
d = open(DLL, 'rb').read()

# ---------------------------------------------------------------- PE helpers
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]; osz = struct.unpack_from('<H', d, pe + 20)[0]
base_img = struct.unpack_from('<I', d, pe + 24 + 28)[0]
secs = []
o = pe + 24 + osz
for i in range(nsec):
    vs, va, rs, rp = struct.unpack_from('<IIII', d, o + 8); secs.append((va, vs, rp, rs)); o += 40
def r2o(r):
    for va, vs, rp, rs in secs:
        if va <= r < va + max(vs, rs): return r - va + rp
rbase = r2o(struct.unpack_from('<I', d, pe + 24 + 96 + 16)[0])
def rname(v):
    if v & 0x80000000:
        p = rbase + (v & 0x7fffffff); n = struct.unpack_from('<H', d, p)[0]; return d[p+2:p+2+2*n].decode('utf-16le')
    return v
def walk(off, path):
    nn, ni = struct.unpack_from('<HH', d, rbase + off + 12)
    for i in range(nn + ni):
        nm, o2 = struct.unpack_from('<II', d, rbase + off + 16 + 8 * i)
        p = path + [rname(nm)]
        if o2 & 0x80000000: yield from walk(o2 & 0x7fffffff, p)
        else:
            rva, sz = struct.unpack_from('<II', d, rbase + o2); yield p, r2o(rva), sz
RES = {(p[0], p[1]): d[o:o + s] for p, o, s in walk(0, [])}

# ---------------------------------------------------------------- PKWARE DCL (blast)
LITLEN = [11,124,8,7,28,7,188,13,76,4,10,8,12,10,12,10,8,23,8,9,7,6,7,8,7,6,55,8,23,24,12,11,7,9,11,12,6,7,22,5,7,24,6,11,9,6,7,22,7,11,38,7,9,8,25,11,8,11,9,12,8,12,5,38,5,38,5,11,7,5,6,21,6,10,53,8,7,24,10,27,44,253,253,253,252,252,252,13,12,45,12,45,12,61,12,45,44,173]
LENLEN = [2,35,36,53,38,23]; DISTLEN = [2,20,53,230,247,151,248]
LENBASE = [3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264]; EXTRA = [0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8]
def build(rep):
    sym = []; s = 0
    for r in rep:
        for _ in range((r >> 4) + 1): sym.append((s, r & 15)); s += 1
    cnt = [0] * 16
    for _, l in sym: cnt[l] += 1
    offs = [0] * 17
    for i in range(1, 16): offs[i + 1] = offs[i] + cnt[i]
    syms = [0] * len(sym)
    for s_, l in sym:
        if l: syms[offs[l]] = s_; offs[l] += 1
    return cnt, syms
HL, HN, HD = build(LITLEN), build(LENLEN), build(DISTLEN)
def blast(buf):
    st = {'i': 0, 'b': 0, 'n': 0}
    def bits(need):
        v = st['b']
        while st['n'] < need: v |= buf[st['i']] << st['n']; st['i'] += 1; st['n'] += 8
        st['b'] = v >> need; st['n'] -= need
        return v & ((1 << need) - 1)
    def dec(h):
        cnt, syms = h; code = first = index = 0
        for l in range(1, 16):
            code |= bits(1) ^ 1; c = cnt[l]
            if code - c < first: return syms[index + (code - first)]
            index += c; first += c; first <<= 1; code <<= 1
        raise ValueError
    lit = bits(8); dsz = bits(8); out = bytearray()
    while True:
        if bits(1):
            s = dec(HN); ln = LENBASE[s] + bits(EXTRA[s])
            if ln == 519: break
            sh = 2 if ln == 2 else dsz
            dist = (dec(HD) << sh) + bits(sh) + 1
            for _ in range(ln): out.append(out[-dist])
        else: out.append(dec(HL) if lit else bits(8))
    return bytes(out)

# ---------------------------------------------------------------- bitmaps -> PNG (colour key -> alpha)
def bmp_to_png(b, key_rgb, crop=None):
    pix = struct.unpack_from('<I', b, 10)[0]; w, h = struct.unpack_from('<ii', b, 18); hsz = struct.unpack_from('<I', b, 14)[0]
    pal = b[14 + hsz: 14 + hsz + 1024]; stride = (w + 3) & ~3
    rows = []
    for y in range(h):
        row = b[pix + (h - 1 - y) * stride: pix + (h - 1 - y) * stride + w]; r = bytearray()
        for idx in row:
            B, G, R = pal[4 * idx: 4 * idx + 3]
            r += bytes((R, G, B, 0 if (R, G, B) == key_rgb else 255))
        rows.append(bytes(r))
    raw = b''.join(b'\0' + r for r in rows)
    def chunk(t, dta): c = struct.pack('>I', len(dta)) + t + dta; return c + struct.pack('>I', zlib.crc32(t + dta) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''), w, h

bitmaps = {}  # id257 -> dict
def bitmap(id257):
    if id257 in bitmaps: return bitmaps[id257]
    r = RES[(257, id257)]
    bid = struct.unpack_from('<H', r, 2)[0] or struct.unpack_from('<H', r, 0)[0]
    ck = struct.unpack_from('<I', r, 4)[0]; key = (ck & 255, (ck >> 8) & 255, (ck >> 16) & 255)
    frames = struct.unpack_from('<H', r, 8)[0] or 1
    c = RES[(261, bid)]; bmp = blast(c[4:]); png, w, h = bmp_to_png(bmp, key)
    bitmaps[id257] = {'bitmap_id': bid, 'frames': frames, 'w': w, 'h': h, 'fw': w // frames, 'png': base64.b64encode(png).decode()}
    return bitmaps[id257]

def sprite_def(id256):
    r = RES[(256, id256)]; id257, np_ = struct.unpack_from('<HH', r, 0)
    paths = []
    for i in range(np_):
        pid = struct.unpack_from('<H', r, 4 + 2 * i)[0]; p = RES[(300, pid)]
        interval, n = struct.unpack_from('<HH', p, 0)
        steps = [dict(zip(('dx', 'dy', 'frame', 'sound'), struct.unpack_from('<hhHH', p, 4 + 8 * k))) for k in range(n)]
        paths.append({'id': pid, 'interval_ms': interval, 'steps': steps})
    b = bitmap(id257)
    return {'id': id256, 'bitmap257': id257, 'frames': b['frames'], 'fw': b['fw'], 'fh': b['h'], 'paths': paths}

# ---------------------------------------------------------------- .data tables
def va(a, n): return d[a - 0x79276000 + 0x5000: a - 0x79276000 + 0x5000 + n]
U32 = lambda a: struct.unpack('<I', va(a, 4))[0]
nstat, nact = U32(0x79276888), U32(0x79277d8c)
def anchor(x, y, m, W=640, H=480):
    if m in (2, 3, 7): x = W - x
    elif m in (5, 6, 8): x += W // 2
    if m in (3, 4, 8): y = H - y
    elif m in (5, 7, 9): y += H // 2
    return x, y
def rec(a, n): return va(a, n)
I = lambda r, o: struct.unpack_from('<i', r, o)[0]; S = lambda r, o: struct.unpack_from('<h', r, o)[0]
statics, actors = [], []
for i in range(nstat):
    r = rec(0x79276000 + 0x54 * i, 0x54)
    sd = sprite_def(S(r, 2)); x, y = anchor(I(r, 4), I(r, 8), I(r, 0xc))
    statics.append({'index': i, 'id': S(r, 0), 'sprite': S(r, 2), 'x': I(r, 4), 'y': I(r, 8), 'anchor': I(r, 0xc), 'flags': I(r, 0x10),
                    'tiled': I(r, 0x14) != 0, 'tile_flags': I(r, 0x1c), 'w': I(r, 0x20), 'h': I(r, 0x24), 'min_w': I(r, 0x4c), 'min_h': I(r, 0x50),
                    'screen_x_640x480': x, 'screen_y_640x480': y, 'frame_w': sd['fw'], 'frame_h': sd['fh']})
def action(i):
    r = rec(0x79277d90 + 0x40 * i, 0x40)
    rng = lambda o: [I(r, o), I(r, o + 4)]
    return {'index': i, 'path_index': I(r, 2), 'kind': I(r, 6), 'range_a': rng(0xa), 'range_b': rng(0x12), 'range_c': rng(0x1a), 'range_d': rng(0x22), 'range_e': rng(0x2a),
            'src_actor': S(r, 0x32), 'dst_actor': S(r, 0x34), 'mask': struct.unpack_from('<I', r, 0x36)[0], 'flags': struct.unpack_from('<I', r, 0x3a)[0], 'bits_3e': r[0x3e], 'bits_3f': r[0x3f]}
for i in range(nact):
    r = rec(0x79276890 + 0x9e * i, 0x9e)
    sd = sprite_def(S(r, 2)); x, y = anchor(I(r, 4), I(r, 8), I(r, 0xc))
    s0, s1 = struct.unpack('<ii', va(0x79279218 + 8 * I(r, 0x62), 8))
    actors.append({'index': i, 'id': S(r, 0), 'sprite': S(r, 2), 'x': I(r, 4), 'y': I(r, 8), 'anchor': I(r, 0xc), 'static_placement': I(r, 0x10) == 1,
                   'tiled': I(r, 0x14) != 0, 'w': I(r, 0x20), 'h': I(r, 0x24), 'min_w': I(r, 0x4c), 'min_h': I(r, 0x50), 'flags': struct.unpack_from('<H', r, 0x54)[0],
                   'start_x': I(r, 0x56), 'start_y': I(r, 0x5a), 'spawn_edge': I(r, 0x5e), 'sequence': I(r, 0x62), 'actions': [action(k) for k in range(s0, s1 + 1)] if s0 > 0 else [],
                   'screen_x_640x480': x, 'screen_y_640x480': y, 'frame_w': sd['fw'], 'frame_h': sd['fh']})
sprites = {}
for e in statics + actors: sprites.setdefault(e['sprite'], sprite_def(e['sprite']))
scene = {'note': 'field names are inferred from the plugin code, not from original symbols', 'statics': statics, 'actors': actors, 'sprites': list(sprites.values())}
json.dump(scene, open(os.path.join(OUT, 'scene.json'), 'w'), indent=1)

# ---------------------------------------------------------------- reference frame from the port
frame_png = None
exe = os.path.join(os.path.dirname(__file__), '..', 'mystery')
if os.path.exists(exe):
    env = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy')
    bmp = os.path.join(OUT, 'frame.bmp')
    subprocess.run([exe, '--dll', DLL, '--size', '640x480', '--scale', '1', '--mute', '--seed', '1', '--fast', '--dump', '100', bmp], env=env, check=True)
    subprocess.run(['magick', bmp, '-alpha', 'off', os.path.join(OUT, 'frame.png')], check=True)
    frame_png = base64.b64encode(open(os.path.join(OUT, 'frame.png'), 'rb').read()).decode()

imgs = {str(k): v['png'] for k, v in bitmaps.items()}
html = open(os.path.join(os.path.dirname(__file__), 'viewer_template.html')).read()
html = html.replace('__SCENE__', json.dumps(scene)).replace('__IMGS__', json.dumps(imgs)).replace('__FRAME__', frame_png or '')
open(os.path.join(OUT, 'viewer.html'), 'w').write(html)
print('wrote', OUT, '(scene.json, viewer.html)', len(statics), 'statics,', len(actors), 'actors,', len(sprites), 'sprite defs')
