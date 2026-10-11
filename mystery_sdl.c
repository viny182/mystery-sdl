/*
 * Mystery screensaver (Microsoft Plus! / Socha "Wildlife" engine) - SDL2 port.
 *
 * This is a transliteration of the plugin logic found in Mystery.dll
 * (Initialize/DoDraw and helpers) plus a small re-implementation of the host
 * services provided by WL32DLL.DLL (sprite objects, paths, sound).
 *
 * Nothing from the original is embedded: the program reads the user's own
 * Mystery.dll at run time (resources + .data tables).
 *
 * Function names fXXXX refer to the plugin function at 0x7927XXXX.
 */
#include <SDL2/SDL.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ utils */
#define I32(p, o) (*(int32_t *)((uint8_t *)(p) + (o)))
#define U32(p, o) (*(uint32_t *)((uint8_t *)(p) + (o)))
#define I16(p, o) (*(int16_t *)((uint8_t *)(p) + (o)))
#define U16(p, o) (*(uint16_t *)((uint8_t *)(p) + (o)))
#define U8(p, o)  (*(uint8_t *)((uint8_t *)(p) + (o)))
typedef uint8_t *P;

static void die(const char *m) { fprintf(stderr, "mystery: %s\n", m); exit(1); }

static uint32_t g_fake_clock; static int g_fast;
static uint32_t now_ms(void) { return g_fast ? g_fake_clock : SDL_GetTicks(); }

/* MSVCRT rand() */
static uint32_t g_seed = 1;
static void c_srand(uint32_t s) { g_seed = s; }
static int c_rand(void) { g_seed = g_seed * 214013u + 2531011u; return (g_seed >> 16) & 0x7fff; }
/* f710e0 */
static int rand_range(int a, int b) { return (int)((uint32_t)(b - a) * (uint32_t)c_rand()) / 0x7fff + a; }

/* ------------------------------------------------------- PE + resources */
static uint8_t *g_file; static size_t g_filesz;
typedef struct { uint32_t va, vs, rp, rs; } Sec;
static Sec g_sec[16]; static int g_nsec; static uint32_t g_imgbase;

static uint32_t rva2off(uint32_t rva) {
    for (int i = 0; i < g_nsec; i++)
        if (rva >= g_sec[i].va && rva < g_sec[i].va + (g_sec[i].vs > g_sec[i].rs ? g_sec[i].vs : g_sec[i].rs))
            return rva - g_sec[i].va + g_sec[i].rp;
    die("bad rva");
    return 0;
}

static void load_pe(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "mystery: cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END); g_filesz = ftell(f); fseek(f, 0, SEEK_SET);
    g_file = malloc(g_filesz);
    if (fread(g_file, 1, g_filesz, f) != g_filesz) die("read");
    fclose(f);
    uint32_t pe = U32(g_file, 0x3c);
    if (memcmp(g_file + pe, "PE\0\0", 4)) die("not a PE");
    int ns = U16(g_file, pe + 6), osz = U16(g_file, pe + 20);
    g_imgbase = U32(g_file, pe + 24 + 28);
    uint32_t o = pe + 24 + osz;
    for (int i = 0; i < ns; i++, o += 40) {
        g_sec[i].vs = U32(g_file, o + 8); g_sec[i].va = U32(g_file, o + 12);
        g_sec[i].rs = U32(g_file, o + 16); g_sec[i].rp = U32(g_file, o + 20);
    }
    g_nsec = ns;
}

/* find resource by (type id | type name) + name id */
static const uint8_t *find_res(int type_id, const char *type_name, int name_id, uint32_t *size) {
    uint32_t pe = U32(g_file, 0x3c);
    uint32_t rrva = U32(g_file, pe + 24 + 96 + 16);
    uint32_t base = rva2off(rrva);
    uint32_t dir = 0; int found = 0;
    uint32_t nn = U16(g_file, base + 12), ni = U16(g_file, base + 14);
    for (uint32_t i = 0; i < nn + ni && !found; i++) {
        uint32_t nm = U32(g_file, base + 16 + 8 * i), off = U32(g_file, base + 20 + 8 * i);
        int match = 0;
        if (nm & 0x80000000) {
            if (type_name) {
                uint32_t p = base + (nm & 0x7fffffff); uint32_t len = U16(g_file, p);
                char buf[32] = {0};
                for (uint32_t k = 0; k < len && k < 31; k++) buf[k] = g_file[p + 2 + 2 * k];
                match = !strcmp(buf, type_name);
            }
        } else match = !type_name && (int)nm == type_id;
        if (match) { dir = off & 0x7fffffff; found = 1; }
    }
    if (!found) return NULL;
    uint32_t d1 = base + dir; found = 0; uint32_t d2 = 0;
    nn = U16(g_file, d1 + 12); ni = U16(g_file, d1 + 14);
    for (uint32_t i = 0; i < nn + ni; i++) {
        uint32_t nm = U32(g_file, d1 + 16 + 8 * i), off = U32(g_file, d1 + 20 + 8 * i);
        if (!(nm & 0x80000000) && (int)nm == name_id) { d2 = off & 0x7fffffff; found = 1; break; }
    }
    if (!found) return NULL;
    uint32_t d3 = base + d2; /* language level: take first */
    uint32_t off = U32(g_file, d3 + 20) & 0x7fffffff;
    uint32_t de = base + off;
    uint32_t rva = U32(g_file, de), sz = U32(g_file, de + 4);
    if (size) *size = sz;
    return g_file + rva2off(rva);
}

/* ---------------------------------------------- PKWARE DCL ("blast") */
static const uint8_t LITLEN[] = {11,124,8,7,28,7,188,13,76,4,10,8,12,10,12,10,8,23,8,9,7,6,7,8,7,6,55,8,23,24,12,11,7,9,11,12,6,7,22,5,7,24,6,11,9,6,7,22,7,11,38,7,9,8,25,11,8,11,9,12,8,12,5,38,5,38,5,11,7,5,6,21,6,10,53,8,7,24,10,27,44,253,253,253,252,252,252,13,12,45,12,45,12,61,12,45,44,173};
static const uint8_t LENLEN[] = {2,35,36,53,38,23};
static const uint8_t DISTLEN[] = {2,20,53,230,247,151,248};
static const short LENBASE[] = {3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264};
static const short EXTRA[] = {0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8};
typedef struct { short count[16]; short symbol[256]; } Huff;
static Huff h_lit, h_len, h_dist;
static void huff_build(Huff *h, const uint8_t *rep, int n) {
    short length[256]; int symbol = 0;
    for (int i = 0; i < n; i++) {
        int len = rep[i]; int left = (len >> 4) + 1; len &= 15;
        do length[symbol++] = len; while (--left);
    }
    memset(h->count, 0, sizeof h->count);
    for (int s = 0; s < symbol; s++) h->count[length[s]]++;
    short offs[16]; offs[1] = 0;
    for (int l = 1; l < 15; l++) offs[l + 1] = offs[l] + h->count[l];
    for (int s = 0; s < symbol; s++) if (length[s]) h->symbol[offs[length[s]]++] = s;
}
typedef struct { const uint8_t *in; size_t n, i; int bitbuf, bitcnt; } BS;
static int bits(BS *s, int need) {
    int val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->i >= s->n) die("blast: out of input");
        val |= (int)s->in[s->i++] << s->bitcnt; s->bitcnt += 8;
    }
    s->bitbuf = val >> need; s->bitcnt -= need;
    return val & ((1 << need) - 1);
}
static int decode(BS *s, Huff *h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        code |= bits(s, 1) ^ 1;
        int count = h->count[len];
        if (code < first + count) return h->symbol[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
    }
    die("blast: bad code"); return 0;
}
/* input: [u32 usize][dcl stream] */
static uint8_t *blast_res(const uint8_t *in, uint32_t insz, uint32_t *outsz) {
    static int inited;
    if (!inited) { huff_build(&h_lit, LITLEN, sizeof LITLEN); huff_build(&h_len, LENLEN, sizeof LENLEN); huff_build(&h_dist, DISTLEN, sizeof DISTLEN); inited = 1; }
    uint32_t usz = U32(in, 0);
    uint8_t *out = malloc(usz + 8); uint32_t o = 0;
    BS s = { in + 4, insz - 4, 0, 0, 0 };
    int lit = bits(&s, 8), dict = bits(&s, 8);
    if (lit > 1 || dict < 4 || dict > 6) die("blast: bad header");
    for (;;) {
        if (bits(&s, 1)) {
            int sym = decode(&s, &h_len);
            int len = LENBASE[sym] + bits(&s, EXTRA[sym]);
            if (len == 519) break;
            int sh = len == 2 ? 2 : dict;
            int dist = decode(&s, &h_dist) << sh; dist += bits(&s, sh); dist++;
            if ((uint32_t)dist > o || o + len > usz) die("blast: bad distance");
            while (len--) { out[o] = out[o - dist]; o++; }
        } else {
            if (o >= usz) die("blast: overflow");
            out[o++] = lit ? decode(&s, &h_lit) : bits(&s, 8);
        }
    }
    if (o != usz) die("blast: size mismatch");
    *outsz = usz; return out;
}

/* ------------------------------------------------------------- bitmaps */
typedef struct { int w, h; uint32_t *px; /* ARGB, a=0 -> transparent */ } Bitmap;
static Bitmap *load_bmp(const uint8_t *b, size_t n, uint32_t colorkey_rgb) {
    (void)n;
    if (b[0] != 'B' || b[1] != 'M') die("not a BMP");
    uint32_t pix = U32(b, 10), hsz = U32(b, 14);
    int w = I32(b, 18), h = I32(b, 22); int bpp = U16(b, 28);
    uint32_t ncol = U32(b, 46); if (!ncol && bpp <= 8) ncol = 1u << bpp;
    if (bpp != 8) die("only 8-bit bitmaps supported");
    int top_down = h < 0; if (h < 0) h = -h;
    const uint8_t *pal = b + 14 + hsz;
    Bitmap *bm = malloc(sizeof *bm); bm->w = w; bm->h = h; bm->px = malloc((size_t)w * h * 4);
    int stride = (w + 3) & ~3;
    for (int y = 0; y < h; y++) {
        const uint8_t *row = b + pix + (size_t)(top_down ? y : h - 1 - y) * stride;
        for (int x = 0; x < w; x++) {
            const uint8_t *c = pal + 4 * row[x]; /* B G R x */
            uint32_t rgb = (c[2] << 16) | (c[1] << 8) | c[0];
            bm->px[(size_t)y * w + x] = rgb == colorkey_rgb ? 0 : (0xff000000u | rgb);
        }
    }
    (void)ncol; return bm;
}

/* 257: bitmap descriptor {u16 0, u16 bmpId, u32 colorkey(COLORREF), u16 frames, u16 nmirror, ...} */
typedef struct { Bitmap *bm; int frames; } BmpRes;
static BmpRes get_bitmap(int id257) {
    uint32_t sz; const uint8_t *d = find_res(257, NULL, id257, &sz);
    if (!d) die("missing 257 resource");
    int bmpid = U16(d, 2) ? U16(d, 2) : U16(d, 0);
    uint32_t ck = U32(d, 4); /* COLORREF 0x00BBGGRR */
    uint32_t rgb = ((ck & 0xff) << 16) | (ck & 0xff00) | ((ck >> 16) & 0xff);
    int frames = U16(d, 8); if (!frames) frames = 1;
    const uint8_t *c = find_res(261, NULL, bmpid, &sz);
    if (!c) die("missing 261 resource");
    uint32_t usz; uint8_t *raw = blast_res(c, sz, &usz);
    BmpRes r = { load_bmp(raw, usz, rgb), frames };
    free(raw); return r;
}

/* ------------------------------------------------------------- sprites */
typedef struct { int16_t dx, dy; uint16_t frame, sound; } Step;
typedef struct { uint16_t interval, n; Step *steps; uint32_t next; } Path;
typedef struct {
    int visible, alive, is_static;
    Bitmap *bm; int nframes, fw, fh;
    int frame, x, y;
    int npaths; Path paths[25];
    uint16_t curPath, curStep, lastFrame;
} Sprite;

#define MAXSPR 512
static Sprite *g_spr[MAXSPR]; static int g_nspr;           /* list A, z-order = index */
static int W, H, g_abort, g_wide;
static uint32_t *g_bg;                                      /* stamped background */

static void audio_play(int id);

static Sprite *spr_create(int id256) {
    uint32_t sz; const uint8_t *d = find_res(256, NULL, id256, &sz);
    if (!d) { g_abort = 1; return NULL; }
    Sprite *s = calloc(1, sizeof *s);
    BmpRes br = get_bitmap(U16(d, 0));
    s->bm = br.bm; s->nframes = br.frames; s->fw = br.bm->w / br.frames; s->fh = br.bm->h;
    s->visible = 1; s->alive = 1;
    s->x = -(s->fw + 1); s->y = -(s->fh + 1);
    s->curPath = s->curStep = s->lastFrame = 0xffff;
    int np = U16(d, 2); if (np > 25) np = 25; s->npaths = np;
    for (int i = 0; i < np; i++) {
        uint32_t psz; const uint8_t *p = find_res(300, NULL, U16(d, 4 + 2 * i), &psz);
        if (!p) { g_abort = 1; free(s); return NULL; }
        s->paths[i].interval = U16(p, 0); s->paths[i].n = U16(p, 2);
        s->paths[i].steps = (Step *)(p + 4); s->paths[i].next = 0;
    }
    if (np > 0) s->curPath = 0;
    if (g_nspr >= MAXSPR) die("too many sprites");
    g_spr[g_nspr++] = s;
    return s;
}
static void spr_destroy(Sprite *s) {
    if (!s) return;
    for (int i = 0; i < g_nspr; i++) if (g_spr[i] == s) { memmove(&g_spr[i], &g_spr[i + 1], (g_nspr - i - 1) * sizeof *g_spr); g_nspr--; break; }
    free(s->bm->px); free(s->bm); free(s);
}
static void spr_move(Sprite *s, uint16_t frame, int x, int y) {      /* 741a2bca */
    if (frame >= s->nframes) frame = s->nframes - 1;
    s->frame = frame; s->x = x; s->y = y;
}
static void spr_select_path(Sprite *s, int idx) {                     /* idx11 / 741a3145 */
    if (s->curPath != idx && idx >= 0 && idx < s->npaths) { s->curPath = idx; s->curStep = 0xffff; s->lastFrame = 0xffff; }
}
static void spr_place(Sprite *s, int step, int x, int y) {            /* idx13 / 741a43e1 */
    uint16_t frame = step;
    if (s->curPath != 0xffff) {
        Path *p = &s->paths[s->curPath];
        if (step >= p->n) step = 0;
        frame = p->n ? p->steps[step].frame : 0;
    }
    spr_move(s, frame, x, y);
}
static void spr_apply(Sprite *s, uint16_t step) {                    /* 741a31b1 */
    if (s->curPath == 0xffff) return;
    Path *p = &s->paths[s->curPath];
    if (step < p->n) s->curStep = step;
    Step *st = &p->steps[s->curStep];
    audio_play(st->sound);
    if (st->dx == 0 && st->dy == 0 && s->lastFrame == st->frame) { s->lastFrame = st->frame; return; }
    s->lastFrame = st->frame;
    spr_move(s, st->frame, s->x + st->dx, s->y + st->dy);
}
static int spr_advance(Sprite *s) {                                  /* 741a3306 */
    Path *p = &s->paths[s->curPath];
    if (p->n == 0) return 1;
    s->curStep = (uint16_t)(s->curStep + 1);
    s->curStep %= p->n;
    spr_apply(s, s->curStep);
    return p->n - 1 == s->curStep;
}
static int spr_tick(Sprite *s) {                                     /* idx9 / 741a4438 + 741a33c1 */
    if (!s || s->npaths == 0 || s->curPath == 0xffff) return 0;
    uint32_t now = now_ms(); Path *p = &s->paths[s->curPath];
    if (p->next <= now) {
        int r = spr_advance(s);
        p->next = now + p->interval;
        return r;
    }
    return 0;
}

/* The plugin stores 32-bit sprite handles in its data tables: keep a stable handle table. */
static Sprite *g_hdl[MAXSPR * 4]; static int g_nhdl = 1;
static int32_t hnew(Sprite *s) { if (!s) return 0; g_hdl[g_nhdl] = s; return g_nhdl++; }
static Sprite *hget(int32_t h) { return h > 0 && h < g_nhdl ? g_hdl[h] : NULL; }
static void hfree(int32_t h) { if (h > 0 && h < g_nhdl) g_hdl[h] = NULL; }

/* static stamp (idx17): paints the first frame..whole bitmap into the background */
static void blit(uint32_t *dst, int dw, int dh, Bitmap *bm, int sx, int sy, int w, int h, int x, int y) {
    for (int j = 0; j < h; j++) {
        int dy = y + j; if (dy < 0 || dy >= dh) continue;
        for (int i = 0; i < w; i++) {
            int dx = x + i; if (dx < 0 || dx >= dw) continue;
            uint32_t c = bm->px[(size_t)(sy + j) * bm->w + sx + i];
            if (c) dst[(size_t)dy * dw + dx] = c;
        }
    }
}
static BmpRes g_scache[128]; static int g_scache_id[128], g_nscache;
static void stamp(int id256, int x, int y) {
    BmpRes *br = NULL;
    for (int i = 0; i < g_nscache; i++) if (g_scache_id[i] == id256) { br = &g_scache[i]; break; }
    if (!br) {
        uint32_t sz; const uint8_t *d = find_res(256, NULL, id256, &sz);
        if (!d || g_nscache >= 128) { g_abort = 1; return; }
        g_scache[g_nscache] = get_bitmap(U16(d, 0)); g_scache_id[g_nscache] = id256; br = &g_scache[g_nscache++];
    }
    blit(g_bg, W, H, br->bm, 0, 0, br->bm->w, br->bm->h, x, y);
}

/* ------------------------------------------------------------- audio */
static SDL_AudioDeviceID g_adev; static SDL_AudioSpec g_aspec;
static uint8_t *g_wav[5]; static uint32_t g_wavlen[5]; static int g_mute;
static void audio_init(void) {
    if (g_mute) return;
    SDL_AudioSpec want; SDL_zero(want);
    want.freq = 22050; want.format = AUDIO_S16SYS; want.channels = 1; want.samples = 1024;
    g_adev = SDL_OpenAudioDevice(NULL, 0, &want, &g_aspec, 0);
    if (!g_adev) { fprintf(stderr, "mystery: no audio (%s)\n", SDL_GetError()); return; }
    for (int id = 1; id <= 4; id++) {
        uint32_t sz; const uint8_t *d = find_res(0, "WAVE", id, &sz);
        if (!d) continue;
        SDL_AudioSpec ws; uint8_t *buf; uint32_t len;
        if (!SDL_LoadWAV_RW(SDL_RWFromConstMem(d, sz), 1, &ws, &buf, &len)) continue;
        SDL_AudioCVT cvt;
        if (SDL_BuildAudioCVT(&cvt, ws.format, ws.channels, ws.freq, g_aspec.format, g_aspec.channels, g_aspec.freq) < 0) { SDL_FreeWAV(buf); continue; }
        cvt.len = len; cvt.buf = malloc((size_t)len * cvt.len_mult);
        memcpy(cvt.buf, buf, len); SDL_FreeWAV(buf);
        SDL_ConvertAudio(&cvt);
        g_wav[id] = cvt.buf; g_wavlen[id] = cvt.len_cvt;
    }
    SDL_PauseAudioDevice(g_adev, 0);
}
static void audio_play(int id) {         /* sndPlaySound(SND_MEMORY|SND_ASYNC): a new sound replaces the old one */
    if (!g_adev || id <= 0 || id > 4 || !g_wav[id]) return;
    SDL_ClearQueuedAudio(g_adev);
    SDL_QueueAudio(g_adev, g_wav[id], g_wavlen[id]);
}

/* ----------------------------------------------------------- plugin code */
static uint8_t *g_data;                   /* copy of Mystery.dll .data (VA 0x79276000..) */
#define DATA_VA 0x79276000u
#define VA(a) (g_data + ((a) - DATA_VA))
static P g_actors, g_actions, g_statics; static int g_nact, g_nstat;
#define SEQ_START(i) I32(VA(0x79279218 + 8 * (i)), 0)
#define SEQ_END(i)   I32(VA(0x79279218 + 8 * (i)), 4)

/* actor field offsets */
enum { A_ID = 0, A_SPR = 2, A_X = 4, A_Y = 8, A_ANCH = 0xc, A_TYPE = 0x10, A_TILE = 0x14, A_W = 0x20, A_H = 0x24,
       A_MINW = 0x4c, A_MINH = 0x50, A_FLAGS = 0x54, A_X0 = 0x56, A_Y0 = 0x5a, A_EDGE = 0x5e, A_SEQ = 0x62,
       A_STATE = 0x66, A_TFLAGS = 0x6a, A_TRIG = 0x6e, A_PEND = 0x72, A_PMASK = 0x76, A_ACT = 0x7a, A_T1 = 0x7e,
       A_T2 = 0x82, A_SHOW = 0x86, A_M = 0x8a, A_HIT = 0x8e, A_SPRITE = 0x92, A_DX = 0x96, A_DY = 0x9a, ACTOR_SZ = 0x9e };
#define ACTOR(i) (g_actors + (i) * ACTOR_SZ)
#define ACTION(i) (g_actions + (i) * 0x40)
#define CUR(a) ACTION(I32(a, A_ACT))

typedef struct { int l, t, r, b; } Rect;
static Sprite *aspr(P a) { return hget(I32(a, A_SPRITE)); }

static void anchor(int *pt, int mode) {                                /* f715a0 */
    switch (mode) { case 2: case 3: case 7: pt[0] = W - pt[0]; break; case 5: case 6: case 8: pt[0] += W / 2; break; }
    switch (mode) { case 3: case 4: case 8: pt[1] = H - pt[1]; break; case 5: case 7: case 9: pt[1] += H / 2; break; }
}
static void edge_spawn(int *pt, int edge, int w, int h) {              /* f727a0 */
    switch (edge) { case 6: pt[1] = -h; break; case 7: pt[0] = W; break; case 8: pt[1] = H; break; case 9: pt[0] = -w; break; }
}
static void edge_wrap(P a, int *pt, int code, int w, int h) {          /* f72730 */
    Sprite *s = aspr(a); pt[0] = s->x; pt[1] = s->y;
    switch (code) { case 6: pt[1] = H; break; case 7: pt[0] = -w; break; case 8: pt[1] = -h; break; case 9: pt[0] = W; break; }
}
static void rect_of(P rec, Rect *r) {                                  /* f71900 */
    int pt[2] = { I32(rec, 4), I32(rec, 8) };
    anchor(pt, I32(rec, 0xc));
    r->l = pt[0]; r->t = pt[1]; r->r = pt[0] + I32(rec, 0x20); r->b = pt[1] + I32(rec, 0x24);
}
static int isect(const Rect *a, const Rect *b) { return a->l < b->r && b->l < a->r && a->t < b->b && b->t < a->b; }
static void sprect(Sprite *s, Rect *r) { r->l = s->x; r->t = s->y; r->r = s->x + s->fw; r->b = s->y + s->fh; }

static P find_actor(int id) { for (int i = 0; i < g_nact; i++) if (I16(ACTOR(i), 0) == (int16_t)id) return ACTOR(i); return NULL; }   /* f722a0 */
static P find_static(int id) { for (int i = 0; i < g_nstat; i++) if (I16(g_statics + i * 0x54, 0) == (int16_t)id) return g_statics + i * 0x54; return NULL; } /* f722d0 */

/* forward decls */
static void f71d50(P a, int ns); static void f720c0(P a); static void f72100(P a); static void f71f90(P a);
static void f71a40(P a, uint32_t mask); static void f71c10(P a); static void f71cf0(P a);

static uint32_t g_user_seed; static int g_have_seed;
static int f72690(P a) {                                               /* edge test */
    Sprite *s = aspr(a); if (!s) return 99;
    int di = 0;
    if (W <= s->x) di = 7;
    if (H <= s->y) di = 8;
    if (I32(a, A_DX) + s->x < 0) di = 9;
    if (I32(a, A_DY) + s->y < 0) di = 6;
    if (I32(a, A_M) != 0) { if (di) { I32(a, A_M) = 0; return di; } di = 0; }
    return di;
}
static void f725c0(P a, int mode, int *pt) {                           /* f725c0 */
    Sprite *s = aspr(a);
    if (mode == 1) { pt[0] = I32(a, A_X0); pt[1] = I32(a, A_Y0); anchor(pt, I32(a, A_ANCH)); edge_spawn(pt, I32(a, A_EDGE), I32(a, A_W), I32(a, A_H)); I32(a, A_M) = 1; }
    else if (mode == 2) { pt[0] = I32(a, A_X0); pt[1] = I32(a, A_Y0); anchor(pt, I32(a, A_ANCH)); }
    else if (mode == 3) { int code = f72690(a) & 0xffff; edge_wrap(a, pt, code, I32(a, A_W), I32(a, A_H)); I32(a, A_M) = 1; }
    else { pt[0] = s->x; pt[1] = s->y; return; }
    spr_move(s, s->frame, pt[0], pt[1]);                               /* idx16 */
}
static void f72560(P a) {
    int pt[2]; f725c0(a, (U8(a, 0x55) & 8) ? 1 : 2, pt);
    Sprite *s = aspr(a); I32(a, A_DX) = s->fw; I32(a, A_DY) = s->fh;
}
static void f72340(P a) {
    if (!I32(a, A_SPRITE)) {
        Sprite *s = spr_create(I16(a, A_SPR));
        I32(a, A_SPRITE) = hnew(s);
        if (!s) g_abort = 1;
    }
    if (I32(a, A_SHOW)) { Sprite *s = aspr(a); if (s) s->visible = 1; I32(a, A_SHOW) = 0; }
}
static void f72300(P a) {
    if (!(U16(a, A_FLAGS) & 8)) {
        I32(a, A_SHOW) = (U16(a, A_FLAGS) & 0x10) == 0;
        f72340(a); /* f723a0 */
        { /* f723a0 */
            if (U16(a, A_FLAGS) & 8) {}
            else if (U16(a, A_FLAGS) & 0x10) { Sprite *s = aspr(a); if (s) s->visible = 0; I32(a, A_SHOW) = 1; }
        }
        f72560(a);
    }
}
static void f723a0(P a) {
    if (U16(a, A_FLAGS) & 8) {
        Sprite *s = aspr(a);
        if ((int16_t)f72690(a) == 0 && s) {
            int pt[2] = { s->x, s->y };
            edge_spawn(pt, I32(a, A_EDGE), I32(a, A_W), I32(a, A_H));
            spr_move(s, s->frame, pt[0], pt[1]);
        }
        if (s) { spr_destroy(s); hfree(I32(a, A_SPRITE)); }
        I32(a, A_SPRITE) = 0; return;
    }
    if (U16(a, A_FLAGS) & 0x10) { Sprite *s = aspr(a); if (s) s->visible = 0; I32(a, A_SHOW) = 1; }
}
static void f72240(P a) {
    f72340(a);
    Sprite *s = aspr(a);
    if (s) { spr_select_path(s, I32(CUR(a), 2)); spr_place(s, 0, s->x, s->y); }
}
static void f724d0(P a) { I32(a, A_T2) = 0; I32(a, A_T1) = 0; I32(a, A_TFLAGS) = 0; }
static void f72440(P a, uint32_t flag, int *range) {
    if (flag == 4) { I32(a, A_T2) = rand_range(range[0], range[1]); U32(a, A_TFLAGS) |= 4; return; }
    int v = rand_range(range[0], range[1]);
    if (flag == 2) { I32(a, A_T2) = v * 0x37 + now_ms(); U32(a, A_TFLAGS) |= 2; return; }
    I32(a, A_T1) = v * 0x37 + now_ms(); U32(a, A_TFLAGS) |= flag;
}
static int f724f0(P a) {
    uint32_t f = U32(a, A_TFLAGS);
    if (!f) return 0;
    if (f & 0x19) {
        if (U32(a, A_T1) <= now_ms()) { U32(a, A_TFLAGS) &= 0xffffffe6u; return 1; }
        return 0;
    }
    if ((f & 4) && I32(a, A_T2) == 0) { U32(a, A_TFLAGS) = f & 0xfffffffbu; return 1; }
    if (f & 2) { if (U32(a, A_T2) <= now_ms()) { U32(a, A_TFLAGS) &= 0xfffffffdu; return 1; } }
    return 0;
}
static void f71b90(P a) { I32(a, A_TRIG) = 0; }
static void f71b40(P a, P t, uint32_t mask) { I32(t, A_PEND)++; U32(t, A_PMASK) |= mask; U32(a, A_TRIG) = mask; }
static void f71b60(P b, P t) {
    int v = I32(t, A_PEND) - 1; I32(t, A_PEND) = v;
    if (v < 1) { I32(t, A_PEND) = 0; I32(t, A_PMASK) = 0; }
    f71b90(b);
}
static void wake(P t) {
    for (int i = 0; i < g_nact; i++) {
        P b = ACTOR(i);
        if (I32(b, A_HIT)) { I32(b, A_HIT) = 0; f71b60(b, t); f720c0(b); }
    }
}
static void f71ad0(P t, uint32_t mask, int *count) {
    int16_t id = I16(t, A_ID);
    for (int i = 0; i < g_nact; i++) {
        P b = ACTOR(i); I32(b, A_HIT) = 0;
        if ((U32(b, A_TRIG) & mask) && I16(CUR(b), 0x32) == id) { I32(b, A_HIT) = 1; (*count)++; }
    }
}
static void f71a40(P t, uint32_t mask) {
    int count = 0; f71ad0(t, mask, &count);
    if (!count) { U32(t, A_PMASK) &= ~mask; return; }
    wake(t);
}
static P f71950(P t, uint32_t mask, int *count, int *cursor) {
    int16_t id = I16(t, A_ID);
    for (int i = *cursor; i < g_nact; i++) {
        P b = ACTOR(i); I32(b, A_HIT) = 0;
        if ((U32(b, A_TRIG) & mask) && I16(CUR(b), 0x32) == id) { (*count)++; I32(b, A_HIT) = 1; *cursor = i; return b; }
    }
    *cursor = g_nact; return NULL;
}
static int f717f0(P a) {                                               /* overlap trigger */
    Sprite *sa = aspr(a); Rect ra; if (sa) sprect(sa, &ra); else memset(&ra, 0, sizeof ra);
    int hits = 0, count = 0, cursor = 0;
    for (;;) {
        P b = f71950(a, 1, &count, &cursor);
        if (!b) { if (!count) U32(a, A_PMASK) &= ~1u; return hits > 0; }
        cursor++;
        int16_t did = I16(CUR(b), 0x34);
        P t = find_actor(did); Rect rt;
        if (t) {
            if (I32(t, A_TYPE) == 0) { Sprite *st = aspr(t); if (st) sprect(st, &rt); else memset(&rt, 0, sizeof rt); }
            else rect_of(t, &rt);
        } else {
            P st = find_static(did);
            if (!st) { I32(b, A_HIT) = 0; continue; }
            rect_of(st, &rt);
        }
        if (isect(&ra, &rt)) hits++; else I32(b, A_HIT) = 0;
    }
}
static void f71ba0(P a) {
    int st = I32(a, A_STATE);
    if (st == 4) { f71c10(a); return; }
    if (st != 5) { f720c0(a); return; }
    f71cf0(a);
}
static void f71c10(P a) {
    int pt[2];
    if (U16(a, A_FLAGS) & 0x100) f725c0(a, (U16(a, A_FLAGS) & 0x1000) ? 1 : 2, pt);
    if (U8(a, A_TFLAGS) & 4) I32(a, A_T2)--;
    if (U8(a, A_FLAGS) & 0x80) { f720c0(a); return; }
    f71d50(a, 3);
    if (I32(a, A_TFLAGS) && f724f0(a)) f71ba0(a);
}
static void f71cf0(P a) {
    int pt[2]; f71d50(a, 3);
    int mode = !(U16(a, A_FLAGS) & 0x2000) ? 3 : (!(U16(a, A_FLAGS) & 0x1000) ? 2 : 1);
    f725c0(a, mode, pt);
    if (U8(a, 0x55) & 4) f720c0(a);
}
static void f71bd0(P a) {
    if (U8(a, A_FLAGS) & 0x40) { f72440(a, 8, (int *)(CUR(a) + 0x1a)); f71d50(a, 4); return; }
    f71c10(a);
}
static void f71c90(P a) {
    if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 8)) f71a40(a, 8);
    if (U8(a, 0x55) & 2) { f72440(a, 0x10, (int *)(CUR(a) + 0x2a)); f71d50(a, 5); return; }
    f71cf0(a);
}
static void f71d50(P a, int ns) {
    switch (I32(a, A_STATE)) {
    case 0:
        switch (ns) {
        case 0: return;
        case 1: case 2: f72300(a); I32(a, A_STATE) = ns; return;
        case 3:
            if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 2)) f71a40(a, 2);
            f72340(a); f72560(a); I32(a, A_STATE) = ns; return;
        }
        break;
    case 1:
        if (ns == 1) return;
        if (ns == 3) {
            if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 2)) f71a40(a, 2);
            f72340(a); f72560(a); I32(a, A_STATE) = 3; return;
        }
        break;
    case 2:
        if (ns == 2) return;
        if (ns == 3) {
            if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 2)) f71a40(a, 2);
            f72340(a); f72560(a); I32(a, A_STATE) = 3; return;
        }
        break;
    case 3:
        switch (ns) {
        case 1: case 2: case 4: case 5: case 6: f723a0(a); I32(a, A_STATE) = ns; return;
        case 3: return;
        }
        break;
    case 4:
        if (ns == 3) { f72340(a); I32(a, A_STATE) = 3; return; }
        if (ns == 4) return;
        I32(a, A_STATE) = ns; return;
    case 5:
        if (ns == 3) { f72340(a); I32(a, A_STATE) = 3; return; }
        if (ns == 5) return;
        I32(a, A_STATE) = ns; return;
    case 6:
        if (ns == 3) {
            if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 2)) f71a40(a, 2);
            f72340(a);
        } else if (ns != 5) {
            if (ns == 6) return;
            I32(a, A_STATE) = ns; return;
        }
        break;
    }
    I32(a, A_STATE) = ns;
}
static void f72080(P a) {
    if (I32(a, A_PEND) > 0 && (U8(a, A_PMASK) & 4)) f71a40(a, 4);
    f71b90(a); f724d0(a); f71d50(a, 6);
}
static void f720c0(P a) {
    int v = I32(a, A_ACT) + 1; I32(a, A_ACT) = v;
    if (v <= SEQ_END(I32(a, A_SEQ))) { f72100(a); return; }
    f72080(a); f71f90(a);
}
static void f72100(P a) {
    P act = CUR(a);
    f71b90(a); f724d0(a);
    if (I32(act, 6) == 2) {
        f72240(a);
        f71d50(a, 3);
        if (!(U32(act, 0x3a) & 2)) {
            if (!(U32(act, 0x3a) & 4)) {
                uint32_t m = U32(act, 0x36);
                if (m) { P t = find_actor(I16(act, 0x32)); f71b40(a, t, m); }
            } else f72440(a, 4, (int *)(act + 10));
        } else f72440(a, 2, (int *)(act + 0x12));
        if (!(U8(act, 0x3e) & 0x40)) U16(a, A_FLAGS) &= 0xffbf; else U8(a, A_FLAGS) |= 0x40;
        if (!(U8(act, 0x3f) & 2)) U16(a, A_FLAGS) &= 0xfdff; else U8(a, 0x55) |= 2;
        if (!(U8(act, 0x3f) & 4)) U16(a, A_FLAGS) &= 0xfbff; else U8(a, 0x55) |= 4;
        if (!(U8(act, 0x3e) & 0x80)) U16(a, A_FLAGS) &= 0xff7f; else U8(a, A_FLAGS) |= 0x80;
        if (!(U8(act, 0x3f) & 1)) U16(a, A_FLAGS) &= 0xfeff; else U8(a, 0x55) |= 1;
        return;
    }
    uint32_t m = U32(act, 0x36);
    if (m) { P t = find_actor(I16(act, 0x32)); f71b40(a, t, m); f71d50(a, 1); return; }
    if (!(U8(act, 0x3a) & 1)) { f720c0(a); return; }
    f72440(a, 1, (int *)(act + 0x22)); f71d50(a, 2);
}
static void f71f90(P a) {
    int act = SEQ_START(I32(a, A_SEQ));
    I32(a, A_ACT) = act;
    if (act <= 0) return;
    int pt[2];
    if (I32(a, A_STATE) == 0) {
        P ac = ACTION(act);
        if ((U8(a, A_FLAGS) & 4) && I32(ac, 6) == 0 && U32(ac, 0x36) != 0) { f720c0(a); return; }
        f72100(a); return;
    }
    if (I32(a, A_STATE) != 6) { f72100(a); return; }
    if (U16(a, A_FLAGS) & 2) f725c0(a, (U16(a, A_FLAGS) & 0x1000) ? 1 : 2, pt);
    if (!(U8(a, 0x55) & 0x40)) {
        P ac = CUR(a);
        if (I32(ac, 6) == 0 && U32(ac, 0x36) != 0) { f72100(a); return; }
    } else {
        int off = I32(a, A_ACT) * 0x40;
        while (I32(g_actions + off, 6) == 0) { off += 0x40; I32(a, A_ACT)++; }
        f72100(a);
    }
}

/* ---- main per-frame logic (f71700 = DoDraw) ---- */
static void do_draw(void) {
    for (int i = 0; i < g_nact && !g_abort; i++) {
        P a = ACTOR(i);
        if (I32(a, A_STATE) == 3) {
            if (I32(a, A_PEND) > 0 && (U32(a, A_PMASK) & 1) && f717f0(a)) {
                for (int k = 0; k < g_nact; k++) { P b = ACTOR(k); if (I32(b, A_HIT)) { I32(b, A_HIT) = 0; f71b60(b, a); f720c0(b); } }
            }
            if (I32(a, A_STATE) == 3 && (int16_t)f72690(a) != 0) f71c90(a);
        }
        if (I32(a, A_TFLAGS) != 0 && f724f0(a)) f71ba0(a);
        if (I32(a, A_STATE) == 3 && spr_tick(aspr(a))) f71bd0(a);
    }
}

/* ---- scene setup ---- */
static void place_sprite(P rec, int *pt) {                            /* f717c0: idx18 create + place */
    Sprite *s = spr_create(I16(rec, 2));
    if (!s) { g_abort = 1; return; }
    spr_place(s, 0, pt[0], pt[1]);
    (void)hnew;
}
static void place_any(P rec, int *pt) {
    if (U8(rec, 0x10) & 2) stamp(I16(rec, 2), pt[0], pt[1]); else place_sprite(rec, pt);
}
static void f712a0(P p) {
    if (I32(p, 0x14) == 0) return;
    int s8[2] = { I32(p, 4), I32(p, 8) };
    anchor(s8, I32(p, 0xc));
    int e[2] = { I32(p, 0x3c), I32(p, 0x40) };
    anchor(e, I32(p, 0x38));
    e[0] += I32(p, 4);
    int iVar2 = I32(p, 0x20) + (e[0] - s8[0]);
    int iVar5 = I32(p, 0x28);
    e[1] += I32(p, 8);
    int iVar4 = I32(p, 0x24) + (e[1] - s8[1]);
    int local24 = I32(p, 0x2c);
    int cols = 1, rows = 1;
    if ((U8(p, 0x1c) & 1) == 0) {
        if (U8(p, 0x1c) & 2) {
            cols = I32(p, 0x30) < 1 ? 1 : (iVar2 - I32(p, 0x20)) / I32(p, 0x30) + 2;
            rows = I32(p, 0x34) < 1 ? 1 : (iVar4 - I32(p, 0x24)) / I32(p, 0x34) + 2;
            if (cols > 1) iVar5 = I32(p, 0x20) + (iVar2 - cols * I32(p, 0x20)) / (cols - 1);
            if (rows > 1) local24 = (iVar4 - rows * I32(p, 0x24)) / (rows - 1) + I32(p, 0x24);
            if (iVar5 < I32(p, 0x28)) iVar5 = I32(p, 0x28);
            if (local24 < I32(p, 0x2c)) local24 = I32(p, 0x2c);
        }
    } else {
        cols = I32(p, 0x30) < 1 ? 1 : (iVar2 - I32(p, 0x20)) / I32(p, 0x30) + 1;
        rows = I32(p, 0x34) < 1 ? 1 : (iVar4 - I32(p, 0x24)) / I32(p, 0x34) + 1;
    }
    if (I32(p, 0x18) != 0) cols = 1;
    int cur[2] = { s8[0], s8[1] };
    if (!(U8(p, 0x1c) & 4)) {
        for (int r = 0; r < rows; r++) {
            if (g_abort) return;
            for (int c = 0; c < cols; c++) {
                if (g_abort) break;
                place_any(p, cur);
                cur[0] += iVar5;
            }
            if (I32(p, 0x18) == 0) cur[0] = s8[0];
            cur[1] += local24;
        }
    } else {
        int limit = e[0] + I32(p, 0x44) / 2;
        for (int r = 0; r < rows && !g_abort; r++) {
            int again;
            do {
                int w = I32(p, 0x44); cur[0] += rand_range(0, w) - w / 2;
                int pt[2] = { cur[0], cur[1] };
                int h = I32(p, 0x48); pt[1] += rand_range(0, h) - h / 2;
                place_any(p, pt);
                if (g_abort) return;
                cur[0] += iVar5;
                again = I32(p, 0x18) == 0 ? !(limit < cur[0]) : 0;
            } while (again);
            if (I32(p, 0x18) == 0) cur[0] = s8[0];
            cur[1] += local24;
        }
    }
}

/* ---- --wide: NOT in the original. Spread background elements that the original defines relative to the
 * screen centre for at most 1280x1024, so that 16:9 / ultrawide logical areas are filled. ---- */
static void anchor_wh(int *pt, int mode, int w, int h) {
    switch (mode) { case 2: case 3: case 7: pt[0] = w - pt[0]; break; case 5: case 6: case 8: pt[0] += w / 2; break; }
    switch (mode) { case 3: case 4: case 8: pt[1] = h - pt[1]; break; case 5: case 7: case 9: pt[1] += h / 2; break; }
}
static void f712a0(P p);
static void wide_stars(void) {                      /* actors 0..9: twinkling stars (sprites 8220/8221/8222) */
    for (int i = 0; i < 10 && i < g_nact; i++) {
        P a = ACTOR(i);
        int pt[2] = { I32(a, A_X0), I32(a, A_Y0) };
        anchor_wh(pt, I32(a, A_ANCH), 640, 480);        /* where it sits on the original 640x480 layout */
        int x = pt[0] * W / 640;
        I32(a, A_ANCH) = 1; I32(a, A_X0) = x; I32(a, A_Y0) = pt[1]; I32(a, 4) = x; I32(a, 8) = pt[1];
    }
}
static void wide_ground(void) {                     /* statics 0..13: rubble patches, defined within about +-700 px of centre */
    const int period = 1450;
    if (W / 2 <= 700) return;
    for (int i = 0; i < 14 && i < g_nstat && !g_abort; i++) {
        P p = g_statics + i * 0x54; int orig = I32(p, 4);
        for (int dir = -1; dir <= 1; dir += 2)
            for (int k = 1; k <= 4; k++) {
                int sh = dir * k * period, start = W / 2 + orig + sh;
                if (start + 500 < 0 || start > W) continue;
                I32(p, 4) = orig + sh; f712a0(p);
            }
        I32(p, 4) = orig;
    }
}
static void init_statics(void) {                                       /* f71210 */
    for (int i = 0; i < g_nstat && !g_abort; i++) {
        P rec = g_statics + i * 0x54;
        if (I32(rec, 0x4c) < W || I32(rec, 0x50) < H) {
            if (I32(rec, 0x14) == 0) { int pt[2] = { I32(rec, 4), I32(rec, 8) }; anchor(pt, I32(rec, 0xc)); stamp(I16(rec, 2), pt[0], pt[1]); }
            else f712a0(rec);
        }
    }
    if (g_wide) wide_ground();
}
static void init_actors(void) {
    if (g_wide) wide_stars();                                        /* f71640 */
    c_srand(g_have_seed ? g_user_seed : now_ms() ^ 0x5bd1e995u);
    for (int i = 0; i < g_nact && !g_abort; i++) {
        P a = ACTOR(i);
        if (I32(a, A_MINW) < W || I32(a, A_MINH) < H) {
            if (I32(a, A_TILE) == 0) {
                if (I32(a, A_TYPE) == 1) { int pt[2] = { I32(a, 4), I32(a, 8) }; anchor(pt, I32(a, 0xc)); place_sprite(a, pt); }
                else f71f90(a);
            } else f712a0(a);
        }
    }
}

/* ------------------------------------------------------------- renderer */
static uint32_t *g_fb;
static void compose(void) {
    memcpy(g_fb, g_bg, (size_t)W * H * 4);
    for (int i = 0; i < g_nspr; i++) {
        Sprite *s = g_spr[i]; if (!s->visible) continue;
        blit(g_fb, W, H, s->bm, s->frame * s->fw, 0, s->fw, s->fh, s->x, s->y);
    }
}

int main(int argc, char **argv) {
    const char *dll = "Mystery.dll"; int ww = 0, wh = 0, windowed = 0, dump_ms = -1, scale = 0, lw = 0, lh = 0; const char *dump_file = "frame.bmp";
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dll") && i + 1 < argc) dll = argv[++i];
        else if (!strcmp(argv[i], "--size") && i + 1 < argc) { sscanf(argv[++i], "%dx%d", &ww, &wh); windowed = 1; }
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) scale = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--logical") && i + 1 < argc) { ++i; if (!strcmp(argv[i], "native")) lw = -1; else sscanf(argv[i], "%dx%d", &lw, &lh); }
        else if (!strcmp(argv[i], "--wide")) g_wide = 1;
        else if (!strcmp(argv[i], "--mute")) g_mute = 1;
        else if (!strcmp(argv[i], "--fast")) g_fast = 1;
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc) { g_user_seed = atoi(argv[++i]); g_have_seed = 1; }
        else if (!strcmp(argv[i], "--dump") && i + 2 < argc) { dump_ms = atoi(argv[++i]); dump_file = argv[++i]; }
        else { fprintf(stderr, "usage: %s [--dll Mystery.dll] [--size WxH] [--wide] [--logical WxH|native] [--scale N] [--mute] [--seed N] [--fast --dump MS out.bmp]\n", argv[0]); return 2; }
    }
    load_pe(dll);
    if (g_imgbase != 0x79270000u) die("unexpected Mystery.dll image base");
    /* load .data image */
    {
        uint32_t rva = DATA_VA - g_imgbase; uint32_t vsz = 0x5000;
        g_data = calloc(1, vsz);
        for (int i = 0; i < g_nsec; i++) if (rva >= g_sec[i].va && rva < g_sec[i].va + g_sec[i].vs) {
            uint32_t n = g_sec[i].rs < vsz ? g_sec[i].rs : vsz; memcpy(g_data, g_file + g_sec[i].rp + (rva - g_sec[i].va), n);
        }
        g_statics = VA(0x79276000); g_nstat = I32(VA(0x79276888), 0);
        g_actors = VA(0x79276890); g_nact = I32(VA(0x79277d8c), 0);
        g_actions = VA(0x79277d90);
        if (g_nstat != 26 || g_nact != 34) die("unexpected table sizes (wrong Mystery.dll?)");
    }
    if (SDL_Init(SDL_INIT_VIDEO | (g_mute ? 0 : SDL_INIT_AUDIO)) < 0) { fprintf(stderr, "SDL: %s\n", SDL_GetError()); return 1; }
    SDL_Window *win = NULL; SDL_Renderer *ren = NULL; SDL_Texture *tex = NULL;
    if (windowed) { W = ww; H = wh; }
    else { SDL_DisplayMode dm; SDL_GetDesktopDisplayMode(0, &dm); W = dm.w; H = dm.h; }
    if (!(g_fast && dump_ms >= 0)) {
        SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "1");
        win = SDL_CreateWindow("Mystery", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, W, H,
                               windowed ? 0 : SDL_WINDOW_FULLSCREEN_DESKTOP);
        if (!win) { fprintf(stderr, "SDL window: %s\n", SDL_GetError()); return 1; }
        SDL_GetWindowSize(win, &W, &H);
        ren = SDL_CreateRenderer(win, -1, 0);
        SDL_GetRendererOutputSize(ren, &W, &H);
        if (g_wide && !windowed && lw <= 0) { lh = 768; lw = (int)((double)lh * W / H + 0.5); if (lw < 1024) lw = 1024; }   /* screen aspect, 768 tall */
        if (lw == 0 && scale <= 0 && !windowed) { lw = 1024; lh = 768; }          /* default: 1024x768 logical area */
        if (lw > 0 && lh > 0) {
            if (lw > W || lh > H) { lw = W; lh = H; }
            W = lw; H = lh; scale = 1;
            SDL_RenderSetLogicalSize(ren, W, H);                                    /* keeps aspect ratio, letterboxed */
        } else {
            if (scale <= 0) { scale = W / 640 < H / 480 ? W / 640 : H / 480; if (scale < 1) scale = 1; }  /* scene was authored for 640x480 */
            W /= scale; H /= scale;
        }
        tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, W, H);
        if (!windowed) SDL_ShowCursor(SDL_DISABLE);
    }
    if (!win) { if (scale < 1) scale = 1; W /= scale; H /= scale; }
    g_bg = calloc((size_t)W * H, 4); g_fb = calloc((size_t)W * H, 4);
    for (size_t i = 0; i < (size_t)W * H; i++) g_bg[i] = 0xff000000u;
    audio_init();

    /* Initialize() */
    g_abort = 0; c_srand(1);
    init_statics();
    init_actors();
    if (g_abort) fprintf(stderr, "mystery: initialisation aborted (missing resource?)\n");

    int mx0 = 0, my0 = 0, have0 = 0, running = 1;
    uint32_t last = now_ms();
    while (running) {
        if (g_fast) g_fake_clock += 15;
        if (dump_ms >= 0 && g_fast && (int)g_fake_clock >= dump_ms) {
            compose();
            SDL_Surface *su = SDL_CreateRGBSurfaceWithFormatFrom(g_fb, W, H, 32, W * 4, SDL_PIXELFORMAT_ARGB8888);
            SDL_SaveBMP(su, dump_file); SDL_FreeSurface(su); break;
        }
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT || e.type == SDL_KEYDOWN || e.type == SDL_MOUSEBUTTONDOWN) running = 0;
            else if (e.type == SDL_MOUSEMOTION && !windowed) {
                if (!have0) { mx0 = e.motion.x; my0 = e.motion.y; have0 = 1; }
                else if (abs(e.motion.x - mx0) + abs(e.motion.y - my0) > 4) running = 0;  /* default "Mouse Threshold" = 4 */
            }
        }
        if (g_abort) break;
        do_draw();
        if (ren) {
            compose();
            SDL_UpdateTexture(tex, NULL, g_fb, W * 4);
            SDL_RenderClear(ren); SDL_RenderCopy(ren, tex, NULL, NULL); SDL_RenderPresent(ren);
        }
        if (!g_fast) { uint32_t t = SDL_GetTicks(); if (t - last < 15) SDL_Delay(15 - (t - last)); last = SDL_GetTicks(); }
    }
    SDL_Quit();
    return 0;
}
