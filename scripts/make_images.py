#!/usr/bin/env python3
"""Generates the marketplace artwork (icon, banner, screenshots, demo GIF).
The editor/dashboard images are rendered from the REAL scanner output of samples/*,
so what they show is exactly what the engine reports. Replace with real screenshots anytime.
Requires: Pillow, node.  Run:  python3 scripts/make_images.py
"""
import json, math, os, re, subprocess
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'images')
os.makedirs(OUT, exist_ok=True)
FD = '/usr/share/fonts/truetype/dejavu/'
def F(size, bold=False, mono=False):
    n = 'DejaVuSansMono' if mono else 'DejaVuSans'
    return ImageFont.truetype(FD + n + ('-Bold' if bold else '') + '.ttf', size)

TEAL, BLUE, NAVY = (52, 211, 180), (59, 130, 246), (11, 18, 32)
SEV = {'critical': (255, 77, 109), 'high': (255, 138, 61), 'medium': (245, 197, 66), 'low': (77, 163, 255), 'info': (139, 149, 167)}

# ───────────────────────── helpers ─────────────────────────
def gradient(w, h, c1, c2, diag=True):
    g = Image.new('RGB', (w, h))
    px = g.load()
    for y in range(h):
        for x in range(w):
            t = ((x / w) + (y / h)) / 2 if diag else y / h
            px[x, y] = tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))
    return g

def bez(p0, p1, p2, p3, n=36):
    pts = []
    for i in range(n + 1):
        t = i / n
        pts.append(tuple((1-t)**3*p0[k] + 3*(1-t)**2*t*p1[k] + 3*(1-t)*t**2*p2[k] + t**3*p3[k] for k in range(2)))
    return pts

def shield_poly(cx, cy, s):
    right = [(0, -1.0), (0.88, -0.70), (0.88, 0.04)] + bez((0.88, 0.04), (0.88, 0.60), (0.46, 0.90), (0, 1.06))[1:]
    left = [(-x, y) for x, y in reversed(right)][:-1]
    return [(cx + x * s, cy + y * s) for x, y in right + left]

def draw_logo(size, bg=True):
    k = 4  # supersample
    S = size * k
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if bg:
        base = gradient(S, S, (16, 28, 52), (8, 13, 26), diag=True).convert('RGBA')
        m = Image.new('L', (S, S), 0)
        ImageDraw.Draw(m).rounded_rectangle((0, 0, S - 1, S - 1), int(S * 0.22), fill=255)
        img.paste(base, (0, 0), m)
        # soft glow
        glow = Image.new('RGBA', (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(glow).ellipse((S*0.15, S*0.2, S*0.85, S*0.9), fill=(52, 211, 180, 70))
        glow = glow.filter(ImageFilter.GaussianBlur(S * 0.09))
        img = Image.alpha_composite(img, glow)
        d = ImageDraw.Draw(img)
    cx, cy, s = S / 2, S * 0.5, S * 0.34
    poly = shield_poly(cx, cy, s)
    fill = gradient(S, S, TEAL, BLUE, diag=True).convert('RGBA')
    mask = Image.new('L', (S, S), 0)
    ImageDraw.Draw(mask).polygon(poly, fill=255)
    img.paste(fill, (0, 0), mask)
    d = ImageDraw.Draw(img)
    inner = shield_poly(cx, cy, s * 0.80)
    d.polygon(inner, fill=(10, 18, 34, 235))
    # keyhole
    kc = (cx, cy - s * 0.12)
    r = s * 0.20
    d.ellipse((kc[0] - r, kc[1] - r, kc[0] + r, kc[1] + r), fill=(52, 211, 180, 255))
    d.polygon([(cx - r * 0.55, kc[1] + r * 0.6), (cx + r * 0.55, kc[1] + r * 0.6), (cx + r * 0.85, cy + s * 0.50), (cx - r * 0.85, cy + s * 0.50)], fill=(52, 211, 180, 255))
    # scan line
    y = cy + s * 0.08
    line = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    ld = ImageDraw.Draw(line)
    ld.rounded_rectangle((cx - s * 0.80, y - S * 0.012, cx + s * 0.80, y + S * 0.012), S * 0.012, fill=(255, 255, 255, 255))
    glow = line.filter(ImageFilter.GaussianBlur(S * 0.012))
    clip = Image.new('L', (S, S), 0)
    ImageDraw.Draw(clip).polygon(shield_poly(cx, cy, s * 0.90), fill=255)
    for layer in (glow, line):
        a = layer.split()[3]
        layer.putalpha(Image.composite(a, Image.new('L', (S, S), 0), clip))
        img = Image.alpha_composite(img, layer)
    return img.resize((size, size), Image.LANCZOS)

def shadow(base, box, r=14, blur=22, off=(0, 10), alpha=150):
    sh = Image.new('RGBA', base.size, (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle((box[0] + off[0], box[1] + off[1], box[2] + off[0], box[3] + off[1]), r, fill=(0, 0, 0, alpha))
    base.alpha_composite(sh.filter(ImageFilter.GaussianBlur(blur)))

def squiggle(d, x1, x2, y, color):
    pts, x, up = [], x1, True
    while x < x2:
        pts.append((x, y + (0 if up else 3)))
        x += 3; up = not up
    pts.append((x2, y + (0 if up else 3)))
    if len(pts) > 1:
        d.line(pts, fill=color, width=2)

def wrap(text, font, width):
    out, line = [], ''
    for w in text.split(' '):
        t = (line + ' ' + w).strip()
        if font.getlength(t) <= width: line = t
        else: out.append(line); line = w
    out.append(line)
    return out

# ───────────────────────── real scanner data ─────────────────────────
def scan(path):
    res = subprocess.run(['node', os.path.join(ROOT, 'bin', 'shieldlocal.js'), path, '-f', 'json'], capture_output=True, text=True, check=True)
    return json.loads(res.stdout)
SCAN = scan(os.path.join(ROOT, 'samples'))
DEMO = next(f for f in SCAN['files'] if f['file'] == 'demo.js')['findings']
DEMO_LINES = open(os.path.join(ROOT, 'samples', 'demo.js')).read().split('\n')[:20]

# ───────────────────────── syntax colouring ─────────────────────────
KW = r'\b(const|let|var|function|return|if|else|new|await|async|require|import|from|def|as|for|in|of)\b'
TOK = re.compile(r'(//.*$)|("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`)|' + KW + r'|(\b\d+\b)|(\b[A-Za-z_$][\w$]*)(?=\()')
def tokens(line):
    pos = 0
    for m in TOK.finditer(line):
        if m.start() > pos: yield line[pos:m.start()], (212, 212, 212)
        col = (106, 153, 85) if m.group(1) else (206, 145, 120) if m.group(2) else (86, 156, 214) if m.group(3) else (181, 206, 168) if m.group(4) else (220, 220, 170)
        yield m.group(0), col
        pos = m.end()
    if pos < len(line): yield line[pos:], (212, 212, 212)

# ───────────────────────── editor renderer ─────────────────────────
def editor(W, H, lines, findings, *, fs=19, lh=30, hover=None, menu=None, status=None, problems=None,
           tab='demo.js', sidebar=None, bulb=None, cursor=None, hover_w=600):
    img = Image.new('RGBA', (W, H), (30, 30, 30, 255))
    d = ImageDraw.Draw(img)
    mono, ui = F(fs, mono=True), F(max(12, fs - 5))
    cw = mono.getlength('M')
    ab = 56
    d.rectangle((0, 0, ab, H), fill=(51, 51, 51))
    for i, y in enumerate((18, 74, 130, 186)):
        c = (255, 255, 255) if i == 0 else (140, 140, 140)
        d.rounded_rectangle((16, y, 40, y + 24), 5, outline=c, width=2)
    # shield icon in activity bar (highlight)
    sx, sy = ab // 2, H - 150
    d.polygon(shield_poly(sx, sy, 15), outline=(52, 211, 180), fill=None)
    d.line([(sx - 6, sy), (sx - 1, sy + 6), (sx + 8, sy - 6)], fill=(52, 211, 180), width=2)
    x0 = ab
    if sidebar:
        d.rectangle((ab, 0, ab + sidebar, H), fill=(37, 37, 38))
        x0 = ab + sidebar
    # tabs
    d.rectangle((x0, 0, W, 44), fill=(37, 37, 38))
    d.rectangle((x0, 0, x0 + 190, 44), fill=(30, 30, 30))
    d.ellipse((x0 + 16, 17, x0 + 28, 29), fill=(241, 224, 90))
    d.text((x0 + 38, 12), tab, font=ui, fill=(255, 255, 255))
    gut = 78
    top = 44 + 14
    code_x = x0 + gut
    pb = (problems or 0)
    status_h = 28
    code_bottom = H - status_h - pb
    # code
    d.rectangle((x0, 44, W, code_bottom), fill=(30, 30, 30))
    for i, line in enumerate(lines):
        y = top + i * lh
        if y + lh > code_bottom: break
        d.text((x0 + gut - 22 - ui.getlength(str(i + 1)), y + (lh - fs) // 2 - 1), str(i + 1), font=ui, fill=(133, 133, 133))
        x = code_x
        for t, col in tokens(line):
            d.text((x, y + (lh - fs) // 2 - 3), t, font=mono, fill=col)
            x += mono.getlength(t)
    for f in findings:
        y = top + f['line'] * lh + lh - 7
        c = (241, 76, 76) if f['severity'] in ('critical', 'high') else (204, 167, 0) if f['severity'] == 'medium' else (55, 148, 255)
        squiggle(d, code_x + f['col'] * cw, code_x + f['endCol'] * cw, y, c)
    if cursor:
        cx = code_x + cursor[1] * cw
        d.rectangle((cx, top + cursor[0] * lh + 3, cx + 2, top + cursor[0] * lh + lh - 3), fill=(255, 255, 255))
    if bulb is not None:
        by = top + bulb * lh
        d.ellipse((x0 + 8, by + 5, x0 + 28, by + 25), fill=(255, 204, 0))
        d.rectangle((x0 + 14, by + 25, x0 + 22, by + 29), fill=(255, 204, 0))
    # problems panel
    if problems:
        py = code_bottom
        d.rectangle((x0, py, W, H - status_h), fill=(24, 24, 24))
        d.line((x0, py, W, py), fill=(60, 60, 60))
        d.text((x0 + 18, py + 10), 'PROBLEMS', font=F(13, True), fill=(255, 255, 255))
        d.rounded_rectangle((x0 + 100, py + 8, x0 + 134, py + 28), 9, fill=(77, 77, 77))
        d.text((x0 + 109, py + 11), str(len(findings)), font=F(13, True), fill=(255, 255, 255))
        d.line((x0 + 18, py + 33, x0 + 98, py + 33), fill=(0, 122, 204), width=2)
        for i, f in enumerate(sorted(findings, key=lambda f: f['line'])[: (problems - 44) // 26]):
            y = py + 44 + i * 26
            c = SEV['high'] if f['severity'] in ('critical', 'high') else SEV['medium']
            d.ellipse((x0 + 22, y + 5, x0 + 34, y + 17), fill=(241, 76, 76) if f['severity'] in ('critical', 'high') else (204, 167, 0))
            d.text((x0 + 46, y), f['title'], font=ui, fill=(204, 204, 204))
            tx = x0 + 46 + ui.getlength(f['title']) + 12
            d.text((tx, y), f"ShieldLocal({f['ruleId']})  [Ln {f['line'] + 1}, Col {f['col'] + 1}]", font=ui, fill=(130, 130, 130))
    # status bar
    sb = status or ('3 issues', (199, 46, 15))
    d.rectangle((0, H - status_h, W, H), fill=(0, 122, 204))
    d.text((14, H - status_h + 5), 'main', font=F(13), fill=(255, 255, 255))
    d.text((ab + 90, H - status_h + 5), 'JavaScript    UTF-8    LF', font=F(13), fill=(255, 255, 255)) if False else None
    chip = f'  {sb[0]}  '
    cwid = F(13, True).getlength(chip) + 28
    d.rectangle((90, H - status_h, 90 + cwid, H), fill=sb[1])
    d.polygon(shield_poly(106, H - 14, 8), outline=(255, 255, 255))
    d.text((120, H - status_h + 5), chip.strip(), font=F(13, True), fill=(255, 255, 255))
    d.text((W - 270, H - status_h + 5), 'Ln 11, Col 13   JavaScript   UTF-8', font=F(13), fill=(255, 255, 255))

    # hover
    if hover:
        f = hover
        bx = code_x + f['col'] * cw
        by = top + (f['line'] + 1) * lh + 6
        bw = hover_w
        lines_ = [(f['title'], F(15, True), (255, 255, 255))]
        for t in wrap(f['message'], F(14), bw - 28): lines_.append((t, F(14), (204, 204, 204)))
        for t in wrap('Fix: ' + f['remediation'], F(14), bw - 28): lines_.append((t, F(14), (156, 220, 254)))
        lines_.append((f"ShieldLocal({f['ruleId']})" + (f"   CWE-{f['cwe']}" if f.get('cwe') else ''), F(13), (130, 130, 130)))
        hh = 22 + sum(int(ft.size * 1.55) for _, ft, _ in lines_) + 40
        shadow(img, (bx, by, bx + bw, by + hh), 6, 10, (0, 4), 160)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((bx, by, bx + bw, by + hh), 6, fill=(37, 37, 38), outline=(69, 69, 69))
        y = by + 12
        for t, ft, col in lines_:
            d.text((bx + 14, y), t, font=ft, fill=col); y += int(ft.size * 1.55)
        d.line((bx + 1, by + hh - 36, bx + bw - 1, by + hh - 36), fill=(69, 69, 69))
        d.text((bx + 14, by + hh - 28), 'View Problem (Alt+F8)', font=F(13), fill=(55, 148, 255))
        d.text((bx + 210, by + hh - 28), 'Quick Fix... (Ctrl+.)', font=F(13), fill=(55, 148, 255))
    if menu:
        f, items = menu
        bx = x0 + 30
        by = top + (f['line'] + 1) * lh + 4
        bw = 560
        shadow(img, (bx, by, bx + bw, by + 12 + 34 * len(items)), 6, 10, (0, 4), 170)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((bx, by, bx + bw, by + 12 + 34 * len(items)), 6, fill=(37, 37, 38), outline=(69, 69, 69))
        for i, t in enumerate(items):
            y = by + 6 + i * 34
            if i == 0: d.rectangle((bx + 3, y, bx + bw - 3, y + 32), fill=(4, 57, 94))
            d.ellipse((bx + 14, y + 9, bx + 28, y + 23), fill=(255, 204, 0) if i == 0 else (130, 130, 130))
            d.text((bx + 42, y + 7), t, font=F(15), fill=(255, 255, 255) if i == 0 else (204, 204, 204))
    return img.convert('RGB')

# ───────────────────────── 1. icon ─────────────────────────
draw_logo(256).save(os.path.join(OUT, 'icon.png'))
draw_logo(512).save(os.path.join(OUT, 'logo-512.png'))

# ───────────────────────── 2. editor screenshot ─────────────────────────
sql = next(f for f in DEMO if f['ruleId'] == 'sql-concat')
ED = editor(1600, 1000, DEMO_LINES, DEMO, hover=sql, problems=300, status=(f'{len(DEMO)} issues', (199, 46, 15)))
ED.save(os.path.join(OUT, 'screenshot-editor.png'))

# ───────────────────────── 3. quick fix screenshot ─────────────────────────
md5 = next(f for f in DEMO if f['ruleId'] == 'crypto-weak-hash-node')
QF = editor(1600, 760, DEMO_LINES[:16], DEMO, menu=(md5, ['ShieldLocal: Use sha256', 'ShieldLocal: Ignore this finding (adds comment)', 'ShieldLocal: Disable rule "crypto-weak-hash-node" in this workspace']),
            bulb=md5['line'], status=(f'{len(DEMO)} issues', (199, 46, 15)))
QF.save(os.path.join(OUT, 'screenshot-quickfix.png'))

# ───────────────────────── 4. dashboard ─────────────────────────
def dashboard():
    W, H = 1600, 1040
    img = Image.new('RGBA', (W, H), (30, 30, 30, 255))
    d = ImageDraw.Draw(img)
    S = SCAN['summary']
    card = (37, 43, 56)
    d.polygon(shield_poly(54, 52, 22), outline=TEAL, width=3) if False else None
    img.alpha_composite(draw_logo(52, bg=False), (30, 26))
    d.text((96, 26), 'ShieldLocal', font=F(26, True), fill=(255, 255, 255))
    d.text((96, 60), 'Offline security scanner', font=F(14), fill=(150, 150, 150))
    for i, (t, primary) in enumerate((('Scan workspace', True), ('Export SARIF', False), ('Export report', False))):
        w = int(F(14).getlength(t)) + 34
        x = W - 40 - sum(int(F(14).getlength(a)) + 34 + 10 for a, _ in (('Scan workspace', 1), ('Export SARIF', 1), ('Export report', 1))[i:])
        d.rounded_rectangle((x, 30, x + w, 66), 7, fill=(14, 99, 156) if primary else None, outline=None if primary else (90, 90, 90))
        d.text((x + 17, 40), t, font=F(14), fill=(255, 255, 255))
    def panel(box, title):
        d.rounded_rectangle(box, 14, fill=card, outline=(70, 76, 90))
        d.text((box[0] + 22, box[1] + 18), title.upper(), font=F(12, True), fill=(150, 160, 175))
    # score
    panel((30, 100, 340, 370), 'Security score')
    cx, cy, r = 185, 255, 70
    d.arc((cx - r, cy - r, cx + r, cy + r), 0, 360, fill=(70, 76, 90), width=14)
    col = TEAL if S['score'] >= 80 else SEV['medium'] if S['score'] >= 55 else SEV['critical']
    d.arc((cx - r, cy - r, cx + r, cy + r), -90, -90 + 360 * S['score'] / 100, fill=col, width=14)
    d.text((cx, cy - 8), str(S['score']), font=F(46, True), fill=(255, 255, 255), anchor='mm')
    d.text((cx, cy + 32), '/ 100', font=F(14), fill=(150, 160, 175), anchor='mm')
    d.text((cx, 345), f"Grade {S['grade']}  -  {S['total']} findings", font=F(14), fill=(190, 195, 205), anchor='mm')
    def bars(box, title, data, colors):
        panel(box, title)
        mx = max(1, max(data.values()))
        for i, (k, v) in enumerate(data.items()):
            y = box[1] + 58 + i * 38
            d.text((box[0] + 22, y), k, font=F(14), fill=(204, 204, 204))
            tx, tw = box[0] + 130, box[2] - box[0] - 200
            d.rounded_rectangle((tx, y + 4, tx + tw, y + 14), 5, fill=(62, 68, 82))
            d.rounded_rectangle((tx, y + 4, tx + max(10, tw * v / mx), y + 14), 5, fill=colors[i % len(colors)] if isinstance(colors, list) else colors[k])
            d.text((box[2] - 24, y), str(v), font=F(14), fill=(204, 204, 204), anchor='ra')
    bars((360, 100, 960, 370), 'By severity', {k: S['bySeverity'][k] for k in ('critical', 'high', 'medium', 'low', 'info')}, SEV)
    cats = dict(sorted(S['byCategory'].items(), key=lambda kv: -kv[1])[:5])
    bars((980, 100, 1570, 370), 'By category', cats, [TEAL, BLUE, (167, 139, 250), (244, 114, 182), SEV['medium'], SEV['high']])
    # table
    panel((30, 390, 1570, 1010), 'Findings')
    x = 52
    chips = [('critical', S['bySeverity']['critical']), ('high', S['bySeverity']['high']), ('medium', S['bySeverity']['medium']), ('low', S['bySeverity']['low'])]
    for k, n in chips:
        t = f'{k} {n}'
        w = int(F(13).getlength(t)) + 26
        d.rounded_rectangle((x, 430, x + w, 458), 14, fill=(14, 99, 156))
        d.text((x + 13, 437), t, font=F(13), fill=(255, 255, 255)); x += w + 8
    d.rounded_rectangle((x + 10, 430, 1548, 458), 7, fill=(60, 60, 60), outline=(90, 90, 90))
    d.text((x + 24, 436), 'Filter by file, rule or text...', font=F(13), fill=(150, 150, 150))
    heads = (('SEVERITY', 52), ('ISSUE', 190), ('LOCATION', 900), ('REF', 1330))
    for t, hx in heads: d.text((hx, 480), t, font=F(11, True), fill=(140, 150, 165))
    d.line((46, 504, 1554, 504), fill=(70, 76, 90))
    rows = []
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    for fl in SCAN['files']:
        for f in fl['findings']: rows.append((fl['file'], f))
    rows.sort(key=lambda r: (order[r[1]['severity']], r[0], r[1]['line']))
    for i, (file, f) in enumerate(rows[:12]):
        y = 516 + i * 40
        c = SEV[f['severity']]
        d.rounded_rectangle((52, y + 3, 52 + int(F(12, True).getlength(f['severity'])) + 22, y + 25), 11, fill=c)
        d.text((63, y + 6), f['severity'], font=F(12, True), fill=(11, 18, 32))
        d.text((190, y + 3), f['title'], font=F(14, True), fill=(235, 235, 235))
        d.text((900, y + 4), f"{file}:{f['line'] + 1}", font=F(13, mono=True), fill=(160, 165, 175))
        ref = f"CWE-{f['cwe']}" if f.get('cwe') else f.get('advisory', '')
        d.text((1330, y + 4), ref or '', font=F(13), fill=(160, 165, 175))
        d.line((46, y + 34, 1554, y + 34), fill=(52, 58, 72))
    return img.convert('RGB')
dashboard().save(os.path.join(OUT, 'screenshot-dashboard.png'))

# ───────────────────────── 5. sidebar tree ─────────────────────────
def sidebar_img():
    W, H = 760, 980
    img = Image.new('RGBA', (W, H), (37, 37, 38, 255))
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, 56, H), fill=(51, 51, 51))
    d.line((0, 2, 0, 56), fill=(255, 255, 255), width=3)
    d.polygon(shield_poly(28, 30, 15), outline=(255, 255, 255)); d.line([(22, 30), (27, 36), (36, 24)], fill=(255, 255, 255), width=2)
    x0 = 56
    d.text((x0 + 18, 18), 'SHIELDLOCAL', font=F(13), fill=(190, 190, 190))
    d.text((x0 + 18, 56), 'v  SECURITY FINDINGS', font=F(12, True), fill=(220, 220, 220))
    y = 96
    groups = {}
    for fl in SCAN['files']:
        for f in fl['findings']: groups.setdefault(f['severity'], []).append((fl['file'], f))
    for sev in ('critical', 'high', 'medium', 'low'):
        items = groups.get(sev, [])
        if not items: continue
        d.text((x0 + 18, y), 'v', font=F(14), fill=(200, 200, 200))
        d.ellipse((x0 + 44, y + 4, x0 + 58, y + 18), fill=SEV[sev])
        d.text((x0 + 70, y), sev.capitalize(), font=F(15, True), fill=(235, 235, 235))
        d.text((W - 40, y), str(len(items)), font=F(14), fill=(160, 160, 160), anchor='ra')
        y += 34
        for file, f in items[:6]:
            d.ellipse((x0 + 62, y + 7, x0 + 72, y + 17), fill=SEV[sev])
            d.text((x0 + 86, y), f['title'][:34], font=F(14), fill=(215, 215, 215))
            tx = x0 + 86 + F(14).getlength(f['title'][:34]) + 10
            d.text((tx, y + 1), f"{file}:{f['line'] + 1}", font=F(12), fill=(125, 125, 125))
            y += 30
        y += 8
    return img.convert('RGB')
sidebar_img().save(os.path.join(OUT, 'screenshot-sidebar.png'))

# ───────────────────────── 6. banner ─────────────────────────
def banner():
    W, H = 1600, 640
    img = gradient(W, H, (9, 16, 30), (14, 30, 54), diag=True).convert('RGBA')
    glow = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse((-200, 250, 600, 900), fill=(52, 211, 180, 60)); gd.ellipse((900, -250, 1700, 350), fill=(59, 130, 246, 70))
    img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(120)))
    grid = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    gd2 = ImageDraw.Draw(grid)
    for x in range(0, W, 64): gd2.line((x, 0, x, H), fill=(255, 255, 255, 9))
    for y in range(0, H, 64): gd2.line((0, y, W, y), fill=(255, 255, 255, 9))
    img.alpha_composite(grid)
    d = ImageDraw.Draw(img)
    img.alpha_composite(draw_logo(190), (90, 90))
    d = ImageDraw.Draw(img)
    d.text((310, 100), 'ShieldLocal', font=F(78, True), fill=(255, 255, 255))
    d.text((314, 196), 'Offline security scanner for VS Code', font=F(29), fill=(170, 190, 215))
    d.text((92, 330), 'Catch secrets, injection flaws, weak crypto and', font=F(26), fill=(215, 225, 240))
    d.text((92, 368), 'vulnerable dependencies while you type.', font=F(26), fill=(215, 225, 240))
    x = 92
    for t, c in (('Secrets', SEV['critical']), ('Injection', SEV['high']), ('Crypto', SEV['medium']), ('Dependencies', SEV['low']), ('SARIF', TEAL)):
        w = int(F(18, True).getlength(t)) + 36
        d.rounded_rectangle((x, 440, x + w, 482), 21, outline=c, width=2)
        d.text((x + 18, 450), t, font=F(18, True), fill=c); x += w + 12
    d.text((92, 530), '77 rules  -  quick fixes  -  dashboard  -  100% offline', font=F(20), fill=(130, 150, 180))
    # code card (cropped from the real editor render)
    crop = editor(764, 520, DEMO_LINES[5:19], [dict(f, line=f['line'] - 5) for f in DEMO if f['line'] >= 5], fs=16, lh=27,
                  hover=dict(sql, line=sql['line'] - 5), status=(f'{len(DEMO)} issues', (199, 46, 15)), hover_w=470)
    cx, cy = 870, 70
    crop = crop.crop((56, 0, 764, 520)).convert('RGBA')
    m = Image.new('L', crop.size, 0)
    ImageDraw.Draw(m).rounded_rectangle((0, 0, crop.width - 1, crop.height - 1), 18, fill=255)
    shadow(img, (cx, cy, cx + crop.width, cy + crop.height), 18, 30, (0, 18), 200)
    img.paste(crop, (cx, cy), m)
    return img.convert('RGB')
banner().save(os.path.join(OUT, 'banner.png'))

# ───────────────────────── 7. animated demo GIF ─────────────────────────
def gif():
    W, H = 1180, 640
    base = [l for l in DEMO_LINES[:3]] + ['', 'app.get("/user", (req, res) => {']
    target = '  const digest = crypto.createHash("md5").update(req.query.p);'
    frames, durs = [], []
    def add(img, ms): frames.append(img); durs.append(ms)
    L = 5  # target line index
    def mk(code, fnds=(), **kw):
        lines = base + [code] + ['});'] if True else None
        return editor(W, H, lines, list(fnds), fs=19, lh=30, tab='demo.js', **kw)
    clean = (  'Clean', (0, 122, 204))
    for n in (0, 8, 20, 34, len(target)):
        add(mk(target[:n], status=clean, cursor=(L, n)), 90 if n < len(target) else 700)
    fnd = {'ruleId': 'crypto-weak-hash-node', 'title': 'Weak hash (MD5/SHA-1)', 'severity': 'medium', 'line': L,
           'col': target.index('createHash'), 'endCol': target.index('createHash') + len('createHash("md5")'),
           'message': 'MD5 and SHA-1 are broken for security purposes.', 'remediation': 'Use SHA-256 or stronger (and bcrypt/argon2 for passwords).', 'cwe': 327}
    warn = ('1 issue', (122, 92, 0))
    add(mk(target, [fnd], status=warn), 1000)
    add(mk(target, [fnd], status=warn, hover=fnd), 2200)
    add(mk(target, [fnd], status=warn, bulb=L, menu=(fnd, ['ShieldLocal: Use sha256', 'ShieldLocal: Ignore this finding (adds comment)', 'ShieldLocal: Disable rule in this workspace'])), 2200)
    fixed = target.replace('"md5"', '"sha256"')
    add(mk(fixed, status=clean), 2600)
    pal = [f.convert('P', palette=Image.ADAPTIVE, colors=128) for f in frames]
    pal[0].save(os.path.join(OUT, 'demo.gif'), save_all=True, append_images=pal[1:], duration=durs, loop=0, optimize=True)
gif()
print('images written to', OUT)
for f in sorted(os.listdir(OUT)):
    print(f'  {f:28s} {os.path.getsize(os.path.join(OUT, f)) // 1024} KB')
