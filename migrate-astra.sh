#!/usr/bin/env bash
# =====================================================================
#  Migrare Astra Cesbo → StreamHub
#
#   sudo bash migrate-astra.sh                 # DOAR afișează ce a găsit (nu schimbă nimic)
#   sudo bash migrate-astra.sh --apply         # oprește Astra, pornește StreamHub cu aceleași linkuri
#   sudo bash migrate-astra.sh fisier.lua ...  # citește canalele din fișierele date (în loc de detecție)
#
#  Citește: scripturi Lua (make_channel / make_stream) și astra.conf (JSON, "make_stream").
#  Păstrează: portul și calea fiecărui link HTTP (http://server:4000/hd365), ieșirile UDP,
#  intrările de rezervă. Revenire la Astra: bash /root/astra-rollback.sh
# =====================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Rulează ca root (sudo)."; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
APPLY=0; FILES=()
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n 2,13p "$0"; exit 0 ;;
    *) FILES+=("$a") ;;
  esac
done
command -v python3 >/dev/null || { apt-get update -qq && apt-get install -y -qq python3-minimal >/dev/null; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
PLAN="$WORK/plan.json"

# ---------------------------------------------------------------- detecție + conversie
python3 - "$PLAN" "${FILES[@]}" <<'PYEOF'
import json, os, re, subprocess, sys, glob, collections

plan_path, explicit = sys.argv[1], sys.argv[2:]

def sh(cmd):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout
    except Exception: return ""

# ---------- unde rulează Astra
procs = []          # (pid, cmdline)
for line in sh("ps -eo pid=,args=").splitlines():
    parts = line.strip().split(None, 1)
    if len(parts) < 2: continue
    pid, args = parts
    exe = args.split()[0]
    if os.path.basename(exe) in ("astra", "astra.bin") or re.search(r'(^|/)astra(\s|$)', args.split(" ")[0]):
        procs.append((pid, args))

units = []          # unități systemd
for line in sh("systemctl list-unit-files --type=service --no-legend 2>/dev/null").splitlines():
    u = line.split()[0] if line.split() else ""
    if "astra" in u.lower(): units.append(u)
for line in sh("systemctl list-units --type=service --all --no-legend 2>/dev/null").splitlines():
    w = line.replace("●", " ").split()
    if w and "astra" in w[0].lower() and w[0] not in units: units.append(w[0])
unit_exec = {u: sh(f"systemctl cat {u} 2>/dev/null") for u in units}

autostart = []      # (fișier, linie) din cron / rc.local
cronroot = sh("crontab -l 2>/dev/null")
for l in cronroot.splitlines():
    if "astra" in l and not l.strip().startswith("#"): autostart.append(("crontab root", l))
for f in ["/etc/rc.local", "/etc/crontab"] + glob.glob("/etc/cron.d/*"):
    try:
        for l in open(f, errors="replace"):
            if "astra" in l and not l.strip().startswith("#"): autostart.append((f, l.rstrip("\n")))
    except Exception: pass

# ---------- fișiere de config
cands = []
def add(p):
    p = os.path.abspath(p)
    if os.path.isfile(p) and p not in cands: cands.append(p)

texts = [a for _, a in procs] + list(unit_exec.values()) + [l for _, l in autostart]
cwd_of = {pid: os.path.realpath(f"/proc/{pid}/cwd") for pid, _ in procs if os.path.exists(f"/proc/{pid}/cwd")}
if explicit:
    for f in explicit: add(f)
else:
    for t in texts:
        for tok in re.findall(r'[\w./~-]+\.(?:lua|conf|json)\b', t):
            for base in [""] + list(cwd_of.values()) + ["/etc/astra", "/root"]:
                add(os.path.join(base, os.path.expanduser(tok)))
    for pat in ["/etc/astra/*", "/etc/astra/**/*.lua", "/opt/astra/**/*.lua", "/root/*.lua", "/root/astra/**/*.lua",
                "/home/*/*.lua", "/usr/local/etc/astra/*", "/etc/*.lua"]:
        for p in glob.glob(pat, recursive=True):
            try:
                t = open(p, errors="replace").read(400000)
            except Exception: continue
            if "make_channel" in t or "make_stream" in t: add(p)

# ---------- parsere
def strip_lua_comments(t):
    t = re.sub(r'--\[\[.*?\]\]', '', t, flags=re.S)
    out = []
    for line in t.splitlines():
        res, q, i = "", None, 0
        while i < len(line):
            c = line[i]
            if q:
                res += c
                if c == "\\" and i + 1 < len(line): res += line[i+1]; i += 1
                elif c == q: q = None
            elif c in "\"'": q = c; res += c
            elif line.startswith("--", i): break
            else: res += c
            i += 1
        out.append(res)
    return "\n".join(out)

def block(t, start):           # de la '{' la '}' pereche, ignorând textul din ghilimele
    depth, i, q = 0, start, None
    while i < len(t):
        c = t[i]
        if q:
            if c == "\\": i += 1
            elif c == q: q = None
        elif c in "\"'": q = c
        elif c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return t[start:i+1]
        i += 1
    return None

def strs(b): return [m[1] if m[1] else m[2] for m in re.findall(r'("([^"]*)"|\'([^\']*)\')', b)] if b else []
def field_list(b, name):
    m = re.search(r'\b' + name + r'\s*=\s*\{', b)
    if m: return strs(block(b, m.end() - 1))
    m = re.search(r'\b' + name + r'\s*=\s*("[^"]*"|\'[^\']*\')', b)
    return [m.group(1)[1:-1]] if m else []
def field_str(b, name):
    m = re.search(r'\b' + name + r'\s*=\s*("[^"]*"|\'[^\']*\')', b)
    return m.group(1)[1:-1] if m else ""

def parse_lua(t, src):
    t = strip_lua_comments(t); res = []
    for m in re.finditer(r'\bmake_(channel|stream)\s*\(\s*\{', t):
        b = block(t, m.end() - 1)
        if not b: continue
        en = re.search(r'\benable\s*=\s*(true|false)', b)
        res.append(dict(src=src, name=field_str(b, "name") or field_str(b, "id"), aid=field_str(b, "id"),
                        input=field_list(b, "input"), output=field_list(b, "output"),
                        enable=not (en and en.group(1) == "false"),
                        dynamic=bool(re.search(r'\binput\s*=\s*[A-Za-z_]', b))))
    return res

def parse_json(t, src):
    d = json.loads(t); res = []
    lst = d.get("make_stream") or d.get("streams") or []
    if isinstance(lst, dict): lst = list(lst.values())
    def urls(v):
        out = []
        for x in v or []:
            if isinstance(x, str): out.append(x)
            elif isinstance(x, dict) and x.get("url"): out.append(x["url"])
        return out
    for s in lst:
        if not isinstance(s, dict): continue
        res.append(dict(src=src, name=s.get("name") or s.get("id") or "", aid=s.get("id") or "",
                        input=urls(s.get("input")), output=urls(s.get("output")),
                        enable=s.get("enable", True) is not False, dynamic=False))
    return res

raw = []
for f in cands:
    try: t = open(f, errors="replace").read()
    except Exception: continue
    ts = t.lstrip()
    if ts.startswith("{"):
        try: raw += parse_json(t, f); continue
        except Exception: pass
    raw += parse_lua(t, f)
for t in texts:                # canale scrise direct în linia de comandă (astra -e "make_channel(...)")
    if "make_channel" in t or "make_stream" in t: raw += parse_lua(t, "linia de comandă")

# ---------- conversie
ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
def slug(s): return re.sub(r'[^A-Za-z0-9_-]+', '-', s).strip('-')[:64] or "canal"
channels, warn, ports = [], [], collections.Counter()
seen_ids = set()
for ch in raw:
    label = ch["name"] or ch["aid"] or "?"
    if not ch["enable"]:
        warn.append(f"[{label}] dezactivat în Astra — trecut ca oprit");
    if ch["dynamic"] and not ch["input"]:
        warn.append(f"[{label}] intrare definită prin variabilă Lua — completează intrarea manual în panou")
    ins, notes = [], []
    for u in ch["input"]:
        base, _, opts = u.partition("#")
        sch = base.split("://")[0].lower()
        keepopt = ""
        if opts:
            pm = re.search(r'(?:^|&)pnr=(\d+)', opts)
            if pm: keepopt = "#pnr=" + pm.group(1)       # StreamHub filtrează programul la fel ca Astra
            ign = [o for o in opts.split("&") if o and not o.startswith(("pnr=", "ua=", "timeout=", "sync", "no_reload", "buffer_size", "localaddr=", "socket_size", "renew="))]
            if ign: notes.append(f"opțiuni Astra ignorate pentru {base}: #{'&'.join(ign)}")
        if sch in ("udp", "rtp", "http", "https", "srt", "rtmp"):
            ins.append(base + keepopt)
        else:
            notes.append(f"intrare nesuportată, sărită: {u}")
    paths, udp_out = [], ""
    for u in ch["output"]:
        base = u.partition("#")[0]
        m = re.match(r'^https?://([^/:]*)(?::(\d+))?(/[^?#]*)?', base)
        sch = base.split("://")[0].lower()
        if sch in ("http", "https") and m:
            ports[int(m.group(2) or 80)] += 1
            p = (m.group(3) or "/").strip("/")
            p = re.sub(r'\.ts$', '', p)
            paths.append(p)
        elif sch in ("udp", "rtp") and not udp_out:
            udp_out = base.replace("rtp://", "udp://")
        elif sch in ("udp", "rtp"):
            notes.append(f"ieșire UDP în plus, nu e preluată: {base}")
        else:
            notes.append(f"ieșire nesuportată, sărită: {u}")
    ids = []
    for p in paths:
        last = p.split("/")[-1] if p.startswith("play/") else p
        if ID_RE.match(last): ids.append(last)
        else: notes.append(f"calea /{p} nu poate fi păstrată identic (doar /nume, fără subfoldere)")
    if not ids: ids = [slug(ch["aid"] or ch["name"])]
    for k, cid in enumerate(ids):
        if cid.lower() in seen_ids:
            warn.append(f"[{label}] ID dublat /{cid} — sărit"); continue
        seen_ids.add(cid.lower())
        channels.append(dict(id=cid, name=ch["name"] or cid, enabled=bool(ch["enable"] and ins), inputs=ins,
                             http=True, hls=True, udp=udp_out if k == 0 else "", public=True))
        if not ins: notes.append("fără intrare utilizabilă — canalul e creat oprit")
    warn += [f"[{label}] {n}" for n in notes]

port_list = [p for p, _ in ports.most_common()]
plan = dict(procs=[(pid, a, cwd_of.get(pid, "/")) for pid, a in procs], units=units, autostart=autostart, files=cands, channels=channels, warnings=warn,
            listen=port_list[0] if port_list else 4000, listen_extra=port_list[1:])
json.dump(plan, open(plan_path, "w"), indent=1)

# ---------- raport
print("\n=== Astra găsit ===")
for pid, a in procs: print(f"  proces {pid}: {a[:150]}")
for u in units: print(f"  serviciu systemd: {u}")
for f, l in autostart: print(f"  pornire automată ({f}): {l.strip()[:150]}")
if not (procs or units or autostart): print("  (niciun proces / serviciu Astra găsit)")
print("\n=== Fișiere citite ===")
for f in cands: print("  " + f)
if not cands: print("  (niciunul)")
print(f"\n=== Canale pentru StreamHub ({len(channels)}) ===")
for c in channels:
    st = "" if c["enabled"] else "  [OPRIT]"
    print(f"  :{plan['listen']}/{c['id']:<16} {c['name'][:24]:<24} ← {', '.join(c['inputs']) or '—'}{'  → ' + c['udp'] if c['udp'] else ''}{st}")
print(f"\nPort principal: {plan['listen']}" + (f"   porturi suplimentare: {', '.join(map(str, plan['listen_extra']))}" if plan['listen_extra'] else ""))
if warn:
    print("\n=== Atenție ===")
    for w in warn: print("  - " + w)
if not channels:
    print("\nNu am găsit canale. Rulează cu calea fișierului: sudo bash migrate-astra.sh /cale/config.lua")
    print("sau trimite ieșirea comenzii:  ps -eo args | grep -i [a]stra")
    sys.exit(3)
PYEOF
RC=$?
[ $RC -eq 0 ] || exit $RC

if [ $APPLY -eq 0 ]; then
  echo
  echo "Nu am schimbat nimic. Dacă lista de mai sus e corectă:  sudo bash $0 --apply ${FILES[*]:-}"
  exit 0
fi

# ---------------------------------------------------------------- aplicare
[ -f "$HERE/install-streamhub.sh" ] || { echo "Lipsește $HERE/install-streamhub.sh (rulează din folderul nts-relay)."; exit 1; }
TS=$(date +%Y%m%d-%H%M%S)
RB=/root/astra-rollback.sh
CFG=/etc/streamhub/config.json
mkdir -p /etc/streamhub /root/astra-backup-$TS
BK=/root/astra-backup-$TS

echo; echo "==> Scriu configurația StreamHub…"
python3 - "$PLAN" "$CFG" "$BK" <<'PYEOF'
import json, os, sys, secrets, shutil
plan, cfgp, bk = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
if os.path.exists(cfgp):
    shutil.copy2(cfgp, os.path.join(bk, "streamhub-config.json"))
    cfg = json.load(open(cfgp))
else:
    cfg = {"admin_user": "admin", "admin_pass": secrets.token_urlsafe(9), "tokens": [], "hls_segment": 4, "hls_window": 6, "channels": []}
cfg["listen"] = f":{plan['listen']}"
cfg["listen_extra"] = [f":{p}" for p in plan["listen_extra"]]
have = {c["id"].lower() for c in cfg.get("channels", [])}
added = 0
for c in plan["channels"]:
    if c["id"].lower() not in have:
        cfg.setdefault("channels", []).append(c); added += 1
json.dump(cfg, open(cfgp, "w"), indent=2, ensure_ascii=False)
os.chmod(cfgp, 0o600)
print(f"    {added} canale adăugate în {cfgp}")
PYEOF

echo "==> Opresc Astra (backup în $BK)…"
{
  echo "#!/usr/bin/env bash"
  echo "# Revenire la Astra (generat de migrate-astra.sh la $TS)"
  echo "systemctl stop streamhub; systemctl disable streamhub"
} > "$RB"
for u in $(python3 -c "import json,sys;print(' '.join(json.load(open('$PLAN'))['units']))"); do
  en=$(systemctl is-enabled "$u" 2>/dev/null || true)
  systemctl stop "$u" 2>/dev/null || true
  systemctl disable "$u" 2>/dev/null || true
  echo "    serviciu oprit: $u"
  [ "$en" = "enabled" ] && echo "systemctl enable $u" >> "$RB"
  echo "systemctl start $u" >> "$RB"
done
if crontab -l 2>/dev/null | grep -v '^\s*#' | grep -q astra; then
  crontab -l > "$BK/crontab-root"
  crontab -l | sed '/^\s*#/!{/astra/s/^/#astra-migrat# /}' | crontab -
  echo "    crontab: liniile cu astra comentate"
  echo "crontab $BK/crontab-root" >> "$RB"
fi
for f in /etc/rc.local /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  if grep -v '^\s*#' "$f" | grep -q astra; then
    cp -a "$f" "$BK/$(echo "$f" | tr / _)"
    sed -i '/^\s*#/!{/astra/s/^/#astra-migrat# /}' "$f"
    echo "    $f: liniile cu astra comentate"
    echo "cp -a $BK/$(echo "$f" | tr / _) $f" >> "$RB"
  fi
done
# pornire manuală Astra în rollback (dacă nu era serviciu)
python3 - "$PLAN" >> "$RB" <<'PYEOF'
import json, sys, shlex
p = json.load(open(sys.argv[1]))
if not p["units"]:
    seen = set()
    for _, a, cwd in p["procs"]:
        if (a, cwd) in seen: continue
        seen.add((a, cwd))
        print(f"(cd {shlex.quote(cwd)} && nohup {a} >/dev/null 2>&1 &)")
PYEOF
APIDS=$(python3 -c "import json;print(' '.join(p[0] for p in json.load(open('$PLAN'))['procs']))")
kill $APIDS 2>/dev/null || true
pkill -x astra 2>/dev/null || true; pkill -x astra.bin 2>/dev/null || true
for i in $(seq 1 20); do
  alive=0; for p in $APIDS; do kill -0 "$p" 2>/dev/null && alive=1; done
  pgrep -x astra >/dev/null && alive=1
  [ $alive -eq 0 ] && break; sleep 0.5
done
kill -9 $APIDS 2>/dev/null || true; pkill -9 -x astra 2>/dev/null || true
echo "    Astra oprit"
chmod +x "$RB"
echo "    revenire la Astra oricând:  bash $RB"

echo "==> Instalez / actualizez StreamHub…"
LP=$(python3 -c "import json;print(json.load(open('$CFG'))['listen'].lstrip(':'))")
PORT=$LP bash "$HERE/install-streamhub.sh"

echo; echo "==> Verific canalele (pornesc în câteva secunde)…"
sleep 8
python3 - "$CFG" <<'PYEOF'
import json, sys, urllib.request, time
cfg = json.load(open(sys.argv[1])); port = cfg["listen"].lstrip(":")
ok = bad = 0
for c in cfg["channels"]:
    if not c.get("enabled"): print(f"  —   /{c['id']} (oprit)"); continue
    url = f"http://127.0.0.1:{port}/{c['id']}"
    n = 0
    try:
        r = urllib.request.urlopen(url, timeout=12); t = time.time()
        while time.time() - t < 3:
            d = r.read1(65536)
            if not d: break
            n += len(d)
    except Exception as e:
        pass
    if n > 10000: ok += 1; print(f"  OK  /{c['id']:<16} {n*8/3/1000:7.0f} kb/s")
    else: bad += 1; print(f"  !!  /{c['id']:<16} fără date — vezi eroarea în panou")
print(f"\n{ok} canale OK, {bad} cu probleme.")
PYEOF
echo "Panou: http://$(hostname -I | awk '{print $1}'):$LP/   (login în $CFG)"
echo "Revenire la Astra:  bash $RB"
