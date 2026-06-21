"""
FTLC3351/3352R3PL1 — Validator  v1.0
EPS Global · Validação independente / em massa de unidades já encodadas
Autossuficiente: extrai identidade do próprio dump, recalcula o patch esperado
e confere contra os valores-alvo conhecidos. Não depende de sessão do Encoder.
"""

import streamlit as st
import hashlib, struct, binascii, re

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — mesmos valores-alvo validados no Field Encoder
# ─────────────────────────────────────────────────────────────────────────────
CISCO_KEYS = {
    0x0E: bytes.fromhex("4AF86716ED1E2F347CA13C9978AD8CA0"),
    0x02: bytes.fromhex("8DDAE6A46EC9DEF6100BF185059C3DAB"),
    0x06: bytes.fromhex("175258fee9b4f0d9eab6006f7c65a8cb"),
    0x08: bytes.fromhex("30DB1EE9C7913AE5A3C8161B574A9FF6"),
    0x11: bytes.fromhex("E14869FDA81B1C212D715E3BC1371D75"),
}
VENDOR_NAME = b"CISCO-FINISAR   "

TARGET_B81 = 0xCF   # Power Class
TARGET_B93 = 0x0D   # Device Technology
LP_TARGETS = {0x69: 0x01, 0x6A: 0x1F, 0x6B: 0x37, 0x71: 0x0E}
B0_TARGETS = {0x80: 0x01, 0x81: 0x01}
TARGET_P1E_FD = 0x02 # Page 1Eh:0xFD ModulePowerClassOverride — confirmado em unidade -8dBm real funcionando
TARGET_P1E_FLEXTUNE_EN   = 0x01 # Page 1Eh:0xC8 FlexTuneEnable — padrão Apticom (configurável conforme preferência do cliente)
TARGET_P1E_FLEXTUNE_GRID = 0x05 # Page 1Eh:0xCB FlexTuneGrid — 0101b = 100GHz, padrão Apticom

PAGE02_FIXED = bytes([
    0x49,0x4E,0x55,0x49,0x41,0x4B,0x44,0x45,0x41,0x41,0x31,0x30,0x2D,0x33,0x32,0x34,
    0x38,0x2D,0x30,0x31,0x56,0x30,0x31,0x20,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xAA,0xAA,
    0x51,0x53,0x46,0x50,0x2D,0x31,0x30,0x30,0x47,0x2D,0x5A,0x52,0x2D,0x53,0x20,0x20,
    0x20,0x20,0x20,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x58,
    0x36,0x34,0x31,0x33,0x34,0x34,0x31,0x31,0x00,0x98,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
])

# ─────────────────────────────────────────────────────────────────────────────
# PARSER (idêntico ao Field Encoder)
# ─────────────────────────────────────────────────────────────────────────────
def parse_dump(text: str) -> dict:
    pages = {}
    current_page = None
    for line in text.splitlines():
        line = line.strip()
        pm = re.match(r"Page\s*:\s*([0-9A-Fa-f]+)h", line)
        if pm:
            current_page = int(pm.group(1), 16)
            pages[current_page] = {}
            continue
        if "Lower Memory" in line:
            current_page = "lower"
            pages[current_page] = {}
            continue
        if "Page Not Valid" in line:
            current_page = None
            continue
        hm = re.match(r"\s*([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s*){1,16})", line)
        if hm and current_page is not None:
            base = int(hm.group(1), 16)
            for i, v in enumerate(hm.group(2).split()):
                pages[current_page][base + i] = int(v, 16)
    return pages

def asc(p, start, n):
    return bytes([p.get(start+i, 0x20) for i in range(n)]).decode("ascii","replace")

def page_to_bytes128(page: dict, base: int) -> bytes:
    return bytes([page.get(base+i, 0x00) for i in range(128)])

def calc_ccbase(page: dict) -> int:
    return sum(page.get(i,0) for i in range(128,191)) & 0xFF

def calc_ccext(page: dict) -> int:
    return sum(page.get(i,0) for i in range(192,223)) & 0xFF

def calc_cisco_patch(sn_16: bytes, manu_id: int):
    if manu_id not in CISCO_KEYS:
        return None, None
    magic   = CISCO_KEYS[manu_id]
    payload = bytes([manu_id]) + VENDOR_NAME + sn_16 + magic
    md5     = hashlib.md5(payload).digest()
    window  = bytes([0x00,0x00,manu_id,md5[0]]) + md5[1:16] + bytes(9)
    crc32   = struct.pack("<I", binascii.crc32(window) & 0xFFFFFFFF)
    return md5, crc32

# ─────────────────────────────────────────────────────────────────────────────
# CORE VALIDATION — autossuficiente, não depende de sessão externa
# ─────────────────────────────────────────────────────────────────────────────
def validate_dump(text: str, expected_channel: tuple = None) -> dict:
    """
    Recebe o texto do dump, retorna um dict com:
      sn, pn, manu_id, checks (lista de tuplas), all_ok (bool), error (str|None)
    expected_channel: (msb, lsb) opcional para conferir Page 12h 0x88/0x89
    """
    pages = parse_dump(text)
    if 0 not in pages or not pages.get(0):
        return {"error": "Page 00h não encontrada ou vazia — arquivo inválido ou incompleto."}

    p0 = pages.get(0,{})
    pb0, plow = pages.get(0xB0,{}), pages.get("lower",{})
    p12, p02 = pages.get(0x12,{}), pages.get(0x02,{})
    p1e = pages.get(0x1E,{})
    # IMPORTANTE: validação sempre lê a Page 00h — é a única página que o switch
    # realmente consulta. Page FFh (quando presente) é só um backup do estado
    # ORIGINAL pré-patch que algumas ferramentas de dump preservam — NUNCA usar
    # para decidir se a unidade está correta.
    upper = p0

    sn = asc(upper,196,16).rstrip()
    pn = asc(upper,168,16).rstrip()
    manu_id = upper.get(226, 0)
    sn_16 = upper.get  # placeholder, real bytes below
    sn_bytes = bytes([upper.get(196+i,0x20) for i in range(16)])

    checks = []

    # ── Estrutura física ────────────────────────────────────────────────
    checks.append(("Power Class (Upper 0x81)", upper.get(129,0)==TARGET_B81,
                    f"0x{upper.get(129,0):02X}", f"0x{TARGET_B81:02X}"))
    checks.append(("Device Technology (Upper 0x93)", upper.get(147,0)==TARGET_B93,
                    f"0x{upper.get(147,0):02X}", f"0x{TARGET_B93:02X}"))
    for addr, target in LP_TARGETS.items():
        cur = plow.get(addr, 0)
        checks.append((f"Lower 0x{addr:02X}", cur==target, f"0x{cur:02X}", f"0x{target:02X}"))
    if pb0:
        for addr, target in B0_TARGETS.items():
            cur = pb0.get(addr, 0)
            checks.append((f"B0h 0x{addr:02X}", cur==target, f"0x{cur:02X}", f"0x{target:02X}"))
    else:
        checks.append(("Page B0h presente", False, "ausente", "presente"))

    if p1e:
        cur_p1e_fd = p1e.get(0xFD, 0)
        checks.append(("ModulePowerClassOverride ⚠️ OBRIGATÓRIO", cur_p1e_fd==TARGET_P1E_FD,
                        f"0x{cur_p1e_fd:02X}", f"0x{TARGET_P1E_FD:02X}"))
        cur_ften = p1e.get(0xC8, 0)
        cur_fgrid = p1e.get(0xCB, 0)
        checks.append(("ℹ️ FlexTuneEnable (informativo, não afeta aprovação)", True,
                        f"0x{cur_ften:02X}", f"ref: 0x{TARGET_P1E_FLEXTUNE_EN:02X}"))
        checks.append(("ℹ️ FlexTuneGrid (informativo, não afeta aprovação)", True,
                        f"0x{cur_fgrid:02X}", f"ref: 0x{TARGET_P1E_FLEXTUNE_GRID:02X} (100GHz)"))
    else:
        checks.append(("ModulePowerClassOverride (Pg1E:0xFD)", False, "Page 1Eh ausente", f"0x{TARGET_P1E_FD:02X}"))

    if expected_channel:
        ch_msb, ch_lsb = expected_channel
        if p12:
            cur_msb, cur_lsb = p12.get(0x88,0), p12.get(0x89,0)
            ch_ok = cur_msb==ch_msb and cur_lsb==ch_lsb
            checks.append(("Canal (Page12h 0x88/0x89)", ch_ok,
                            f"{cur_msb:02X} {cur_lsb:02X}", f"{ch_msb:02X} {ch_lsb:02X}"))
        else:
            checks.append(("Canal (Page12h 0x88/0x89)", False, "Page 12h ausente", f"{ch_msb:02X} {ch_lsb:02X}"))

    # ── Checksums internos ──────────────────────────────────────────────
    ccbase_ok = upper.get(191,0) == calc_ccbase(upper)
    ccext_ok  = upper.get(223,0) == calc_ccext(upper)
    checks.append(("CC_BASE consistente", ccbase_ok, f"0x{upper.get(191,0):02X}", "auto-consistente"))
    checks.append(("CC_EXT consistente", ccext_ok, f"0x{upper.get(223,0):02X}", "auto-consistente"))

    # ── Patch Cisco — recalculado a partir do PRÓPRIO SN gravado ────────
    md5_stored = bytes([upper.get(227+i,0) for i in range(16)])
    crc_stored = bytes([upper.get(252+i,0) for i in range(4)])
    md5_calc, crc_calc = calc_cisco_patch(sn_bytes, manu_id)
    if md5_calc is None:
        checks.append(("Cisco Manu_ID conhecido", False, f"0x{manu_id:02X}", "0x02/06/08/0E/11"))
    else:
        md5_ok = md5_stored == md5_calc
        crc_ok = crc_stored == crc_calc
        checks.append(("Cisco MD5 (auto-consistente c/ SN gravado)", md5_ok,
                        md5_stored.hex().upper()[:16]+"...", "MATCH" if md5_ok else "DIVERGENTE"))
        checks.append(("Cisco CRC32", crc_ok, crc_stored.hex().upper(), crc_calc.hex().upper()))

    # ── Page 02h — CLEI fixo ─────────────────────────────────────────────
    if p02:
        p02_bytes = page_to_bytes128(p02, 128)
        p02_match = p02_bytes == PAGE02_FIXED
        checks.append(("Page 02h (CLEI Cisco)", p02_match, "presente", "MATCH" if p02_match else "DIVERGENTE"))
    else:
        checks.append(("Page 02h (CLEI Cisco)", False, "ausente", "esperado presente"))

    all_ok = all(c[1] for c in checks)
    return {
        "error": None, "sn": sn, "pn": pn, "manu_id": manu_id,
        "checks": checks, "all_ok": all_ok,
    }

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="FTLC Validator", page_icon="✅", layout="wide")
st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#E8E8E8}
[data-testid="stSidebar"]{background:#2A2A2A}
.sec{color:#2E6A9C;font-weight:bold;font-size:15px;border-bottom:2px solid #B42D27;padding-bottom:4px;margin-bottom:12px}
.card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:12px}
.unit-pass{background:#fff;border-left:5px solid #1A5A2A;border-radius:6px;padding:12px 16px;margin-bottom:10px}
.unit-fail{background:#fff;border-left:5px solid #B42D27;border-radius:6px;padding:12px 16px;margin-bottom:10px}
.badge-pass{background:#1A5A2A;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold}
.badge-fail{background:#B42D27;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold}
</style>
""", unsafe_allow_html=True)

ca, cb = st.columns([1,10])
with ca: st.markdown("### ✅")
with cb:
    st.markdown("""
    <h2 style="color:#1A5A2A;margin:0;font-family:Arial">FTLC Validator <span style="font-size:14px;color:#888">v1.0</span></h2>
    <p style="color:#555;margin:0;font-size:13px">EPS Global · Validação independente / em massa · SFF-8636 Rev 2.12</p>
    """, unsafe_allow_html=True)
st.markdown("---")

st.markdown('<div class="sec">📡 Canal esperado (opcional)</div>', unsafe_allow_html=True)
st.caption("Se todas as unidades do lote foram tunadas para o mesmo canal, informe aqui para conferir Page 12h. Deixe em branco para pular essa checagem.")
cc1, cc2 = st.columns(2)
with cc1: ch_msb_in = st.text_input("Byte MSB (0x88)", value="", max_chars=2, placeholder="ex: 00")
with cc2: ch_lsb_in = st.text_input("Byte LSB (0x89)", value="", max_chars=2, placeholder="ex: 06")
expected_channel = None
if ch_msb_in.strip() and ch_lsb_in.strip():
    try:
        expected_channel = (int(ch_msb_in,16)&0xFF, int(ch_lsb_in,16)&0xFF)
    except ValueError:
        st.error("Valores de canal inválidos — use hex de 2 dígitos.")

st.markdown('<div class="sec">📂 Upload — uma ou várias unidades</div>', unsafe_allow_html=True)
files = st.file_uploader("Dumps TXT (pode selecionar vários de uma vez)", type=["txt"],
                          accept_multiple_files=True, key="batch_upload")

if not files:
    st.markdown('<div class="card">Aguardando upload. Pode soltar 1 arquivo para validar uma unidade, ou vários para validar um lote inteiro de uma vez.</div>',
                unsafe_allow_html=True)
    st.stop()

st.markdown("---")
st.markdown('<div class="sec">📊 Resultado</div>', unsafe_allow_html=True)

results = []
for f in files:
    text = f.read().decode("utf-8", errors="replace")
    r = validate_dump(text, expected_channel)
    r["filename"] = f.name
    results.append(r)

n_total = len(results)
n_ok = sum(1 for r in results if not r["error"] and r["all_ok"])
n_fail = n_total - n_ok

m1, m2, m3 = st.columns(3)
m1.metric("Total", n_total)
m2.metric("✅ Aprovadas", n_ok)
m3.metric("❌ Reprovadas", n_fail)

st.markdown("---")

for r in results:
    if r["error"]:
        st.markdown(f'<div class="unit-fail"><b>{r["filename"]}</b> — ❌ ERRO: {r["error"]}</div>',
                     unsafe_allow_html=True)
        continue

    status_cls = "unit-pass" if r["all_ok"] else "unit-fail"
    badge_cls  = "badge-pass" if r["all_ok"] else "badge-fail"
    badge_txt  = "APROVADA" if r["all_ok"] else "REPROVADA"

    with st.expander(f"{'✅' if r['all_ok'] else '❌'}  {r['filename']}  —  SN: {r['sn']}  —  PN: {r['pn']}",
                      expanded=not r["all_ok"]):
        st.markdown(f'<span class="{badge_cls}">{badge_txt}</span>', unsafe_allow_html=True)
        st.markdown(f"**Manu_ID:** `0x{r['manu_id']:02X}`")
        st.markdown("")
        for label, ok, cur, tgt in r["checks"]:
            icon = "✅" if ok else "❌"
            col = "#1A5A2A" if ok else "#B42D27"
            st.markdown(
                f'<div style="display:flex;gap:12px;padding:4px 6px;border-bottom:1px solid #eee;font-size:13px">'
                f'<div style="width:18px">{icon}</div>'
                f'<div style="width:280px;font-weight:600">{label}</div>'
                f'<code style="color:{col};font-size:11px">{cur}</code>'
                f'<span style="color:#999">esperado:</span>'
                f'<code style="font-size:11px">{tgt}</code></div>',
                unsafe_allow_html=True)

# ── Export CSV ────────────────────────────────────────────────────────────────
st.markdown("---")
csv_lines = ["filename,sn,pn,manu_id,status,failed_checks"]
for r in results:
    if r["error"]:
        csv_lines.append(f'{r["filename"]},,,,"ERRO","{r["error"]}"')
        continue
    failed = [c[0] for c in r["checks"] if not c[1]]
    status = "APROVADA" if r["all_ok"] else "REPROVADA"
    csv_lines.append(f'{r["filename"]},{r["sn"]},{r["pn"]},0x{r["manu_id"]:02X},{status},"{"; ".join(failed)}"')
csv_data = "\n".join(csv_lines)
st.download_button("📥 Baixar relatório CSV", data=csv_data, file_name="ftlc_validation_report.csv",
                    mime="text/csv")

st.markdown("---")
st.caption("EPS Global · FTLC Validator v1.0 · Validação autossuficiente — recalcula patch a partir do SN gravado no próprio dump · SFF-8636 Rev 2.12")