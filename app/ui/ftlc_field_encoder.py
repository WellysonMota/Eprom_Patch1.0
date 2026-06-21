"""
FTLC3351/3352R3PL1 — Field Encoding Tool  v0.4
EPS Global · Standalone · SFF-8636 Rev 2.12
Fluxo: Dump único -> Checklist -> Identidade/Patch -> Output -> Verificação Final
"""

import streamlit as st
import hashlib, struct, binascii, re

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
CISCO_KEYS = {
    0x0E: bytes.fromhex("4AF86716ED1E2F347CA13C9978AD8CA0"),
    0x02: bytes.fromhex("8DDAE6A46EC9DEF6100BF185059C3DAB"),
    0x06: bytes.fromhex("175258fee9b4f0d9eab6006f7c65a8cb"),
    0x08: bytes.fromhex("30DB1EE9C7913AE5A3C8161B574A9FF6"),
    0x11: bytes.fromhex("E14869FDA81B1C212D715E3BC1371D75"),
}
KEY_LABELS = {
    0x0E: "0x0E — confirmado FTLC3351/3352",
    0x02: "0x02", 0x06: "0x06", 0x08: "0x08", 0x11: "0x11",
}
VENDOR_NAME = b"CISCO-FINISAR   "
BASE_PN     = "FTLC3351R3PL1-C "
OUI         = [0xAC, 0x80, 0xD6]
EXT_SPEC    = 0x27
TARGET_B81  = 0xCF   # Extended ID — Power Class PC7/5.0W
TARGET_B93  = 0x0D   # Device Technology
TARGET_P1E_FD = 0x02 # Page 1Eh:0xFD ModulePowerClassOverride — confirmado em unidade -8dBm real funcionando (2611W388G); ausente (0x00) nas unidades problema
TARGET_P1E_FLEXTUNE_EN   = 0x01 # Page 1Eh:0xC8 FlexTuneEnable — padrão Apticom (configurável conforme preferência do cliente)
TARGET_P1E_FLEXTUNE_GRID = 0x05 # Page 1Eh:0xCB FlexTuneGrid — 0101b = 100GHz, padrão Apticom

def p1e_fd_meaning(val):
    return {
        0x00: "⚠️ SFF padrão — depende do host setar a bit (estado quebrado típico)",
        0x01: "Bypass TOTAL — ignora o host (mais agressivo, não validado em campo)",
        0x02: "Power Class 5-7 — valor VALIDADO em todas as unidades funcionando",
    }.get(val, f"valor não documentado (0x{val:02X})")
TARGET_BC2  = 0x3D
TARGET_BC3  = 0xDB

LP_DDM_EN   = (0x69, 0x01)
LP_DDM_CAP  = (0x6A, 0x1F)
LP_MAXPWR   = (0x6B, 0x37)
LP_NEARFAR  = (0x71, 0x0E)

B0_LOWMEM   = (0x80, 0x01)   # LowMemConfigSelect
B0_NOMWAVE  = (0x81, 0x01)   # NominalWavelengthControl

# Page 02h — payload FIXO confirmado contra dump real Apticom (SN 2611W388H)
# CLEI "INUIAKDEAA" (QSFP-100G-ZR-S Cisco) — igual para TODAS as unidades FTLC3351/3352
PAGE02_FIXED_HEX = (
    "494E5549414B4445414131302D333234"
    "382D3031563031200100000000000000"
    "00780000000000000000000000000000"
    "00000000000000000000000000AAAA"
    "5153465020313030472D5A522D532020"
    "20202020000000000000000000000058"
    "3634313334343131009800000000000000"
    "0000000000000000000000000000"
).replace(" ", "")
# Rebuild cleanly from verified bytes (avoids hex-string concat errors)
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
assert len(PAGE02_FIXED) == 128

SN_SUFFIXES   = ["Nenhum (SN original)", "-1", "-2", "-3", "-4", "-5", "Manual..."]
PN_SUFFIXES   = ["Nenhum (PN base)", "A", "B", "C", "D", "Manual..."]
PN_SUF_LABELS = ["Nenhum (PN base)",
                 "-A  →  FTLC3351R3PL1-CA", "-B  →  FTLC3351R3PL1-CB",
                 "-C  →  FTLC3351R3PL1-CC", "-D  →  FTLC3351R3PL1-CD",
                 "Manual..."]

# ─────────────────────────────────────────────────────────────────────────────
# PARSER
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

def get_sn(p): return asc(p, 196, 16).rstrip()
def get_pn(p): return asc(p, 168, 16).rstrip()

def pad16(s: str) -> bytes:
    return s.encode("ascii","replace").ljust(16)[:16]

def calc_ccbase(page: dict) -> int:
    return sum(page.get(i,0) for i in range(128,191)) & 0xFF

def calc_ccext(page: dict) -> int:
    return sum(page.get(i,0) for i in range(192,223)) & 0xFF

def calc_cisco_patch(sn_16: bytes, manu_id: int) -> tuple:
    magic   = CISCO_KEYS[manu_id]
    payload = bytes([manu_id]) + VENDOR_NAME + sn_16 + magic
    md5     = hashlib.md5(payload).digest()
    window  = bytes([0x00,0x00,manu_id,md5[0]]) + md5[1:16] + bytes(9)
    crc32   = struct.pack("<I", binascii.crc32(window) & 0xFFFFFFFF)
    return md5, crc32

def build_upper_page(source: dict, sn_final: bytes, pn_final: bytes, manu_id: int) -> dict:
    page = dict(source)
    page[129] = TARGET_B81
    page[147] = TARGET_B93
    for i,b in enumerate(VENDOR_NAME):  page[148+i] = b
    for i,b in enumerate(OUI):          page[165+i] = b
    for i,b in enumerate(pn_final):     page[168+i] = b
    page[191] = calc_ccbase(page)
    page[192] = EXT_SPEC
    page[194] = TARGET_BC2
    page[195] = TARGET_BC3
    for i,b in enumerate(sn_final):     page[196+i] = b
    page[223] = calc_ccext(page)
    md5, crc32 = calc_cisco_patch(sn_final, manu_id)
    page[224] = 0x00;  page[225] = 0x00
    page[226] = manu_id
    page[227] = md5[0]
    for i,b in enumerate(md5[1:16]):    page[228+i] = b
    page[243] = 0x00
    for i in range(8):                  page[244+i] = 0x00
    for i,b in enumerate(crc32):        page[252+i] = b
    return page

def build_lower_page(source: dict) -> dict:
    page = dict(source)
    for addr, val in [LP_DDM_EN, LP_DDM_CAP, LP_MAXPWR, LP_NEARFAR]:
        page[addr] = val
    return page

def page_to_bytes128(page: dict, base: int) -> bytes:
    return bytes([page.get(base+i, 0x00) for i in range(128)])

# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def status_row(label, addr_label, current_hex, target_hex, ok, note=""):
    icon = "✅" if ok else "⚠️"
    bg = "#f0fff4" if ok else "#fff8e8"
    bd = "#1A5A2A" if ok else "#c47c00"
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:10px;padding:7px 12px;'
        f'background:{bg};border-left:3px solid {bd};border-radius:4px;margin-bottom:4px;font-size:13px">'
        f'<div style="width:18px">{icon}</div>'
        f'<div style="width:230px;font-weight:600;color:#333">{label}</div>'
        f'<div style="width:130px;color:#888;font-family:monospace;font-size:11px">{addr_label}</div>'
        f'<code style="background:#f4f4f4;padding:2px 6px;border-radius:3px;color:#666;font-size:11px">{current_hex}</code>'
        f'<span style="color:#999">→</span>'
        f'<code style="background:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px">{target_hex}</code>'
        f'<div style="color:#777;font-size:11px;margin-left:8px">{note}</div>'
        f'</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG & CSS
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="FTLC Field Encoder v0.4", page_icon="🔧", layout="wide")
st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#E8E8E8}
[data-testid="stSidebar"]{background:#2A2A2A}
.stButton>button{background:#B42D27;color:#fff;border:none;font-weight:bold;padding:6px 18px;border-radius:4px}
.stButton>button:hover{background:#8a1f1b}
.hex-out{font-family:'Roboto Mono',monospace;font-size:11px;background:#1a1a2e;color:#00ff88;
  padding:14px;border-radius:6px;word-break:break-all;line-height:1.8;letter-spacing:.5px}
.hex-out-lp{font-family:'Roboto Mono',monospace;font-size:11px;background:#0d1f0d;color:#7fff7f;
  padding:14px;border-radius:6px;word-break:break-all;line-height:1.8;letter-spacing:.5px}
.hex-out-p2{font-family:'Roboto Mono',monospace;font-size:11px;background:#0d1a2e;color:#7fc8ff;
  padding:14px;border-radius:6px;word-break:break-all;line-height:1.8;letter-spacing:.5px}
.card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:12px}
.sec{color:#2E6A9C;font-weight:bold;font-size:15px;border-bottom:2px solid #B42D27;padding-bottom:4px;margin-bottom:12px}
.sec-final{color:#fff;font-weight:bold;font-size:16px;background:#B42D27;padding:10px 16px;border-radius:6px;margin-bottom:16px}
.sec-verify{color:#fff;font-weight:bold;font-size:16px;background:#1A5A2A;padding:10px 16px;border-radius:6px;margin-bottom:16px}
.info-box{background:#f0f4ff;border-left:4px solid #2E6A9C;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.ok-box{background:#f0fff4;border-left:4px solid #1A5A2A;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.warn-box{background:#fff3f3;border-left:4px solid #B42D27;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.preview{font-family:monospace;background:#2A2A2A;color:#00ff88;padding:5px 12px;border-radius:4px;font-size:13px;letter-spacing:1px}
.output-block{background:#fff;border:2px solid #2E6A9C;border-radius:8px;padding:16px;margin-bottom:16px}
.output-title{color:#2E6A9C;font-weight:bold;font-size:14px;margin-bottom:8px}
.final-banner-ok{background:#1A5A2A;color:#fff;text-align:center;font-size:20px;font-weight:bold;
  padding:18px;border-radius:8px;letter-spacing:1px;margin:16px 0}
.final-banner-fail{background:#B42D27;color:#fff;text-align:center;font-size:20px;font-weight:bold;
  padding:18px;border-radius:8px;letter-spacing:1px;margin:16px 0}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
ca, cb = st.columns([1,10])
with ca: st.markdown("### 🔧")
with cb:
    st.markdown("""
    <h2 style="color:#B42D27;margin:0;font-family:Arial">
      FTLC Field Encoder <span style="font-size:14px;color:#888">v0.4</span></h2>
    <p style="color:#555;margin:0;font-size:13px">
      EPS Global · FTLC3351/3352R3PL1 → Cisco Nexus · SFF-8636 Rev 2.12 · Fluxo dump único</p>
    """, unsafe_allow_html=True)
st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
# 1 — UPLOAD (dump único)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📂 1 — Upload do Dump TXT</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Cisco I2C Memory Dump (.txt)", type=["txt"], key="main_upload")
if not uploaded:
    st.markdown("""<div class="info-box">
    Fluxo: <b>dump no switch</b> → upload aqui → checklist → identidade/patch → gerar strings →
    gravar no IDE Coherent → reinserir módulo → <b>verificação final</b> no fim desta página.
    </div>""", unsafe_allow_html=True)
    st.stop()

text  = uploaded.read().decode("utf-8", errors="replace")
pages = parse_dump(text)
if 0 not in pages:
    st.error("Page 00h não encontrada. Verificar arquivo."); st.stop()

p0, pfff, pb0, plow = pages.get(0,{}), pages.get(0xFF,{}), pages.get(0xB0,{}), pages.get("lower",{})
p12 = pages.get(0x12, {})
p1e = pages.get(0x1E, {})
src_upper = pfff if pfff else p0
src_lower = plow

sn_orig = get_sn(pfff) if pfff else get_sn(p0)
pn_orig = get_pn(pfff) if pfff else get_pn(p0)
fw_maj  = pb0.get(0xD0,0); fw_min = pb0.get(0xD1,0)
is_3352 = "3352" in pn_orig; is_3351 = "3351" in pn_orig
b0_present  = len(pb0) > 0
p12_present = len(p12) > 0
p1e_present = len(p1e) > 0

# ─────────────────────────────────────────────────────────────────────────────
# 2 — MODULE INFO
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔎 2 — Informações do Módulo</div>', unsafe_allow_html=True)
mi1, mi2 = st.columns(2)
with mi1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Identidade original**")
    st.markdown(f"SN: `{sn_orig}` &nbsp;&nbsp; PN: `{pn_orig}`")
    st.markdown(f"FW: `{fw_maj}.{fw_min:02d}`" + (" " if b0_present else "  ⚠️ Page B0h ausente no dump"))
    if is_3352: st.markdown("ℹ️ **FTLC3352R3PL1** — 0 dBm High Power")
    elif is_3351: st.markdown("ℹ️ **FTLC3351R3PL1** — -8 dBm")
    st.markdown('</div>', unsafe_allow_html=True)
with mi2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Páginas detectadas no dump**")
    pg_list = ", ".join(sorted(
        ([ "Lower" ] if plow else []) +
        ([ "00h" ] if p0 else []) + ([ "FFh" ] if pfff else []) +
        ([ "B0h" ] if pb0 else []) + ([ "12h" ] if p12 else [])
    ))
    st.markdown(pg_list if pg_list else "—")
    if not p12_present:
        st.markdown("⚠️ Page 12h ausente — canal atual não pôde ser lido (você ainda pode digitar o alvo abaixo)")
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 3 — CHECKLIST DE AJUSTES (diagnóstico, current vs target)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📋 3 — Checklist de Ajustes</div>', unsafe_allow_html=True)

cur_129 = src_upper.get(129, 0)
cur_147 = src_upper.get(147, 0)
cur_6b  = src_lower.get(0x6B, 0)
cur_69  = src_lower.get(0x69, 0)
cur_6a  = src_lower.get(0x6A, 0)
cur_71  = src_lower.get(0x71, 0)
cur_b0_80 = pb0.get(0x80, None)
cur_b0_81 = pb0.get(0x81, None)
cur_ch_msb = p12.get(0x88, None)
cur_ch_lsb = p12.get(0x89, None)

st.markdown("**✅ Automático — já incluído na string da seção 6 (Upper Page)**")
st.caption("Não precisa gravar nada manualmente para estes campos — basta colar a string da Upper Page.")
status_row("Power Class (Extended ID)", "Upper 0x81 (129)", f"0x{cur_129:02X}", "0xCF", cur_129==0xCF)
status_row("Device Technology", "Upper 0x93 (147)", f"0x{cur_147:02X}", "0x0D", cur_147==0x0D)

st.markdown("")
st.markdown("**✋ Manual — gravar separadamente no IDE**")
st.caption("Lower Page inteira (gravação manual nesta fase) + registros isolados em B0h/Page12h que não fazem parte de nenhuma string.")
status_row("Max Power", "Lower 0x6B (107)", f"0x{cur_6b:02X}", "0x37 (5.5W)", cur_6b==0x37)
status_row("DDM Enable", "Lower 0x69 (105)", f"0x{cur_69:02X}", "0x01", cur_69==0x01)
status_row("DDM Capabilities", "Lower 0x6A (106)", f"0x{cur_6a:02X}", "0x1F", cur_6a==0x1F)
status_row("Near/Far End", "Lower 0x71 (113)", f"0x{cur_71:02X}", "0x0E", cur_71==0x0E)
status_row("LowMemConfigSelect", "B0h 0x80 (128)",
           f"0x{cur_b0_80:02X}" if cur_b0_80 is not None else "—", "0x01",
           cur_b0_80==0x01, "" if b0_present else "(B0h ausente no dump)")
status_row("NominalWavelengthControl", "B0h 0x81 (129)",
           f"0x{cur_b0_81:02X}" if cur_b0_81 is not None else "—", "0x01",
           cur_b0_81==0x01, "" if b0_present else "(B0h ausente no dump)")
cur_p1e_fd = p1e.get(0xFD, None)
status_row("ModulePowerClassOverride ⚠️ OBRIGATÓRIO", "Page 1Eh 0xFD (253)",
           f"0x{cur_p1e_fd:02X}" if cur_p1e_fd is not None else "—", f"0x{TARGET_P1E_FD:02X}",
           cur_p1e_fd==TARGET_P1E_FD, "" if p1e_present else "(Page 1Eh ausente no dump)")
cur_p1e_ften = p1e.get(0xC8, None)
status_row("FlexTuneEnable (configurável c/ cliente)", "Page 1Eh 0xC8 (200)",
           f"0x{cur_p1e_ften:02X}" if cur_p1e_ften is not None else "—", f"0x{TARGET_P1E_FLEXTUNE_EN:02X}",
           cur_p1e_ften==TARGET_P1E_FLEXTUNE_EN, "" if p1e_present else "(Page 1Eh ausente no dump)")
cur_p1e_fgrid = p1e.get(0xCB, None)
status_row("FlexTuneGrid (configurável c/ cliente)", "Page 1Eh 0xCB (203)",
           f"0x{cur_p1e_fgrid:02X}" if cur_p1e_fgrid is not None else "—", f"0x{TARGET_P1E_FLEXTUNE_GRID:02X} (100GHz)",
           cur_p1e_fgrid==TARGET_P1E_FLEXTUNE_GRID, "" if p1e_present else "(Page 1Eh ausente no dump)")
ch_cur_str = f"{cur_ch_msb:02X} {cur_ch_lsb:02X}" if (cur_ch_msb is not None and cur_ch_lsb is not None) else "—"
status_row("Canal (definido na seção 4)", "Page12h 0x88/0x89", ch_cur_str, "ver seção 4 ↓", False,
           "" if p12_present else "(Page 12h ausente no dump)")

# ─────────────────────────────────────────────────────────────────────────────
# 4 — CANAL (input manual)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📡 4 — Canal — Page 12h, endereços 0x88 / 0x89</div>', unsafe_allow_html=True)
st.markdown('<div class="card">', unsafe_allow_html=True)
st.caption("Valor de 2 bytes documentado pela Coherent por canal. Ex: 00 06 = canal 37 (193.70 THz). Apenas estes 2 bytes são escritos — nunca a página inteira.")
cc1, cc2, cc3 = st.columns([1,1,2])
with cc1:
    ch_msb_in = st.text_input("Byte MSB (0x88)", value="00", max_chars=2, help="Hex, 2 dígitos")
with cc2:
    ch_lsb_in = st.text_input("Byte LSB (0x89)", value="06", max_chars=2, help="Hex, 2 dígitos")
with cc3:
    ch_label = st.text_input("Canal / Frequência (apenas anotação, opcional)", value="Canal 37 — 193.70 THz")

try:
    ch_msb_val = int(ch_msb_in, 16) & 0xFF
    ch_lsb_val = int(ch_lsb_in, 16) & 0xFF
    ch_valid = True
except ValueError:
    ch_msb_val = ch_lsb_val = 0
    ch_valid = False
    st.error("Valor de canal inválido — use hex de 2 dígitos (ex: 00, 06, 1A)")

if ch_valid:
    st.markdown(f"**Gravar em Page 12h:** byte 0x88 = `0x{ch_msb_val:02X}` &nbsp;&nbsp; byte 0x89 = `0x{ch_lsb_val:02X}` &nbsp;&nbsp; ({ch_label})")
st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 5 — IDENTIDADE & PATCH CISCO
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔑 5 — Identidade & Patch Cisco</div>', unsafe_allow_html=True)
id1, id2, id3 = st.columns(3)

with id1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Serial Number**")
    st.caption(f"Detectado: `{sn_orig}`")
    sn_sel = st.selectbox("Sufixo SN", SN_SUFFIXES, index=0)
    sn_manual = ""
    if sn_sel == "Manual...":
        sn_manual = st.text_input("SN completo (manual)", value=sn_orig, max_chars=16)
    if sn_sel == "Manual...": sn_final_str = sn_manual[:16]
    elif sn_sel == "Nenhum (SN original)": sn_final_str = sn_orig
    else: sn_final_str = (sn_orig + sn_sel)[:16]
    sn_16 = pad16(sn_final_str)
    sn_disp = sn_16.decode("ascii","replace")
    st.markdown(f"**Final:** <span class='preview'>{sn_disp}</span>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with id2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Part Number**")

    # Deriva o modelo a partir do PN ORIGINAL (Page FFh se presente, senão Page 00h),
    # removendo qualquer sufixo "-C"/"-CX" que já possa estar lá (ex: dump de unidade
    # que já passou por uma tentativa de encoding anterior).
    pn_model_detected = pn_orig.strip()
    for suf in [f"-C{l}" for l in "ABCD"] + ["-C"]:
        if pn_model_detected.endswith(suf):
            pn_model_detected = pn_model_detected[:-len(suf)]
            break
    if not pn_model_detected:
        pn_model_detected = "FTLC3351R3PL1"  # fallback se dump não tiver PN legível
        st.warning("PN não detectado no dump — usando fallback FTLC3351R3PL1")

    lock_3351 = st.checkbox("Travar em FTLC3351R3PL1 (padrão Apticom, mesmo em unidades 3352)",
                             value=False,
                             help="Apticom grava sempre '3351' no PN, mesmo em hardware 3352 — "
                                  "PN não afeta o DSP, é só autenticação. Desmarcado = usa o modelo "
                                  "real detectado na Page FFh.")
    pn_model_base = "FTLC3351R3PL1" if lock_3351 else pn_model_detected

    if pn_model_base != pn_model_detected:
        st.caption(f"Detectado na Page FFh: `{pn_model_detected}` → travado para `{pn_model_base}`")
    else:
        st.caption(f"Base detectada (Page FFh): `{pn_model_detected}`")

    base_with_c = (pn_model_base + "-C")[:15]
    pn_suf_labels_dyn = ["Nenhum (PN base)"] + [
        f"-{l}  →  {base_with_c}{l}" for l in "ABCD"
    ] + ["Manual..."]

    pn_suf_idx = st.selectbox("Sufixo PN", options=range(len(PN_SUFFIXES)),
                               format_func=lambda i: pn_suf_labels_dyn[i], index=0)
    pn_sel = PN_SUFFIXES[pn_suf_idx]
    pn_manual = ""
    if pn_sel == "Manual...":
        pn_manual = st.text_input("PN completo (manual)", value=base_with_c, max_chars=16)
    if pn_sel == "Manual...": pn_final_str = pn_manual[:16]
    elif pn_sel == "Nenhum (PN base)": pn_final_str = base_with_c
    else: pn_final_str = (base_with_c + pn_sel)[:16]
    pn_16 = pad16(pn_final_str)
    pn_disp = pn_16.decode("ascii","replace")
    st.markdown(f"**Final:** <span class='preview'>{pn_disp}</span>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with id3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Cisco Key**")
    key_opts = list(CISCO_KEYS.keys())
    sel_idx = st.selectbox("Manu_ID", options=range(len(key_opts)),
                            format_func=lambda i: KEY_LABELS[key_opts[i]], index=0)
    manu_id = key_opts[sel_idx]
    st.caption(f"byte 0xE2 = 0x{manu_id:02X}")
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 6 — BUILD + OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
upper_enc = build_upper_page(src_upper, sn_16, pn_16, manu_id)
lower_enc = build_lower_page(src_lower)
md5_res, crc32_res = calc_cisco_patch(sn_16, manu_id)
upper_bytes = page_to_bytes128(upper_enc, 128)
lower_bytes = page_to_bytes128(lower_enc, 0)
page02_bytes = PAGE02_FIXED
full_page00_bytes = lower_bytes + upper_bytes
upper_hexstr = upper_bytes.hex().upper()
lower_hexstr = lower_bytes.hex().upper()
page02_hexstr = page02_bytes.hex().upper()
full_page00_hexstr = full_page00_bytes.hex().upper()

st.markdown("---")
st.markdown('<div class="sec-final">📋  6 — STRINGS FINAIS — Copiar e gravar no IDE Coherent/Finisar</div>',
            unsafe_allow_html=True)

# Password reminder
st.markdown("""<div class="warn-box">
<b>🔑 SFF — Unlock and Save to Edit Registers</b><br>
Unlock Password: Page 00 Register 0x7B (4 bytes): <code>556E6C6B</code> ("Unlk")<br>
Save Password:&nbsp;&nbsp;&nbsp;Page 00 Register 0x7B (4 bytes): <code>53617665</code> ("Save")
</div>""", unsafe_allow_html=True)

# Resumo da Unidade — visão consolidada do que vai ser gravado
magic_key_hex = CISCO_KEYS[manu_id].hex().upper()
ch_resumo = f"{ch_label} (Page12h 0x{ch_msb_val:02X} {ch_lsb_val:02X})" if ch_valid else "não definido"
st.markdown(f"""<div class="output-block" style="background:#F7F9FB">
<div class="output-title">📋 Resumo da Unidade — o que vai ser gravado</div>
<b>SN:</b> {sn_disp.strip()} &nbsp;|&nbsp; <b>PN:</b> {pn_disp.strip()} &nbsp;|&nbsp; <b>Manu_ID:</b> 0x{manu_id:02X}<br>
<b>Cisco Key:</b> <code style="font-size:11px">{magic_key_hex}</code><br>
<b>ModulePowerClassOverride (Pg1E:0xFD):</b> 0x{TARGET_P1E_FD:02X} — {p1e_fd_meaning(TARGET_P1E_FD)}<br>
<b>FlexTune:</b> 0x{TARGET_P1E_FLEXTUNE_EN:02X} (ligado) &nbsp;|&nbsp; Grid: 0x{TARGET_P1E_FLEXTUNE_GRID:02X} (100GHz) — confirmar com cliente<br>
<b>NominalWavelengthControl (B0h:0x81):</b> 0x01 (ligado)<br>
<b>Canal:</b> {ch_resumo}
</div>""", unsafe_allow_html=True)

# LOWER — escondida por padrão, só libera com confirmação explícita
with st.expander("🟢 LOWER PAGE · 128 bytes  (clique pra abrir — NÃO é o fluxo normal)", expanded=False):
    st.warning("⚠️ Você quer realmente copiar a Lower Page? Ela é gravada manualmente nesta fase "
               "(ver checklist seção 3). Confirme abaixo para liberar a string.")
    confirm_lower = st.checkbox("Sim, quero ver/copiar a Lower Page mesmo assim", key="confirm_lower_page")
    if confirm_lower:
        st.markdown('<div class="output-block">', unsafe_allow_html=True)
        st.markdown("**📍 Inserir em:** `Page : 00h (Lower)` · **Endereço inicial:** `0x00`")
        st.caption("Modificações: 0x69=01 (DDM Enable) | 0x6A=1F (DDM Cap) | 0x6B=37 (Max Power 5.5W) | 0x71=0E (Near/Far End)")
        st.markdown(f'<div class="hex-out-lp">{lower_hexstr}</div>', unsafe_allow_html=True)
        lc1, lc2 = st.columns([4,1])
        with lc1: st.code(lower_hexstr, language=None)
        with lc2:
            st.download_button("📥 .bin", data=lower_bytes, file_name=f"lower_{sn_disp.strip()}.bin",
                                mime="application/octet-stream", use_container_width=True, key="dl_lower")
        st.markdown('</div>', unsafe_allow_html=True)

# UPPER
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔴 UPPER PAGE 00h · 128 bytes</div>', unsafe_allow_html=True)
st.markdown("**📍 Inserir em:** `Page : 00h (Upper)` · **Endereço inicial:** `0x80`")
st.caption(f"SN: {sn_disp.strip()} | PN: {pn_disp.strip()} | Manu_ID: 0x{manu_id:02X} | CC_BASE: 0x{upper_enc.get(191,0):02X} | CC_EXT: 0x{upper_enc.get(223,0):02X}")
st.markdown(f'<div class="hex-out">{upper_hexstr}</div>', unsafe_allow_html=True)
uc1, uc2 = st.columns([4,1])
with uc1: st.code(upper_hexstr, language=None)
with uc2:
    st.download_button("📥 .bin", data=upper_bytes, file_name=f"upper_{sn_disp.strip()}.bin",
                        mime="application/octet-stream", use_container_width=True, key="dl_upper")
st.markdown('</div>', unsafe_allow_html=True)

# PAGE 02h
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔵 PAGE 02h · 128 bytes · CLEI Cisco (fixo — igual para as 12 unidades)</div>', unsafe_allow_html=True)
st.markdown("**📍 Inserir em:** `Page : 02h` · **Endereço inicial:** `0x80`")
st.caption("CLEI: INUIAKDEAA (QSFP-100G-ZR-S) — payload validado contra dump real Apticom, não depende do SN")
st.markdown(f'<div class="hex-out-p2">{page02_hexstr}</div>', unsafe_allow_html=True)
pc1, pc2 = st.columns([4,1])
with pc1: st.code(page02_hexstr, language=None)
with pc2:
    st.download_button("📥 .bin", data=page02_bytes, file_name="page02_fixed.bin",
                        mime="application/octet-stream", use_container_width=True, key="dl_page02")
st.markdown('</div>', unsafe_allow_html=True)

# FULL PAGE 00 (Lower+Upper concatenada) — backup para Revelprogs
with st.expander("📦 Full Page 00 (Lower+Upper concatenada, 256 bytes) — só para Revelprogs, se precisar"):
    st.markdown("**📍 Inserir em:** `Page : 00h (completa)` · **Endereço inicial:** `0x00`")
    st.caption("Lower (128) + Upper (128) = 256 bytes. Use apenas se o Revelprogs pedir a página completa "
               "de uma vez em vez de Lower/Upper separadas.")
    st.markdown(f'<div class="hex-out">{full_page00_hexstr}</div>', unsafe_allow_html=True)
    fp1, fp2c = st.columns([4,1])
    with fp1: st.code(full_page00_hexstr, language=None)
    with fp2c:
        st.download_button("📥 .bin", data=full_page00_bytes, file_name=f"full_page00_{sn_disp.strip()}.bin",
                            mime="application/octet-stream", use_container_width=True, key="dl_full_page00")

# B0h + Page 1Eh + Canal instructions
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔩 Registros individuais — gravar separadamente no IDE (NÃO são páginas completas)</div>', unsafe_allow_html=True)
ri1, ri2 = st.columns(2)
with ri1:
    st.markdown(f"**B0h : 0x80** = `0x01` — LowMemConfigSelect")
    st.markdown(f"**B0h : 0x81** = `0x01` — NominalWavelengthControl")
    st.markdown(f"**Page 1Eh : 0xFD** = `0x{TARGET_P1E_FD:02X}` — ModulePowerClassOverride ⚠️ **OBRIGATÓRIO**")
    st.markdown(f"**Page 1Eh : 0xC8** = `0x{TARGET_P1E_FLEXTUNE_EN:02X}` — FlexTuneEnable (confirmar com cliente)")
    st.markdown(f"**Page 1Eh : 0xCB** = `0x{TARGET_P1E_FLEXTUNE_GRID:02X}` — FlexTuneGrid / 100GHz (confirmar com cliente)")
with ri2:
    if ch_valid:
        st.markdown(f"**Page 12h : 0x88** = `0x{ch_msb_val:02X}` — Canal MSB")
        st.markdown(f"**Page 12h : 0x89** = `0x{ch_lsb_val:02X}` — Canal LSB ({ch_label})")
st.markdown('</div>', unsafe_allow_html=True)

# Checksum confirmation
cc_b_ok = upper_enc.get(191) == calc_ccbase(upper_enc)
cc_e_ok = upper_enc.get(223) == calc_ccext(upper_enc)
vc1, vc2 = st.columns(2)
with vc1: st.markdown(f"{'✅' if cc_b_ok else '❌'} CC_BASE = `0x{upper_enc.get(191,0):02X}`")
with vc2: st.markdown(f"{'✅' if cc_e_ok else '❌'} CC_EXT  = `0x{upper_enc.get(223,0):02X}`")

# ─────────────────────────────────────────────────────────────────────────────
# 7 — RESUMO IMPRIMÍVEL
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec">📊 7 — Resumo da Unidade</div>', unsafe_allow_html=True)
sm1, sm2 = st.columns(2)
summary = [
    ("PN Original", pn_orig), ("SN Original", sn_orig),
    ("PN Encodado", pn_disp.rstrip()), ("SN Encodado", sn_disp.rstrip()),
    ("Manu_ID", f"0x{manu_id:02X}"), ("CC_BASE", f"0x{upper_enc.get(191,0):02X}"),
    ("CC_EXT", f"0x{upper_enc.get(223,0):02X}"), ("MD5", md5_res.hex().upper()),
    ("CRC32", crc32_res.hex().upper()), ("Max Power", "0x37 = 5.5W"),
    ("Canal", ch_label if ch_valid else "—"),
    ("B0h 0x80/0x81", "0x01 / 0x01"),
]
items = list(summary)
for i,(k,v) in enumerate(items):
    with (sm1 if i < len(items)//2+1 else sm2):
        st.markdown(f"**{k}:** `{v}`")

st.markdown("---")
st.markdown("""<div class="info-box">
📌 A verificação final pós-gravação agora é feita na página separada <b>FTLC Validator</b> —
suba o dump pós-gravação lá para confirmar 100% antes de entregar ao cliente, ou para validar
lotes inteiros de unidades de uma vez.
</div>""", unsafe_allow_html=True)
st.caption("EPS Global · FTLC Field Encoder v0.4 · Patch validado vs 5 dumps reais · Page 02h validada vs dump Apticom 2611W388H · SFF-8636 Rev 2.12")