"""
FTLC3351/3352R3PL1 — Arista Field Encoding Tool  v0.1
EPS Global · Standalone · SFF-8636 Rev 2.12
Fluxo: Dump único -> Checklist -> Identidade/Patch Arista -> Output -> Verificação Final

⚠️ ORDEM CRÍTICA: Power Class (Upper 0x81) e Device Technology (Upper 0x93) são
gravados no page ANTES de qualquer outra coisa. O CRC32 Arista cobre a Page00h
inteira (128-251), então ele só é calculado por ÚLTIMO, depois de TODOS os outros
campos (vendor, OUI, PN, SN, power class, device tech) já estarem no lugar. Mudar
qualquer um desses campos depois de gerar a string invalida o CRC32 — é preciso
gerar tudo de novo.
"""

import streamlit as st
import struct, zlib, re

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
ARISTA_VENDOR_NAME = b"Arista Networks "     # 16 bytes, confirmado em Full_Page_Arista_10km_LR.bin
ARISTA_OUI          = bytes([0x38, 0x86, 0x02])  # confirmado em Full_Page_Arista_10km_LR.bin

DEFAULT_B81 = 0xCF   # Extended ID — Power Class 7 (editável abaixo)
DEFAULT_B93 = 0x0D   # Device Technology (editável abaixo)

TARGET_P1E_FD            = 0x02  # Page 1Eh:0xFD ModulePowerClassOverride — obrigatório
TARGET_P1E_FLEXTUNE_EN   = 0x00  # ⚠️ Arista exige FlexTune DESLIGADO
TARGET_P1E_FLEXTUNE_GRID = 0x05  # 100GHz — só relevante se FlexTune fosse ligado

def p1e_fd_meaning(val):
    return {
        0x00: "⚠️ SFF padrão — depende do host setar a bit (estado quebrado típico)",
        0x01: "Bypass TOTAL — ignora o host (mais agressivo, não validado em campo)",
        0x02: "Power Class 5-7 — valor VALIDADO em todas as unidades funcionando",
    }.get(val, f"valor não documentado (0x{val:02X})")

LP_DDM_EN   = (0x69, 0x01)
LP_DDM_CAP  = (0x6A, 0x1F)
LP_MAXPWR   = (0x6B, 0x37)
LP_NEARFAR  = (0x71, 0x0E)

B0_LOWMEM   = (0x80, 0x01)   # LowMemConfigSelect
B0_NOMWAVE  = (0x81, 0x01)   # NominalWavelengthControl

CLEAR_START, CLEAR_END = 0xE0, 0xFB          # 224-251, limpa (sem resíduo de patch Cisco)
CRC_REGION_START, CRC_REGION_END = 128, 251  # Page00h inteira, exceto os 4 bytes finais
CRC_OFF = 252                                 # abs 0xFC-0xFF, 4 bytes, big-endian

SN_SUFFIXES = ["Nenhum (SN original)", "-1", "-2", "-3", "-4", "-5", "Manual..."]
PN_SUFFIXES = ["Nenhum (PN base)", "-A", "-B", "-C", "-D", "Manual..."]

# ─────────────────────────────────────────────────────────────────────────────
# PARSER  (idêntico ao encoder/validador Cisco — mesmo formato Coherent IDE)
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
        tokens = line.split()
        if tokens and current_page is not None and re.fullmatch(r"[0-9A-Fa-f]{1,2}", tokens[0]):
            base = int(tokens[0], 16)
            vals = [t for t in tokens[1:] if re.fullmatch(r"[0-9A-Fa-f]{2}", t)]
            for i, v in enumerate(vals):
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

def calc_arista_crc32(page: dict) -> bytes:
    region = bytes([page.get(i, 0) for i in range(CRC_REGION_START, CRC_REGION_END+1)])
    crc = zlib.crc32(region) & 0xFFFFFFFF
    return struct.pack(">I", crc)

def build_upper_page_arista(source: dict, sn_final: bytes, pn_final: bytes,
                             power_class_val: int, device_tech_val: int) -> dict:
    """Ordem crítica: Power Class e Device Tech primeiro, CRC32 por último."""
    page = dict(source)

    # 1) Power Class e Device Technology — PRIMEIRO, editáveis
    page[129] = power_class_val   # Upper 0x81
    page[147] = device_tech_val   # Upper 0x93

    # 2) Identidade Arista
    for i, b in enumerate(ARISTA_VENDOR_NAME): page[148+i] = b
    for i, b in enumerate(ARISTA_OUI):         page[165+i] = b
    for i, b in enumerate(pn_final):           page[168+i] = b
    for i, b in enumerate(sn_final):           page[196+i] = b

    # 3) Limpa região antes usada pelo patch Cisco
    for i in range(CLEAR_START, CLEAR_END+1):  page[i] = 0x00

    # 4) Recalcula CC_BASE e CC_EXT (cobrem faixas que já incluem os campos acima)
    page[191] = calc_ccbase(page)
    page[223] = calc_ccext(page)

    # 5) CRC32 Arista — SEMPRE POR ÚLTIMO, cobre a página inteira (128-251)
    crc = calc_arista_crc32(page)
    for i, b in enumerate(crc): page[CRC_OFF+i] = b

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
st.set_page_config(page_title="Arista Field Encoder v0.1", page_icon="🅰️", layout="wide")
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
.card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:12px}
.sec{color:#2E6A9C;font-weight:bold;font-size:15px;border-bottom:2px solid #B42D27;padding-bottom:4px;margin-bottom:12px}
.sec-final{color:#fff;font-weight:bold;font-size:16px;background:#B42D27;padding:10px 16px;border-radius:6px;margin-bottom:16px}
.info-box{background:#f0f4ff;border-left:4px solid #2E6A9C;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.warn-box{background:#fff3f3;border-left:4px solid #B42D27;padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.preview{font-family:monospace;background:#2A2A2A;color:#00ff88;padding:5px 12px;border-radius:4px;font-size:13px;letter-spacing:1px}
.output-block{background:#fff;border:2px solid #2E6A9C;border-radius:8px;padding:16px;margin-bottom:16px}
.output-title{color:#2E6A9C;font-weight:bold;font-size:14px;margin-bottom:8px}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
ca, cb = st.columns([1,10])
with ca: st.markdown("### 🅰️")
with cb:
    st.markdown("""
    <h2 style="color:#B42D27;margin:0;font-family:Arial">
      Arista Field Encoder <span style="font-size:14px;color:#888">v0.1</span></h2>
    <p style="color:#555;margin:0;font-size:13px">
      EPS Global · FTLC3351/3352R3PL1 → Arista · SFF-8636 Rev 2.12 · Fluxo dump único</p>
    """, unsafe_allow_html=True)
st.markdown("---")

st.markdown("""<div class="warn-box">
⚠️ <b>Ordem crítica:</b> o CRC32 Arista cobre a Page00h inteira (128-251). Power Class (0x81) e
Device Technology (0x93) são aplicados <b>antes</b> de tudo, e o CRC32 é sempre a última coisa
calculada — depois de vendor, OUI, PN e SN. Se você mudar qualquer campo depois de gerar a string,
o CRC32 fica inválido e precisa gerar tudo de novo.
</div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1 — UPLOAD (dump único)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📂 1 — Upload do Dump TXT</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("I2C Memory Dump (.txt, formato Coherent IDE)", type=["txt"], key="main_upload_arista")
if not uploaded:
    st.markdown("""<div class="info-box">
    Fluxo: <b>dump no switch/programador</b> → upload aqui → checklist → power class/device tech/canal/identidade →
    gerar strings → gravar no IDE Coherent → reinserir módulo → <b>verificação final</b> no Arista Validator.
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
    st.markdown('</div>', unsafe_allow_html=True)
with mi2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Páginas detectadas no dump**")
    pg_list = ", ".join(sorted(
        (["Lower"] if plow else []) +
        (["00h"] if p0 else []) + (["FFh"] if pfff else []) +
        (["B0h"] if pb0 else []) + (["12h"] if p12 else []) + (["1Eh"] if p1e else [])
    ))
    st.markdown(pg_list if pg_list else "—")
    if not p12_present:
        st.markdown("⚠️ Page 12h ausente — canal atual não pôde ser lido (você ainda pode digitar o alvo abaixo)")
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 3 — POWER CLASS & DEVICE TECHNOLOGY (editáveis, aplicados ANTES do CRC32)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">⚡ 3 — Power Class & Device Technology (editar ANTES de gerar)</div>', unsafe_allow_html=True)
st.caption("Esses dois campos entram no cálculo do CRC32 Arista. Ajuste aqui antes de gerar as strings finais — mudar depois invalida o CRC32.")
pw1, pw2 = st.columns(2)
with pw1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Power Class — Upper 0x81 (Extended Identifier)**")
    cur_129 = src_upper.get(129, 0)
    st.caption(f"Valor atual no dump: `0x{cur_129:02X}`")
    b81_in = st.text_input("Power Class (hex)", value=f"{DEFAULT_B81:02X}", max_chars=2,
                            help="Padrão 0xCF = Power Class 7. Ajuste se o módulo exigir outra classe.")
    st.markdown('</div>', unsafe_allow_html=True)
with pw2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Device Technology — Upper 0x93**")
    cur_147 = src_upper.get(147, 0)
    st.caption(f"Valor atual no dump: `0x{cur_147:02X}`")
    b93_in = st.text_input("Device Technology (hex)", value=f"{DEFAULT_B93:02X}", max_chars=2)
    st.markdown('</div>', unsafe_allow_html=True)

try:
    power_class_val = int(b81_in, 16) & 0xFF
    device_tech_val = int(b93_in, 16) & 0xFF
    pw_valid = True
except ValueError:
    power_class_val, device_tech_val = DEFAULT_B81, DEFAULT_B93
    pw_valid = False
    st.error("Valor inválido em Power Class ou Device Technology — use hex de 2 dígitos.")

# ─────────────────────────────────────────────────────────────────────────────
# 4 — CHECKLIST DE AJUSTES (energia / DDM / flextune — igual ao Cisco)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📋 4 — Checklist de Ajustes (energia / DDM / FlexTune)</div>', unsafe_allow_html=True)

cur_6b  = src_lower.get(0x6B, 0)
cur_69  = src_lower.get(0x69, 0)
cur_6a  = src_lower.get(0x6A, 0)
cur_71  = src_lower.get(0x71, 0)
cur_b0_80 = pb0.get(0x80, None)
cur_b0_81 = pb0.get(0x81, None)

st.markdown("**✅ Automático — já incluído na string da seção 7 (Upper Page)**")
status_row("Power Class (Extended ID)", "Upper 0x81 (129)", f"0x{cur_129:02X}", f"0x{power_class_val:02X}", cur_129==power_class_val)
status_row("Device Technology", "Upper 0x93 (147)", f"0x{cur_147:02X}", f"0x{device_tech_val:02X}", cur_147==device_tech_val)

st.markdown("")
st.markdown("**✋ Manual — gravar separadamente no IDE**")
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
status_row("FlexTuneEnable ⚠️ PRECISA ESTAR DESLIGADO (Arista)", "Page 1Eh 0xC8 (200)",
           f"0x{cur_p1e_ften:02X}" if cur_p1e_ften is not None else "—", f"0x{TARGET_P1E_FLEXTUNE_EN:02X}",
           cur_p1e_ften==TARGET_P1E_FLEXTUNE_EN, "" if p1e_present else "(Page 1Eh ausente no dump)")
ch_cur_str_prev = (f"{p12.get(0x88,0):02X} {p12.get(0x89,0):02X}" if p12_present else "—")
status_row("Canal (definido na seção 5)", "Page12h 0x88/0x89", ch_cur_str_prev, "ver seção 5 ↓", False,
           "" if p12_present else "(Page 12h ausente no dump)")

# ─────────────────────────────────────────────────────────────────────────────
# 5 — CANAL (input manual)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📡 5 — Canal — Page 12h, endereços 0x88 / 0x89</div>', unsafe_allow_html=True)
st.markdown('<div class="card">', unsafe_allow_html=True)
st.caption("Valor de 2 bytes documentado pela Coherent por canal. Apenas estes 2 bytes são escritos — nunca a página inteira.")
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
# 6 — IDENTIDADE ARISTA (Vendor/OUI fixos, PN/SN com sufixo)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔑 6 — Identidade Arista</div>', unsafe_allow_html=True)
id1, id2, id3 = st.columns(3)

with id1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Vendor / OUI (fixos)**")
    st.caption("Confirmados em Full_Page_Arista_10km_LR.bin — não editáveis.")
    st.markdown(f"Vendor: <span class='preview'>{ARISTA_VENDOR_NAME.decode()}</span>", unsafe_allow_html=True)
    st.markdown(f"OUI: <span class='preview'>{ARISTA_OUI.hex(':').upper()}</span>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with id2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Serial Number**")
    st.caption(f"Detectado: `{sn_orig}`")
    sn_sel = st.selectbox("Sufixo SN", SN_SUFFIXES, index=1)  # default "-1"
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

with id3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Part Number**")
    st.caption(f"Detectado: `{pn_orig}`")
    pn_sel = st.selectbox("Sufixo PN", PN_SUFFIXES, index=1)  # default "-A"
    pn_manual = ""
    if pn_sel == "Manual...":
        pn_manual = st.text_input("PN completo (manual)", value=pn_orig, max_chars=16)
    if pn_sel == "Manual...": pn_final_str = pn_manual[:16]
    elif pn_sel == "Nenhum (PN base)": pn_final_str = pn_orig
    else:
        base = pn_orig
        if len(base) + len(pn_sel) > 16:
            base = base[:16-len(pn_sel)]
        pn_final_str = base + pn_sel
    pn_16 = pad16(pn_final_str)
    pn_disp = pn_16.decode("ascii","replace")
    st.markdown(f"**Final:** <span class='preview'>{pn_disp}</span>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 7 — BUILD + OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
upper_enc = build_upper_page_arista(src_upper, sn_16, pn_16, power_class_val, device_tech_val)
lower_enc = build_lower_page(src_lower)
upper_bytes = page_to_bytes128(upper_enc, 128)
lower_bytes = page_to_bytes128(lower_enc, 0)
upper_hexstr = upper_bytes.hex().upper()
lower_hexstr = lower_bytes.hex().upper()
crc_final = bytes([upper_enc.get(CRC_OFF+i,0) for i in range(4)])

st.markdown("---")
st.markdown('<div class="sec-final">📋  7 — STRINGS FINAIS — Copiar e gravar no IDE Coherent/Finisar</div>',
            unsafe_allow_html=True)

st.markdown("""<div class="warn-box">
<b>🔑 SFF — Unlock and Save to Edit Registers</b><br>
Unlock Password: Page 00 Register 0x7B (4 bytes): <code>556E6C6B</code> ("Unlk")<br>
Save Password:&nbsp;&nbsp;&nbsp;Page 00 Register 0x7B (4 bytes): <code>53617665</code> ("Save")
</div>""", unsafe_allow_html=True)

ch_resumo = f"{ch_label} (Page12h 0x{ch_msb_val:02X} {ch_lsb_val:02X})" if ch_valid else "não definido"
st.markdown(f"""<div class="output-block" style="background:#F7F9FB">
<div class="output-title">📋 Resumo da Unidade — o que vai ser gravado</div>
<b>Vendor:</b> {ARISTA_VENDOR_NAME.decode().strip()} &nbsp;|&nbsp; <b>OUI:</b> {ARISTA_OUI.hex(':').upper()}<br>
<b>SN:</b> {sn_disp.strip()} &nbsp;|&nbsp; <b>PN:</b> {pn_disp.strip()}<br>
<b>Power Class (0x81):</b> 0x{power_class_val:02X} &nbsp;|&nbsp; <b>Device Technology (0x93):</b> 0x{device_tech_val:02X}<br>
<b>ModulePowerClassOverride (Pg1E:0xFD):</b> 0x{TARGET_P1E_FD:02X} — {p1e_fd_meaning(TARGET_P1E_FD)}<br>
<b>FlexTune:</b> 0x{TARGET_P1E_FLEXTUNE_EN:02X} (desligado — obrigatório Arista)<br>
<b>NominalWavelengthControl (B0h:0x81):</b> 0x01 (ligado)<br>
<b>Canal:</b> {ch_resumo}<br>
<b>CRC32 Arista (0xFC-0xFF, BE):</b> <code style="font-size:12px;font-weight:bold">{crc_final.hex().upper()}</code>
</div>""", unsafe_allow_html=True)

with st.expander("🟢 LOWER PAGE · 128 bytes  (clique pra abrir — NÃO é o fluxo normal)", expanded=False):
    st.warning("⚠️ Você quer realmente copiar a Lower Page? Ela é gravada manualmente nesta fase.")
    confirm_lower = st.checkbox("Sim, quero ver/copiar a Lower Page mesmo assim", key="confirm_lower_page_arista")
    if confirm_lower:
        st.markdown('<div class="output-block">', unsafe_allow_html=True)
        st.markdown("**📍 Inserir em:** `Page : 00h (Lower)` · **Endereço inicial:** `0x00`")
        st.caption("Modificações: 0x69=01 (DDM Enable) | 0x6A=1F (DDM Cap) | 0x6B=37 (Max Power 5.5W) | 0x71=0E (Near/Far End)")
        st.markdown(f'<div class="hex-out-lp">{lower_hexstr}</div>', unsafe_allow_html=True)
        lc1, lc2 = st.columns([4,1])
        with lc1: st.code(lower_hexstr, language=None)
        with lc2:
            st.download_button("📥 .bin", data=lower_bytes, file_name=f"lower_{sn_disp.strip()}.bin",
                                mime="application/octet-stream", use_container_width=True, key="dl_lower_arista")
        st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔴 UPPER PAGE 00h · 128 bytes</div>', unsafe_allow_html=True)
st.markdown("**📍 Inserir em:** `Page : 00h (Upper)` · **Endereço inicial:** `0x80`")
st.caption(f"SN: {sn_disp.strip()} | PN: {pn_disp.strip()} | CC_BASE: 0x{upper_enc.get(191,0):02X} | CC_EXT: 0x{upper_enc.get(223,0):02X} | CRC32: {crc_final.hex().upper()}")
st.markdown(f'<div class="hex-out">{upper_hexstr}</div>', unsafe_allow_html=True)
uc1, uc2 = st.columns([4,1])
with uc1: st.code(upper_hexstr, language=None)
with uc2:
    st.download_button("📥 .bin", data=upper_bytes, file_name=f"upper_arista_{sn_disp.strip()}.bin",
                        mime="application/octet-stream", use_container_width=True, key="dl_upper_arista")
st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔩 Registros individuais — gravar separadamente no IDE (NÃO são páginas completas)</div>', unsafe_allow_html=True)
ri1, ri2 = st.columns(2)
with ri1:
    st.markdown(f"**B0h : 0x80** = `0x01` — LowMemConfigSelect")
    st.markdown(f"**B0h : 0x81** = `0x01` — NominalWavelengthControl")
    st.markdown(f"**Page 1Eh : 0xFD** = `0x{TARGET_P1E_FD:02X}` — ModulePowerClassOverride ⚠️ **OBRIGATÓRIO**")
    st.markdown(f"**Page 1Eh : 0xC8** = `0x{TARGET_P1E_FLEXTUNE_EN:02X}` — FlexTuneEnable ⚠️ **DESLIGADO (Arista)**")
with ri2:
    if ch_valid:
        st.markdown(f"**Page 12h : 0x88** = `0x{ch_msb_val:02X}` — Canal MSB")
        st.markdown(f"**Page 12h : 0x89** = `0x{ch_lsb_val:02X}` — Canal LSB ({ch_label})")
st.markdown('</div>', unsafe_allow_html=True)

cc_b_ok = upper_enc.get(191) == calc_ccbase(upper_enc)
cc_e_ok = upper_enc.get(223) == calc_ccext(upper_enc)
crc_ok  = crc_final == calc_arista_crc32(upper_enc)
vc1, vc2, vc3 = st.columns(3)
with vc1: st.markdown(f"{'✅' if cc_b_ok else '❌'} CC_BASE = `0x{upper_enc.get(191,0):02X}`")
with vc2: st.markdown(f"{'✅' if cc_e_ok else '❌'} CC_EXT  = `0x{upper_enc.get(223,0):02X}`")
with vc3: st.markdown(f"{'✅' if crc_ok else '❌'} CRC32 Arista = `{crc_final.hex().upper()}`")

# ─────────────────────────────────────────────────────────────────────────────
# 8 — RESUMO IMPRIMÍVEL
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec">📊 8 — Resumo da Unidade</div>', unsafe_allow_html=True)
sm1, sm2 = st.columns(2)
summary = [
    ("PN Original", pn_orig), ("SN Original", sn_orig),
    ("PN Encodado", pn_disp.rstrip()), ("SN Encodado", sn_disp.rstrip()),
    ("Vendor", ARISTA_VENDOR_NAME.decode().strip()), ("OUI", ARISTA_OUI.hex(':').upper()),
    ("Power Class (0x81)", f"0x{power_class_val:02X}"), ("Device Tech (0x93)", f"0x{device_tech_val:02X}"),
    ("CC_BASE", f"0x{upper_enc.get(191,0):02X}"), ("CC_EXT", f"0x{upper_enc.get(223,0):02X}"),
    ("CRC32 Arista", crc_final.hex().upper()), ("Max Power", "0x37 = 5.5W"),
    ("Canal", ch_label if ch_valid else "—"),
]
items = list(summary)
for i,(k,v) in enumerate(items):
    with (sm1 if i < len(items)//2+1 else sm2):
        st.markdown(f"**{k}:** `{v}`")

st.markdown("---")
st.markdown("""<div class="info-box">
📌 A verificação final pós-gravação é feita na página separada <b>Arista Validator</b> —
suba o dump pós-gravação lá para confirmar 100% antes de entregar ao cliente.
</div>""", unsafe_allow_html=True)
st.caption("EPS Global · Arista Field Encoder v0.1 · CRC32 cobre a página inteira — Power Class e Device Technology sempre antes, CRC32 sempre por último · SFF-8636 Rev 2.12")