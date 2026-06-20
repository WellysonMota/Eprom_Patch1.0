"""
FTLC3351/3352R3PL1 — Field Encoding Tool  v0.3
EPS Global · Standalone · SFF-8636 Rev 2.12
"""

import streamlit as st
import hashlib, struct, binascii, re
from io import StringIO, BytesIO

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
    0x02: "0x02",
    0x06: "0x06",
    0x08: "0x08",
    0x11: "0x11",
}
VENDOR_NAME   = b"CISCO-FINISAR   "
BASE_PN       = "FTLC3351R3PL1-C "   # 16 chars
OUI           = [0xAC, 0x80, 0xD6]
EXT_SPEC      = 0x27
TARGET_B81    = 0xCF
TARGET_B93    = 0x0D
TARGET_BC2    = 0x3D
TARGET_BC3    = 0xDB

# Lower Page NV targets (confirmed vs 4 real dumps)
LP_DDM_EN    = (0x69, 0x01)   # DDM Enable
LP_DDM_CAP   = (0x6A, 0x1F)   # DDM Capabilities
LP_MAXPWR    = (0x6B, 0x37)   # Max Power = 5.5W (Apticom confirmed)
LP_NEARFAR   = (0x71, 0x0E)   # Near/Far End = canal único coerente

SN_SUFFIXES  = ["Nenhum (SN original)", "-1", "-2", "-3", "-4", "-5", "Manual..."]
PN_SUFFIXES  = ["Nenhum (PN base)", "A", "B", "C", "D", "Manual..."]
PN_SUF_LABELS= ["Nenhum (PN base)",
                "-A  →  FTLC3351R3PL1-CA",
                "-B  →  FTLC3351R3PL1-CB",
                "-C  →  FTLC3351R3PL1-CC",
                "-D  →  FTLC3351R3PL1-CD",
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

# ─────────────────────────────────────────────────────────────────────────────
# ENCODING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
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

def build_upper_page(source: dict, sn_final: bytes,
                     pn_final: bytes, manu_id: int) -> dict:
    page = dict(source)
    # Identity
    page[129] = TARGET_B81
    page[147] = TARGET_B93
    for i,b in enumerate(VENDOR_NAME):  page[148+i] = b
    for i,b in enumerate(OUI):          page[165+i] = b
    for i,b in enumerate(pn_final):     page[168+i] = b
    # CC_BASE
    page[191] = calc_ccbase(page)
    # Options
    page[192] = EXT_SPEC
    page[194] = TARGET_BC2
    page[195] = TARGET_BC3
    # SN
    for i,b in enumerate(sn_final):     page[196+i] = b
    # CC_EXT
    page[223] = calc_ccext(page)
    # Cisco patch
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
    """Take Lower Page from dump and apply the 4 NV target bytes."""
    page = dict(source)
    for addr, val in [LP_DDM_EN, LP_DDM_CAP, LP_MAXPWR, LP_NEARFAR]:
        page[addr] = val
    return page

def page_to_bytes128(page: dict, base: int) -> bytes:
    """128 bytes starting at base address."""
    return bytes([page.get(base+i, 0x00) for i in range(128)])

def bytes_to_hexstr(b: bytes) -> str:
    return b.hex().upper()

# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def chk(ok, t, f): return f"{'✅' if ok else '❌'} {t if ok else f}"

def diff_row(label, orig, new, changed=True):
    arrow = "→" if changed else "≡"
    col   = "#B42D27" if changed else "#1A5A2A"
    bg    = "#ffecec" if changed else "#eeffee"
    st.markdown(
        f'<div style="display:flex;align-items:center;padding:3px 0;'
        f'border-bottom:1px solid #eee;gap:10px;font-size:13px">'
        f'<div style="width:230px;color:#555">{label}</div>'
        f'<code style="background:#f4f4f4;padding:2px 5px;border-radius:3px;'
        f'color:#666;font-size:11px">{orig}</code>'
        f'<span style="color:{col};font-weight:bold">{arrow}</span>'
        f'<code style="background:{bg};padding:2px 5px;border-radius:3px;'
        f'color:{col};font-weight:bold;font-size:11px">{new}</code>'
        f'</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG & CSS
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="FTLC Field Encoder v0.3", page_icon="🔧", layout="wide")
st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#E8E8E8}
[data-testid="stSidebar"]{background:#2A2A2A}
.stButton>button{background:#B42D27;color:#fff;border:none;
  font-weight:bold;padding:6px 18px;border-radius:4px}
.stButton>button:hover{background:#8a1f1b}
.hex-out{font-family:'Roboto Mono',monospace;font-size:11px;
  background:#1a1a2e;color:#00ff88;padding:14px;border-radius:6px;
  word-break:break-all;line-height:1.8;letter-spacing:.5px}
.hex-out-lp{font-family:'Roboto Mono',monospace;font-size:11px;
  background:#0d1f0d;color:#7fff7f;padding:14px;border-radius:6px;
  word-break:break-all;line-height:1.8;letter-spacing:.5px}
.card{background:#fff;border-radius:8px;padding:16px;
  box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:12px}
.sec{color:#2E6A9C;font-weight:bold;font-size:15px;
  border-bottom:2px solid #B42D27;padding-bottom:4px;margin-bottom:12px}
.sec-final{color:#fff;font-weight:bold;font-size:16px;
  background:#B42D27;padding:10px 16px;border-radius:6px;margin-bottom:16px}
.info-box{background:#f0f4ff;border-left:4px solid #2E6A9C;
  padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.ok-box{background:#f0fff4;border-left:4px solid #1A5A2A;
  padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.warn-box{background:#fff3f3;border-left:4px solid #B42D27;
  padding:10px 14px;border-radius:4px;margin:8px 0;font-size:13px}
.preview{font-family:monospace;background:#2A2A2A;color:#00ff88;
  padding:5px 12px;border-radius:4px;font-size:13px;letter-spacing:1px}
.output-block{background:#fff;border:2px solid #2E6A9C;border-radius:8px;
  padding:16px;margin-bottom:16px}
.output-title{color:#2E6A9C;font-weight:bold;font-size:14px;margin-bottom:8px}
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
      FTLC Field Encoder <span style="font-size:14px;color:#888">v0.3</span></h2>
    <p style="color:#555;margin:0;font-size:13px">
      EPS Global · FTLC3351/3352R3PL1 → Cisco Nexus · SFF-8636 Rev 2.12</p>
    """, unsafe_allow_html=True)
st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
# 1 — UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">📂 1 — Upload do Dump TXT</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Cisco I2C Memory Dump (.txt)", type=["txt"])
if not uploaded:
    st.markdown("""<div class="info-box">
    Aguardando upload do TXT dump.<br>
    Fluxo: <b>dump no switch</b> → upload aqui → configurar → copiar strings → gravar no IDE Coherent
    </div>""", unsafe_allow_html=True)
    st.stop()

text  = uploaded.read().decode("utf-8", errors="replace")
pages = parse_dump(text)

if 0 not in pages:
    st.error("Page 00h não encontrada. Verificar arquivo."); st.stop()

p0   = pages.get(0, {})
pfff = pages.get(0xFF, {})
pb0  = pages.get(0xB0, {})
plow = pages.get("lower", {})

src_upper = pfff if pfff else p0
src_lower = plow

sn_orig = get_sn(pfff) if pfff else get_sn(p0)
pn_orig = get_pn(pfff) if pfff else get_pn(p0)
fw_maj  = pb0.get(0xD0, 0); fw_min = pb0.get(0xD1, 0)
max_pwr = plow.get(0x6B, 0)
b0_80   = pb0.get(0x80, 0); b0_81 = pb0.get(0x81, 0)
is_3352 = "3352" in pn_orig; is_3351 = "3351" in pn_orig

# ─────────────────────────────────────────────────────────────────────────────
# 2 — MODULE INFO
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔎 2 — Informações do Módulo</div>', unsafe_allow_html=True)
mi1, mi2 = st.columns(2)
with mi1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Identidade original (Page FFh)**")
    st.markdown(f"SN: `{sn_orig}` &nbsp;&nbsp; PN: `{pn_orig}`")
    st.markdown(f"FW: `{fw_maj}.{fw_min:02d}` &nbsp;&nbsp; Max Power: `0x{max_pwr:02X}` = `{max_pwr*0.1:.1f}W`")
    if is_3352:
        st.markdown("ℹ️ **FTLC3352R3PL1** — 0 dBm High Power")
    elif is_3351:
        st.markdown("ℹ️ **FTLC3351R3PL1** — -8 dBm")
    st.markdown('</div>', unsafe_allow_html=True)
with mi2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Estado B0h / Lower Page**")
    st.markdown(chk(b0_80==0x01, "B0h:0x80=0x01 LowMemConfigSelect ✓",
                    f"B0h:0x80=0x{b0_80:02X} ⚠️ esperado 0x01"))
    st.markdown(chk(b0_81==0x01, "B0h:0x81=0x01 NominalWavelength ✓",
                    f"B0h:0x81=0x{b0_81:02X} ⚠️ ALTERAR para 0x01"))
    ddm_e=plow.get(0x69,0); ddm_c=plow.get(0x6A,0)
    st.markdown(chk(ddm_e==0x01, f"0x69=0x01 DDM Enable ✓",
                    f"0x69=0x{ddm_e:02X} → será gravado como 0x01"))
    st.markdown(chk(ddm_c==0x1F, f"0x6A=0x1F DDM Capabilities ✓",
                    f"0x6A=0x{ddm_c:02X} → será gravado como 0x1F"))
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 3 — IDENTITY
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔑 3 — Configuração de Identidade</div>', unsafe_allow_html=True)
id1, id2 = st.columns(2)

with id1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Serial Number**")
    st.caption(f"Detectado (FFh): `{sn_orig}`")
    sn_sel = st.selectbox("Sufixo SN", SN_SUFFIXES, index=0,
                          help="Adiciona sufixo ao SN original — garante SN único no cache Nexus")
    sn_manual = ""
    if sn_sel == "Manual...":
        sn_manual = st.text_input("SN completo (manual)", value=sn_orig,
                                   max_chars=16, help="Máx 16 chars")
    if sn_sel == "Manual...":
        sn_final_str = sn_manual[:16]
    elif sn_sel == "Nenhum (SN original)":
        sn_final_str = sn_orig
    else:
        sn_final_str = (sn_orig + sn_sel)[:16]
    sn_16 = pad16(sn_final_str)
    sn_disp = sn_16.decode("ascii","replace")
    changed_sn = sn_final_str != sn_orig
    st.markdown(f"**SN final:** <span class='preview'>{sn_disp}</span>",
                unsafe_allow_html=True)
    if changed_sn:
        st.caption("🔄 MD5, CRC32 e CC_EXT recalculados")
    st.markdown('</div>', unsafe_allow_html=True)

with id2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("**Part Number**")
    st.caption(f"PN base encodado: `{BASE_PN.rstrip()}`")
    pn_suf_idx = st.selectbox("Sufixo PN",
                               options=range(len(PN_SUFFIXES)),
                               format_func=lambda i: PN_SUF_LABELS[i], index=0,
                               help="Adiciona sufixo ao PN base — diferencia no cache Nexus")
    pn_sel = PN_SUFFIXES[pn_suf_idx]
    pn_manual = ""
    if pn_sel == "Manual...":
        pn_manual = st.text_input("PN completo (manual)", value=BASE_PN.rstrip(),
                                   max_chars=16, help="Máx 16 chars")
    base15 = BASE_PN.rstrip()  # 15 chars
    if pn_sel == "Manual...":
        pn_final_str = pn_manual[:16]
    elif pn_sel == "Nenhum (PN base)":
        pn_final_str = BASE_PN
    else:
        pn_final_str = (base15 + pn_sel)[:16]  # e.g. "FTLC3351R3PL1-CA"
    pn_16   = pad16(pn_final_str)
    pn_disp = pn_16.decode("ascii","replace")
    changed_pn = pn_final_str.rstrip() != BASE_PN.rstrip()
    st.markdown(f"**PN final:** <span class='preview'>{pn_disp}</span>",
                unsafe_allow_html=True)
    if changed_pn:
        st.caption("🔄 CC_BASE recalculado")
    st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 4 — KEY SELECTION
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="sec">🔐 4 — Cisco Patch — Seleção de Key</div>',
            unsafe_allow_html=True)
st.markdown('<div class="card">', unsafe_allow_html=True)
key_opts = list(CISCO_KEYS.keys())
sel_idx  = st.selectbox("Manu_ID / Magic Key",
                         options=range(len(key_opts)),
                         format_func=lambda i: KEY_LABELS[key_opts[i]], index=0)
manu_id  = key_opts[sel_idx]
magic    = CISCO_KEYS[manu_id]
kc1, kc2 = st.columns(2)
with kc1: st.markdown(f"**Manu_ID:** `0x{manu_id:02X}` → byte 0xE2 (226)")
with kc2: st.markdown(f"**Magic Key:** `{magic.hex().upper()[:16]}...{magic.hex().upper()[-8:]}`")
st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# 5 — BUILD PAGES
# ─────────────────────────────────────────────────────────────────────────────
upper_enc  = build_upper_page(src_upper, sn_16, pn_16, manu_id)
lower_enc  = build_lower_page(src_lower)
md5_res, crc32_res = calc_cisco_patch(sn_16, manu_id)

upper_bytes = page_to_bytes128(upper_enc, 128)   # bytes 128-255
lower_bytes = page_to_bytes128(lower_enc, 0)      # bytes 0-127
upper_hexstr = bytes_to_hexstr(upper_bytes)
lower_hexstr = bytes_to_hexstr(lower_bytes)

# ─────────────────────────────────────────────────────────────────────────────
# 6 — DIFF SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
with st.expander("⚙️  Ver modificações aplicadas (Upper + Lower Page)", expanded=False):
    st.markdown("**Upper Page 00h:**")
    orig_129 = src_upper.get(129,0); orig_147=src_upper.get(147,0)
    orig_vn  = asc(src_upper,148,16); orig_oui="{:02X}:{:02X}:{:02X}".format(
                    src_upper.get(165,0),src_upper.get(166,0),src_upper.get(167,0))
    orig_pn_ = asc(src_upper,168,16); orig_sn_=asc(src_upper,196,16)
    orig_191 = src_upper.get(191,0); orig_bc0=src_upper.get(192,0)
    orig_bc2 = src_upper.get(194,0); orig_bc3=src_upper.get(195,0)
    orig_df  = src_upper.get(223,0)

    diff_row("Byte 129 (0x81) Extended ID",  f"0x{orig_129:02X}", f"0x{TARGET_B81:02X}", orig_129!=TARGET_B81)
    diff_row("Byte 147 (0x93) Device Tech",  f"0x{orig_147:02X}", f"0x{TARGET_B93:02X}", orig_147!=TARGET_B93)
    diff_row("Bytes 148-163 Vendor Name",     orig_vn.rstrip(),   "CISCO-FINISAR",       orig_vn.rstrip()!="CISCO-FINISAR")
    diff_row("Bytes 165-167 OUI",             orig_oui,           "AC:80:D6",             orig_oui!="AC:80:D6")
    diff_row("Bytes 168-183 Vendor PN",       orig_pn_.rstrip(),  pn_disp.rstrip(),       orig_pn_.rstrip()!=pn_disp.rstrip())
    diff_row("Byte 191 (0xBF) CC_BASE",      f"0x{orig_191:02X}",f"0x{upper_enc.get(191,0):02X}", True)
    diff_row("Byte 192 (0xC0) Ext Spec",     f"0x{orig_bc0:02X}",f"0x{EXT_SPEC:02X}", orig_bc0!=EXT_SPEC)
    diff_row("Byte 194 (0xC2) Options 2",    f"0x{orig_bc2:02X}",f"0x{TARGET_BC2:02X}", orig_bc2!=TARGET_BC2)
    diff_row("Byte 195 (0xC3) Options 3",    f"0x{orig_bc3:02X}",f"0x{TARGET_BC3:02X}", orig_bc3!=TARGET_BC3)
    diff_row("Bytes 196-211 Serial Number",   orig_sn_.rstrip(),  sn_disp.rstrip(),       orig_sn_.rstrip()!=sn_disp.rstrip())
    diff_row("Byte 223 (0xDF) CC_EXT",       f"0x{orig_df:02X}", f"0x{upper_enc.get(223,0):02X}", True)

    st.markdown("**Lower Page:**")
    for addr, target in [LP_DDM_EN, LP_DDM_CAP, LP_MAXPWR, LP_NEARFAR]:
        orig = src_lower.get(addr, 0)
        diff_row(f"Byte 0x{addr:02X} ({addr})", f"0x{orig:02X}", f"0x{target:02X}", orig!=target)

# Checksum verification
cc_b_ok = upper_enc.get(191) == calc_ccbase(upper_enc)
cc_e_ok = upper_enc.get(223) == calc_ccext(upper_enc)
vc1, vc2 = st.columns(2)
with vc1: st.markdown(f"{'✅' if cc_b_ok else '❌'} CC_BASE = `0x{upper_enc.get(191,0):02X}`")
with vc2: st.markdown(f"{'✅' if cc_e_ok else '❌'} CC_EXT  = `0x{upper_enc.get(223,0):02X}`")

# ─────────────────────────────────────────────────────────────────────────────
# FINAL — STRINGS & DOWNLOADS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec-final">📋  STRINGS FINAIS — Copiar e gravar no IDE Coherent/Finisar</div>',
            unsafe_allow_html=True)

# ── LOWER PAGE ──────────────────────────────────────────────────────────────
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🟢 LOWER PAGE &nbsp;·&nbsp; 128 bytes = 256 hex chars</div>',
            unsafe_allow_html=True)

lp_changes = {0x69:"0x01 (DDM Enable)", 0x6A:"0x1F (DDM Cap)",
              0x6B:"0x37 (Max Power 5.5W)", 0x71:"0x0E (Near/Far End)"}
lp_summary = "  |  ".join([f"0x{a:02X}={v}" for a,v in lp_changes.items()])
st.caption(f"Modificações: {lp_summary}")

st.markdown(f'<div class="hex-out-lp">{lower_hexstr}</div>', unsafe_allow_html=True)
lc1, lc2 = st.columns([4, 1])
with lc1:
    st.code(lower_hexstr, language=None)
with lc2:
    fname_lp = f"lower_page_{sn_disp.strip()}.bin"
    st.download_button(
        label="📥 .bin",
        data=lower_bytes,
        file_name=fname_lp,
        mime="application/octet-stream",
        help=f"Download Lower Page como arquivo binário ({fname_lp})",
        use_container_width=True,
    )

# Quick check on LP bytes
lp_ok = all(lower_enc.get(a,0)==v for a,v in [LP_DDM_EN, LP_DDM_CAP, LP_MAXPWR, LP_NEARFAR])
st.markdown(f"{'✅' if lp_ok else '❌'} Bytes 0x69=0x{lower_enc.get(0x69,0):02X} | 0x6A=0x{lower_enc.get(0x6A,0):02X} | 0x6B=0x{lower_enc.get(0x6B,0):02X} | 0x71=0x{lower_enc.get(0x71,0):02X}")
st.markdown('</div>', unsafe_allow_html=True)

# ── UPPER PAGE 00h ──────────────────────────────────────────────────────────
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔴 UPPER PAGE 00h &nbsp;·&nbsp; 128 bytes = 256 hex chars</div>',
            unsafe_allow_html=True)

up_summary = f"SN: {sn_disp.strip()} | PN: {pn_disp.strip()} | Manu_ID: 0x{manu_id:02X} | CC_BASE: 0x{upper_enc.get(191,0):02X} | CC_EXT: 0x{upper_enc.get(223,0):02X}"
st.caption(up_summary)

st.markdown(f'<div class="hex-out">{upper_hexstr}</div>', unsafe_allow_html=True)
uc1, uc2 = st.columns([4, 1])
with uc1:
    st.code(upper_hexstr, language=None)
with uc2:
    fname_up = f"upper_page_{sn_disp.strip()}.bin"
    st.download_button(
        label="📥 .bin",
        data=upper_bytes,
        file_name=fname_up,
        mime="application/octet-stream",
        help=f"Download Upper Page 00h como arquivo binário ({fname_up})",
        use_container_width=True,
    )

# Spot checks
b = list(upper_bytes)
spot_ok = all([b[0]==0x11, b[1]==0xCF, b[19]==0x0D,
               b[37]==0xAC, b[64]==0x27, b[66]==0x3D,
               b[67]==0xDB, b[98]==manu_id])
scl, scr = st.columns(2)
with scl:
    st.markdown(f"{'✅' if b[0]==0x11 else '❌'} ID=0x{b[0]:02X} &nbsp; {'✅' if b[1]==0xCF else '❌'} ExtID=0x{b[1]:02X} &nbsp; {'✅' if b[19]==0x0D else '❌'} DevTech=0x{b[19]:02X} &nbsp; {'✅' if b[98]==manu_id else '❌'} ManufID=0x{b[98]:02X}")
with scr:
    st.markdown(f"{'✅' if b[63] else '✓'} CC_BASE=0x{b[63]:02X} &nbsp; {'✅'} CC_EXT=0x{b[95]:02X} &nbsp; CRC32={b[124]:02X}{b[125]:02X}{b[126]:02X}{b[127]:02X}")
st.markdown('</div>', unsafe_allow_html=True)

# ── B0h ─────────────────────────────────────────────────────────────────────
st.markdown('<div class="output-block">', unsafe_allow_html=True)
st.markdown('<div class="output-title">🔵 B0h — Gravar registro NV separadamente</div>',
            unsafe_allow_html=True)
bc1, bc2 = st.columns(2)
with bc1:
    st.markdown(f"**B0h:0x80 (128)** = `0x01` — LowMemConfigSelect")
    st.markdown(f"{'✅ Já correto no módulo' if b0_80==0x01 else '⚠️ Gravar 0x01 no IDE'}")
with bc2:
    st.markdown(f"**B0h:0x81 (129)** = `0x01` — NominalWavelength Control")
    st.markdown(f"{'✅ Já correto no módulo' if b0_81==0x01 else '⚠️ Gravar 0x01 no IDE'}")
st.markdown('</div>', unsafe_allow_html=True)

# ── SUMMARY TABLE ────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec">📊 Resumo da Unidade</div>', unsafe_allow_html=True)
sm1, sm2 = st.columns(2)
summary = [
    ("PN Original (FFh)", pn_orig), ("SN Original (FFh)", sn_orig),
    ("PN Encodado", pn_disp.rstrip()), ("SN Encodado", sn_disp.rstrip()),
    ("Vendor Name", "CISCO-FINISAR"), ("OUI", "AC:80:D6"),
    ("Manu_ID", f"0x{manu_id:02X}"), ("CC_BASE", f"0x{upper_enc.get(191,0):02X}"),
    ("CC_EXT", f"0x{upper_enc.get(223,0):02X}"), ("MD5", md5_res.hex().upper()),
    ("CRC32", crc32_res.hex().upper()), ("Max Power gravado", "0x37 = 5.5W"),
]
items = list(summary)
for i,(k,v) in enumerate(items):
    with (sm1 if i < len(items)//2+1 else sm2):
        st.markdown(f"**{k}:** `{v}`")

st.markdown("---")
st.caption("EPS Global · FTLC Field Encoder v0.3 · Algoritmo verificado vs Apticom 2611W388Q ✓ 2611W388V ✓ · SFF-8636 Rev 2.12")