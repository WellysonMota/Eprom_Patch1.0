"""
FTLC3351/3352R3PL1 — Encoding Validator / Report  v2.0
EPS Global · Independent / batch validation of encoded transceivers
Self-sufficient: extracts identity from the dump itself, recomputes the
expected patch and checks against known targets. No dependency on encoder session.
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
VENDOR_NAME   = b"CISCO-FINISAR   "
TARGET_B81    = 0xCF
TARGET_B93    = 0x0D
LP_TARGETS    = {0x69: 0x01, 0x6A: 0x1F, 0x6B: 0x37, 0x71: 0x0E}
B0_TARGETS    = {0x80: 0x01, 0x81: 0x01}
TARGET_P1E_FD          = 0x02
TARGET_P1E_FLEXTUNE_EN   = 0x01
TARGET_P1E_FLEXTUNE_GRID = 0x05

def p1e_fd_meaning(val):
    return {
        0x00: "SFF standard — depends on host setting the bit (typical broken state)",
        0x01: "Full BYPASS — ignores host (aggressive mode, NOT field-validated)",
        0x02: "Power Class 5-7 — VALIDATED value in all working field units",
    }.get(val, f"undocumented value (0x{val:02X})")

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
# ITU CHANNEL DICTIONARIES  (source: Coherent / Finisar FTLC3351/3352 channel table)
# Key = Finisar Reference Channel (value stored in Page 12h offset 0x88/0x89)
# Value = (ITU_channel, frequency_THz, wavelength_nm)
# ─────────────────────────────────────────────────────────────────────────────
CHAN_100GHZ = {
    -17:(14,191.4,1566.31),-16:(15,191.5,1565.5),-15:(16,191.6,1564.68),
    -14:(17,191.7,1563.86),-13:(18,191.8,1563.05),-12:(19,191.9,1562.23),
    -11:(20,192.0,1561.41),-10:(21,192.1,1560.61), -9:(22,192.2,1559.79),
     -8:(23,192.3,1558.98), -7:(24,192.4,1558.17), -6:(25,192.5,1557.36),
     -5:(26,192.6,1556.55), -4:(27,192.7,1555.75), -3:(28,192.8,1554.94),
     -2:(29,192.9,1554.13), -1:(30,193.0,1553.33),  0:(31,193.1,1552.52),
      1:(32,193.2,1551.72),  2:(33,193.3,1550.92),  3:(34,193.4,1550.12),
      4:(35,193.5,1549.32),  5:(36,193.6,1548.51),  6:(37,193.7,1547.72),
      7:(38,193.8,1546.92),  8:(39,193.9,1546.12),  9:(40,194.0,1545.32),
     10:(41,194.1,1544.53), 11:(42,194.2,1543.73), 12:(43,194.3,1542.94),
     13:(44,194.4,1542.14), 14:(45,194.5,1541.35), 15:(46,194.6,1540.56),
     16:(47,194.7,1539.77), 17:(48,194.8,1538.98), 18:(49,194.9,1538.19),
     19:(50,195.0,1537.4),  20:(51,195.1,1536.61), 21:(52,195.2,1535.82),
     22:(53,195.3,1535.04), 23:(54,195.4,1534.25), 24:(55,195.5,1533.47),
     25:(56,195.6,1532.68), 26:(57,195.7,1531.9),  27:(58,195.8,1531.12),
     28:(59,195.9,1530.33), 29:(60,196.0,1529.55), 30:(61,196.1,1528.77),
}

CHAN_50GHZ = {
    -35:(13.5,191.35,1566.72),-34:(14,191.4,1566.31),-33:(14.5,191.45,1565.9),
    -32:(15,191.5,1565.5),   -31:(15.5,191.55,1565.09),-30:(16,191.6,1564.68),
    -29:(16.5,191.65,1564.27),-28:(17,191.7,1563.86), -27:(17.5,191.75,1563.45),
    -26:(18,191.8,1563.05),  -25:(18.5,191.85,1562.64),-24:(19,191.9,1562.23),
    -23:(19.5,191.95,1561.83),-22:(20,192.0,1561.42), -21:(20.5,192.05,1561.01),
    -20:(21,192.1,1560.61),  -19:(21.5,192.15,1560.2),-18:(22,192.2,1559.79),
    -17:(22.5,192.25,1559.39),-16:(23,192.3,1558.98), -15:(23.5,192.35,1558.58),
    -14:(24,192.4,1558.17),  -13:(24.5,192.45,1557.77),-12:(25,192.5,1557.36),
    -11:(25.5,192.55,1556.96),-10:(26,192.6,1556.56),  -9:(26.5,192.65,1556.15),
     -8:(27,192.7,1555.75),   -7:(27.5,192.75,1555.34), -6:(28,192.8,1554.94),
     -5:(28.5,192.85,1554.54),-4:(29,192.9,1554.13),   -3:(29.5,192.95,1553.73),
     -2:(30,193.0,1553.33),   -1:(30.5,193.05,1552.93),  0:(31,193.1,1552.52),
      1:(31.5,193.15,1552.12), 2:(32,193.2,1551.72),    3:(32.5,193.25,1551.32),
      4:(33,193.3,1550.92),    5:(33.5,193.35,1550.52),  6:(34,193.4,1550.12),
      7:(34.5,193.45,1549.72), 8:(35,193.5,1549.32),    9:(35.5,193.55,1548.91),
     10:(36,193.6,1548.52),   11:(36.5,193.65,1548.11), 12:(37,193.7,1547.72),
     13:(37.5,193.75,1547.32),14:(38,193.8,1546.92),   15:(38.5,193.85,1546.52),
     16:(39,193.9,1546.12),   17:(39.5,193.95,1545.72), 18:(40,194.0,1545.32),
     19:(40.5,194.05,1544.92),20:(41,194.1,1544.53),   21:(41.5,194.15,1544.13),
     22:(42,194.2,1543.73),   23:(42.5,194.25,1543.33), 24:(43,194.3,1542.94),
     25:(43.5,194.35,1542.54),26:(44,194.4,1542.14),   27:(44.5,194.45,1541.75),
     28:(45,194.5,1541.35),   29:(45.5,194.55,1540.95), 30:(46,194.6,1540.56),
     31:(46.5,194.65,1540.16),32:(47,194.7,1539.77),   33:(47.5,194.75,1539.37),
     34:(48,194.8,1538.98),   35:(48.5,194.85,1538.58), 36:(49,194.9,1538.19),
     37:(49.5,194.95,1537.79),38:(50,195.0,1537.4),    39:(50.5,195.05,1537.0),
     40:(51,195.1,1536.61),   41:(51.5,195.15,1536.22), 42:(52,195.2,1535.82),
     43:(52.5,195.25,1535.43),44:(53,195.3,1535.04),   45:(53.5,195.35,1534.64),
     46:(54,195.4,1534.25),   47:(54.5,195.45,1533.86), 48:(55,195.5,1533.47),
     49:(55.5,195.55,1533.07),50:(56,195.6,1532.68),   51:(56.5,195.65,1532.29),
     52:(57,195.7,1531.9),    53:(57.5,195.75,1531.51), 54:(58,195.8,1531.12),
     55:(58.5,195.85,1530.72),56:(59,195.9,1530.33),   57:(59.5,195.95,1529.94),
     58:(60,196.0,1529.55),   59:(60.5,196.05,1529.16), 60:(61,196.1,1528.77),
}

def resolve_channel(ch_raw, flextune_grid):
    """Return (itu_ch, freq_thz, wavelength_nm, grid_label) or None."""
    # treat ch_raw as signed 16-bit
    if ch_raw > 32767: ch_raw -= 65536
    if flextune_grid == 0x04:  # 50GHz
        info = CHAN_50GHZ.get(ch_raw)
        label = "50GHz"
    else:                       # default 100GHz
        info = CHAN_100GHZ.get(ch_raw)
        label = "100GHz"
    if info:
        return (info[0], info[1], info[2], label)
    return None

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
# CORE VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
def validate_dump(text: str, expected_channel: tuple = None) -> dict:
    pages = parse_dump(text)
    if 0 not in pages or not pages.get(0):
        return {"error": "Page 00h not found or empty — invalid or incomplete file."}

    p0    = pages.get(0,{})
    pb0   = pages.get(0xB0,{})
    plow  = pages.get("lower",{})
    p12   = pages.get(0x12,{})
    p02   = pages.get(0x02,{})
    p1e   = pages.get(0x1E,{})
    upper = p0   # validation always reads Page 00h (the live state the switch sees)

    sn        = asc(upper,196,16).rstrip()
    pn        = asc(upper,168,16).rstrip()
    manu_id   = upper.get(226, 0)
    sn_bytes  = bytes([upper.get(196+i,0x20) for i in range(16)])
    date_code = asc(upper,212,8).strip()

    # ── Channel ──────────────────────────────────────────────────────────────
    cur_fgrid = p1e.get(0xCB, 0x05) if p1e else 0x05
    ch_msb    = p12.get(0x88, 0) if p12 else 0
    ch_lsb    = p12.get(0x89, 0) if p12 else 0
    ch_raw    = (ch_msb << 8) | ch_lsb
    ch_info   = resolve_channel(ch_raw, cur_fgrid) if p12 else None

    checks = []
    cur_p1e_fd, cur_ften = 0, 0

    # ── Structural checks ─────────────────────────────────────────────────────
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
        checks.append(("Page B0h present", False, "absent", "present"))

    if p1e:
        cur_p1e_fd = p1e.get(0xFD, 0)
        checks.append(("ModulePowerClassOverride ⚠️ MANDATORY", cur_p1e_fd==TARGET_P1E_FD,
                        f"0x{cur_p1e_fd:02X}", f"0x{TARGET_P1E_FD:02X}"))
        cur_ften  = p1e.get(0xC8, 0)
        cur_fgrid2 = p1e.get(0xCB, 0)
        checks.append(("ℹ️ FlexTuneEnable (informational, does not affect result)", True,
                        f"0x{cur_ften:02X}", f"ref: 0x{TARGET_P1E_FLEXTUNE_EN:02X}"))
        checks.append(("ℹ️ FlexTuneGrid (informational, does not affect result)", True,
                        f"0x{cur_fgrid2:02X}", f"ref: 0x{TARGET_P1E_FLEXTUNE_GRID:02X} (100GHz)"))
    else:
        checks.append(("ModulePowerClassOverride (Pg1E:0xFD)", False,
                        "Page 1Eh absent", f"0x{TARGET_P1E_FD:02X}"))

    if expected_channel:
        ch_msb_e, ch_lsb_e = expected_channel
        if p12:
            ch_ok = ch_msb==ch_msb_e and ch_lsb==ch_lsb_e
            checks.append(("Channel (Page12h 0x88/0x89)", ch_ok,
                            f"{ch_msb:02X} {ch_lsb:02X}",
                            f"{ch_msb_e:02X} {ch_lsb_e:02X}"))
        else:
            checks.append(("Channel (Page12h 0x88/0x89)", False,
                            "Page 12h absent", f"{ch_msb_e:02X} {ch_lsb_e:02X}"))

    # ── Checksums ─────────────────────────────────────────────────────────────
    ccbase_ok = upper.get(191,0) == calc_ccbase(upper)
    ccext_ok  = upper.get(223,0) == calc_ccext(upper)
    checks.append(("CC_BASE self-consistent", ccbase_ok,
                    f"0x{upper.get(191,0):02X}", "auto-consistent"))
    checks.append(("CC_EXT self-consistent", ccext_ok,
                    f"0x{upper.get(223,0):02X}", "auto-consistent"))

    # ── Cisco patch ───────────────────────────────────────────────────────────
    md5_stored = bytes([upper.get(227+i,0) for i in range(16)])
    crc_stored = bytes([upper.get(252+i,0) for i in range(4)])
    md5_calc, crc_calc = calc_cisco_patch(sn_bytes, manu_id)
    cisco_crc32_str = crc_stored.hex().upper()
    if md5_calc is None:
        checks.append(("Cisco Manu_ID known", False, f"0x{manu_id:02X}", "0x02/06/08/0E/11"))
    else:
        md5_ok = md5_stored == md5_calc
        crc_ok = crc_stored == crc_calc
        checks.append(("Cisco MD5 (self-consistent with programmed SN)", md5_ok,
                        md5_stored.hex().upper()[:16]+"...",
                        "MATCH" if md5_ok else "DIVERGENT"))
        checks.append(("Cisco CRC32", crc_ok,
                        crc_stored.hex().upper(),
                        crc_calc.hex().upper()))

    # ── Page 02h ─────────────────────────────────────────────────────────────
    if p02:
        p02_bytes = page_to_bytes128(p02, 128)
        p02_match = p02_bytes == PAGE02_FIXED
        checks.append(("Page 02h (Cisco CLEI)", p02_match,
                        "present", "MATCH" if p02_match else "DIVERGENT"))
    else:
        checks.append(("Page 02h (Cisco CLEI)", False, "absent", "expected present"))

    all_ok         = all(c[1] for c in checks)
    cisco_key_hex  = CISCO_KEYS.get(manu_id, b"").hex().upper()

    return {
        "error": None, "sn": sn, "pn": pn, "manu_id": manu_id,
        "date_code": date_code,
        "ch_msb": ch_msb, "ch_lsb": ch_lsb, "ch_info": ch_info,
        "checks": checks, "all_ok": all_ok,
        "p1e_fd": cur_p1e_fd, "flextune_en": cur_ften, "flextune_grid": cur_fgrid,
        "b0_81": pb0.get(0x81, 0) if pb0 else 0,
        "cisco_key_hex": cisco_key_hex,
        "cisco_crc32": cisco_crc32_str,
    }

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="FTLC Encoding Validator", page_icon="✅", layout="wide")
st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#EAEAEA}
[data-testid="stSidebar"]{background:#2A2A2A}
.report-title{font-family:Arial,sans-serif;font-size:22px;font-weight:bold;color:#2A2A2A;margin:0}
.report-sub{font-family:Arial,sans-serif;font-size:13px;color:#555;margin:0}
.sec{color:#2E6A9C;font-weight:bold;font-size:14px;letter-spacing:.5px;
     border-bottom:2px solid #B42D27;padding-bottom:4px;margin:18px 0 10px 0;
     text-transform:uppercase}
.badge-pass{background:#1A5A2A;color:#fff;padding:4px 14px;border-radius:4px;
            font-size:13px;font-weight:bold;font-family:Arial}
.badge-fail{background:#B42D27;color:#fff;padding:4px 14px;border-radius:4px;
            font-size:13px;font-weight:bold;font-family:Arial}
.summary-box{background:#fff;border:1px solid #d0d0d0;border-radius:6px;
             padding:14px 18px;margin:10px 0 14px 0;font-family:Arial,sans-serif;font-size:13px}
.summary-row{display:flex;gap:12px;padding:3px 0;border-bottom:1px solid #f0f0f0}
.summary-lbl{color:#555;min-width:220px;font-size:12px}
.summary-val{color:#1a1a1a;font-weight:600;font-size:12px}
.check-row{display:flex;gap:10px;padding:4px 6px;border-bottom:1px solid #f0f0f0;font-size:12px;align-items:center}
.check-label{min-width:300px;font-weight:600;color:#2A2A2A}
.check-cur{font-family:monospace;font-size:11px;min-width:160px}
.check-exp{font-family:monospace;font-size:11px;color:#888}
.ch-badge{background:#2E6A9C;color:#fff;padding:2px 8px;border-radius:3px;
          font-size:12px;font-weight:bold;font-family:monospace;margin-right:6px}
.ch-detail{color:#444;font-size:12px}
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
ha, hb = st.columns([1,10])
with ha: st.markdown("### ✅")
with hb:
    st.markdown("""
    <p class="report-title">FTLC DCO Transceiver — Encoding Validation Report
    <span style="font-size:13px;color:#999;font-weight:normal">v2.0</span></p>
    <p class="report-sub">EPS Global · Independent batch validation · SFF-8636 Rev 2.12 · Cisco Nexus Compatibility</p>
    """, unsafe_allow_html=True)
st.markdown("---")

# ── Expected channel (optional) ───────────────────────────────────────────────
st.markdown('<div class="sec">Expected Channel (optional)</div>', unsafe_allow_html=True)
st.caption("If all units in the batch were tuned to the same channel, enter the Page 12h bytes to include a channel match check. Leave blank to skip.")
cc1, cc2 = st.columns(2)
with cc1: ch_msb_in = st.text_input("MSB byte (0x88)", value="", max_chars=2, placeholder="e.g. 00")
with cc2: ch_lsb_in = st.text_input("LSB byte (0x89)", value="", max_chars=2, placeholder="e.g. 06")
expected_channel = None
if ch_msb_in.strip() and ch_lsb_in.strip():
    try:
        expected_channel = (int(ch_msb_in,16)&0xFF, int(ch_lsb_in,16)&0xFF)
    except ValueError:
        st.error("Invalid channel bytes — use 2-digit hex values.")

# ── File upload ───────────────────────────────────────────────────────────────
st.markdown('<div class="sec">Upload Encoded Dump Files</div>', unsafe_allow_html=True)
files = st.file_uploader(
    "I2C Memory Dump TXT files (select one or multiple for batch validation)",
    type=["txt"], accept_multiple_files=True, key="batch_upload")

if not files:
    st.markdown("""
    <div style="background:#fff;border-radius:6px;padding:16px;color:#555;font-family:Arial;font-size:13px">
    Awaiting upload. Drop one file to validate a single unit, or multiple files to validate an entire batch at once.
    </div>""", unsafe_allow_html=True)
    st.stop()

st.markdown("---")

# ── Run validation ────────────────────────────────────────────────────────────
results = []
for f in files:
    text = f.read().decode("utf-8", errors="replace")
    r = validate_dump(text, expected_channel)
    r["filename"] = f.name
    results.append(r)

n_total = len(results)
n_ok    = sum(1 for r in results if not r["error"] and r["all_ok"])
n_fail  = n_total - n_ok

# ── Batch summary metrics ─────────────────────────────────────────────────────
st.markdown('<div class="sec">Batch Summary</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Units", n_total)
m2.metric("✅ PASS", n_ok)
m3.metric("❌ FAIL", n_fail)
rate = f"{100*n_ok//n_total}%" if n_total else "—"
m4.metric("Pass Rate", rate)
st.markdown("---")

# ── Per-unit report cards ─────────────────────────────────────────────────────
st.markdown('<div class="sec">Unit Reports</div>', unsafe_allow_html=True)

for r in results:
    if r["error"]:
        st.error(f"**{r['filename']}** — {r['error']}")
        continue

    badge_cls = "badge-pass" if r["all_ok"] else "badge-fail"
    badge_txt = "PASS" if r["all_ok"] else "FAIL"
    exp_label = f"{'✅' if r['all_ok'] else '❌'}  {r['filename']}  |  SN: {r['sn']}  |  PN: {r['pn']}"

    with st.expander(exp_label, expanded=not r["all_ok"]):

        # Status badge
        st.markdown(f'<span class="{badge_cls}">{badge_txt}</span>', unsafe_allow_html=True)
        st.markdown("")

        # ── Unit Summary section ─────────────────────────────────────────────
        st.markdown('<div class="sec">Unit Summary</div>', unsafe_allow_html=True)

        # Channel display
        ch_disp = "Page 12h absent"
        if r["ch_info"]:
            itu_ch, freq_thz, wl_nm, grid_lbl = r["ch_info"]
            ch_raw_disp = f"0x{r['ch_msb']:02X} 0x{r['ch_lsb']:02X}"
            ch_disp = (f"<span class='ch-badge'>Ch {itu_ch} ({grid_lbl})</span>"
                       f"<span class='ch-detail'>{freq_thz:.3f} THz &nbsp;·&nbsp; "
                       f"{wl_nm:.2f} nm &nbsp;·&nbsp; raw: {ch_raw_disp}</span>")
        elif r.get("ch_msb") is not None:
            ch_disp = f"raw: 0x{r['ch_msb']:02X} 0x{r['ch_lsb']:02X} (not in supported range)"

        # FlexTune / B0:81
        ft_lbl  = "Enabled" if r["flextune_en"]==1 else "Disabled"
        g_lbl   = "100GHz" if r["flextune_grid"]==0x05 else ("50GHz" if r["flextune_grid"]==0x04 else f"0x{r['flextune_grid']:02X}")
        w_lbl   = "✅ Enabled (0x01)" if r["b0_81"]==1 else f"❌ Disabled (0x{r['b0_81']:02X})"
        pwr_lbl = p1e_fd_meaning(r["p1e_fd"])
        cisco_key_short = r["cisco_key_hex"][:16]+"..." if r["cisco_key_hex"] else "unknown"

        summary_rows = [
            ("Part Number (Programmed)",       r["pn"]),
            ("Serial Number (Programmed)",     r["sn"]),
            ("Date Code",                      r["date_code"] if r["date_code"] else "—"),
            ("Manu_ID",                        f"0x{r['manu_id']:02X}"),
            ("Channel",                        ch_disp),
            ("Cisco Key",                      f"<code style='font-size:11px'>{r['cisco_key_hex'] or 'unknown'}</code>"),
            ("Cisco CRC32",                    f"<code style='font-size:12px;font-weight:bold'>{r['cisco_crc32']}</code>"),
            ("ModulePowerClassOverride (Pg1E:0xFD)",
             f"<b>0x{r['p1e_fd']:02X}</b> — {pwr_lbl}"),
            ("FlexTune",                       f"{ft_lbl} &nbsp;|&nbsp; Grid: {g_lbl}"),
            ("NominalWavelengthControl (B0h:0x81)", w_lbl),
        ]

        rows_html = "".join(
            f"<div class='summary-row'>"
            f"<span class='summary-lbl'>{lbl}</span>"
            f"<span class='summary-val'>{val}</span>"
            f"</div>"
            for lbl, val in summary_rows
        )
        st.markdown(f"<div class='summary-box'>{rows_html}</div>", unsafe_allow_html=True)

        # ── Encoding Verification section ────────────────────────────────────
        st.markdown('<div class="sec">Encoding Verification</div>', unsafe_allow_html=True)
        for label, ok, cur, tgt in r["checks"]:
            icon  = "✅" if ok else "❌"
            color = "#1A5A2A" if ok else "#B42D27"
            st.markdown(
                f"<div class='check-row'>"
                f"<div style='width:20px'>{icon}</div>"
                f"<div class='check-label'>{label}</div>"
                f"<code class='check-cur' style='color:{color}'>{cur}</code>"
                f"<span style='color:#aaa;font-size:11px'>expected:</span>"
                f"<code class='check-exp'>{tgt}</code>"
                f"</div>",
                unsafe_allow_html=True)

# ── CSV Export ────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec">Export</div>', unsafe_allow_html=True)
csv_lines = ["filename,sn,pn,date_code,manu_id,channel_itu,freq_thz,wavelength_nm,cisco_crc32,result,failed_checks"]
for r in results:
    if r["error"]:
        csv_lines.append(f'{r["filename"]},,,,,,,,,"ERROR","{r["error"]}"')
        continue
    ch_itu  = r["ch_info"][0] if r["ch_info"] else ""
    freq    = r["ch_info"][1] if r["ch_info"] else ""
    wl      = r["ch_info"][2] if r["ch_info"] else ""
    failed  = [c[0] for c in r["checks"] if not c[1]]
    status  = "PASS" if r["all_ok"] else "FAIL"
    csv_lines.append(
        f'{r["filename"]},{r["sn"]},{r["pn"]},{r["date_code"]},'
        f'0x{r["manu_id"]:02X},{ch_itu},{freq},{wl},{r["cisco_crc32"]},'
        f'{status},"{"; ".join(failed)}"')
csv_data = "\n".join(csv_lines)
st.download_button("📥 Download Validation Report (CSV)",
                   data=csv_data, file_name="FTLC_Encoding_Validation_Report.csv",
                   mime="text/csv")
st.markdown("---")
st.caption("EPS Global · FTLC DCO Encoding Validator v2.0 · "
           "Self-sufficient validation — patch recomputed from programmed SN · SFF-8636 Rev 2.12")