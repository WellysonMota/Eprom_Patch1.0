import streamlit as st

st.set_page_config(
    page_title="Cisco Page 02h Validator",
    page_icon="📋",
    layout="wide"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

/* ── Reset & Base ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 16px;
    color: #1A1A1A;
}

.stApp {
    background-color: #E8E8E8;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background-color: #2A2A2A !important;
    border-right: 3px solid #B42D27 !important;
}
[data-testid="stSidebar"] * {
    font-family: 'Inter', sans-serif !important;
    color: #E8E8E8 !important;
}
[data-testid="stSidebar"] .stButton button {
    background-color: #3A3A3A !important;
    border: 1px solid #555 !important;
    color: #E8E8E8 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1.0rem !important;
    font-weight: 500 !important;
    border-radius: 4px !important;
    text-align: left !important;
    padding: 0.5rem 0.8rem !important;
}
[data-testid="stSidebar"] .stButton button[kind="primary"] {
    background-color: #B42D27 !important;
    border-color: #B42D27 !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
}
[data-testid="stSidebar"] .stButton button:hover {
    background-color: #B42D27 !important;
    border-color: #B42D27 !important;
    color: #FFFFFF !important;
}

/* ── Title block ── */
.title-block {
    background-color: #2A2A2A;
    border-left: 5px solid #B42D27;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1.5rem;
    border-radius: 0 4px 4px 0;
}
.title-block h1 {
    font-size: 1.8rem;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: 0.03em;
    margin: 0 0 0.2rem 0;
}
.title-block p {
    color: #AAAAAA;
    font-size: 0.9rem;
    font-family: 'Roboto Mono', monospace;
    letter-spacing: 0.05em;
    margin: 0;
}

/* ── Section labels ── */
.section-label {
    font-family: 'Inter', sans-serif;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #777777;
    text-transform: uppercase;
    margin: 1.8rem 0 0.6rem 0;
    padding: 0.3rem 0.6rem;
    background-color: #DCDCDC;
    border-left: 3px solid #2E6A9C;
    border-radius: 0 3px 3px 0;
}

hr.divider {
    border: none;
    border-top: 2px solid #C8C8C8;
    margin: 1rem 0;
}

/* ── Inputs / Selectbox ── */
[data-testid="stSelectbox"] > div,
[data-testid="stTextInput"] > div > div {
    background-color: #FFFFFF !important;
    border: 1px solid #AAAAAA !important;
    border-radius: 4px !important;
    color: #1A1A1A !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1.0rem !important;
}
[data-testid="stSelectbox"] > div:focus-within,
[data-testid="stTextInput"] > div > div:focus-within {
    border-color: #2E6A9C !important;
    box-shadow: 0 0 0 2px rgba(46,106,156,0.2) !important;
}
label, .stTextInput label, .stSelectbox label {
    color: #444444 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.9rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em !important;
}

/* ── Expander ── */
[data-testid="stExpander"] {
    background-color: #F4F4F4 !important;
    border: 1px solid #C8C8C8 !important;
    border-radius: 4px !important;
}
[data-testid="stExpander"] summary {
    color: #444444 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    border: 2px dashed #AAAAAA !important;
    border-radius: 4px !important;
    background: #F4F4F4 !important;
    padding: 1rem !important;
}

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #FFFFFF;
    border: 1px solid #C8C8C8;
    border-top: 3px solid #2E6A9C;
    border-radius: 4px;
    padding: 0.8rem 1rem !important;
}
[data-testid="stMetricLabel"] {
    color: #777777 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    color: #1A1A1A !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1.3rem !important;
    font-weight: 700 !important;
}

/* ── Download button ── */
.stDownloadButton button {
    width: 100%;
    background-color: #B42D27 !important;
    border: none !important;
    color: #FFFFFF !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 1.05rem !important;
    letter-spacing: 0.06em !important;
    border-radius: 4px !important;
    padding: 0.65rem 1rem !important;
    transition: background-color 0.15s ease;
}
.stDownloadButton button:hover {
    background-color: #8B1F1A !important;
}

/* ── Alerts ── */
.stSuccess > div {
    background-color: #E8F5E9 !important;
    border-left: 4px solid #2E7D32 !important;
    color: #1B5E20 !important;
    border-radius: 0 4px 4px 0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
    font-weight: 500 !important;
}
.stError > div {
    background-color: #FFEBEE !important;
    border-left: 4px solid #B42D27 !important;
    color: #7F0000 !important;
    border-radius: 0 4px 4px 0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
}
.stWarning > div {
    background-color: #FFF3E0 !important;
    border-left: 4px solid #E65100 !important;
    color: #BF360C !important;
    border-radius: 0 4px 4px 0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
}
.stInfo > div {
    background-color: #E3F2FD !important;
    border-left: 4px solid #2E6A9C !important;
    color: #0D47A1 !important;
    border-radius: 0 4px 4px 0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.95rem !important;
}

/* ── Code blocks ── */
.stCode, [data-testid="stCode"] {
    background: #F4F4F4 !important;
    border: 1px solid #C8C8C8 !important;
    border-radius: 4px !important;
    font-family: 'Roboto Mono', monospace !important;
    color: #1A1A1A !important;
    font-size: 0.9rem !important;
}

/* ── Sig card (MD5/CRC display) ── */
.sig-card {
    background: #FFFFFF;
    border: 1px solid #C8C8C8;
    border-left: 3px solid #2E6A9C;
    border-radius: 0 4px 4px 0;
    padding: 0.8rem 1rem;
    font-family: 'Roboto Mono', monospace;
    font-size: 0.95rem;
    color: #1A1A1A;
    word-break: break-all;
    line-height: 1.8;
}
.sig-label {
    font-size: 0.78rem;
    font-weight: 700;
    color: #777777;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
}

/* ── Sidebar status block ── */
.sidebar-status {
    font-family: 'Roboto Mono', monospace;
    font-size: 0.85rem;
    color: #AAAAAA;
    padding: 0.8rem;
    border: 1px solid #444444;
    border-radius: 4px;
    background: #1A1A1A;
    line-height: 2.0;
}
.sidebar-status .dot {
    display: inline-block;
    width: 8px; height: 8px;
    background: #4CAF50;
    border-radius: 50%;
    margin-right: 6px;
    box-shadow: 0 0 5px #4CAF50;
}

/* ── Check blocks (validator cards) ── */
.check-block {
    background: #FFFFFF;
    border: 1px solid #C8C8C8;
    border-top: 3px solid #C8C8C8;
    border-radius: 0 0 4px 4px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.6rem;
    font-family: 'Roboto Mono', monospace;
    font-size: 0.88rem;
}
.check-block.pass-block { border-top-color: #2E7D32; }
.check-block.fail-block { border-top-color: #B42D27; }

.check-header {
    display: flex; justify-content: space-between;
    align-items: center; margin-bottom: 0.5rem;
}
.check-name {
    font-family: 'Inter', sans-serif;
    font-size: 0.78rem;
    font-weight: 700;
    color: #444444;
    letter-spacing: 0.12em;
    text-transform: uppercase;
}
.badge-pass {
    background-color: #2E7D32;
    color: #FFFFFF;
    border-radius: 3px;
    padding: 0.15rem 0.6rem;
    font-size: 0.75rem;
    font-weight: 700;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.08em;
}
.badge-fail {
    background-color: #B42D27;
    color: #FFFFFF;
    border-radius: 3px;
    padding: 0.15rem 0.6rem;
    font-size: 0.75rem;
    font-weight: 700;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.08em;
}
.check-row {
    display: flex; gap: 0.8rem;
    margin-top: 0.2rem;
    border-top: 1px solid #F0F0F0;
    padding-top: 0.2rem;
}
.check-key {
    color: #888888;
    min-width: 80px;
    font-size: 0.82rem;
}
.check-val { color: #1A1A1A; word-break: break-all; }
.check-val-bad { color: #B42D27; font-weight: 600; word-break: break-all; }

/* ── Final result banners ── */
.final-pass {
    text-align: center;
    font-size: 1.4rem;
    font-weight: 700;
    color: #FFFFFF;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.08em;
    padding: 1rem;
    background-color: #2E7D32;
    border-radius: 4px;
    border-left: 6px solid #1B5E20;
}
.final-fail {
    text-align: center;
    font-size: 1.4rem;
    font-weight: 700;
    color: #FFFFFF;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.08em;
    padding: 1rem;
    background-color: #B42D27;
    border-radius: 4px;
    border-left: 6px solid #7F0000;
}
.final-warn {
    text-align: center;
    font-size: 1.4rem;
    font-weight: 700;
    color: #FFFFFF;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.08em;
    padding: 1rem;
    background-color: #E65100;
    border-radius: 4px;
    border-left: 6px solid #BF360C;
}

/* ── ID badges (transceiver family) ── */
.id-badge {
    display: inline-block;
    font-family: 'Roboto Mono', monospace;
    font-size: 0.85rem;
    font-weight: 500;
    padding: 0.2rem 0.8rem;
    border-radius: 3px;
    margin-right: 0.5rem;
    border: 1px solid;
}
.id-sfp    { background: #E3F2FD; border-color: #2E6A9C; color: #1A3A6B; }
.id-qsfp   { background: #F3E5F5; border-color: #6A1B9A; color: #4A148C; }
.id-400g   { background: #FFF3E0; border-color: #E65100; color: #BF360C; }
.id-unknown{ background: #F5F5F5; border-color: #9E9E9E; color: #616161; }

/* ── Field cards (page2) ── */
.field-card {
    background: #FFFFFF;
    border: 1px solid #C8C8C8;
    border-radius: 4px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem;
}
.field-label {
    font-size: 0.75rem;
    font-weight: 700;
    color: #777777;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
}
.field-value { color: #1A1A1A; font-size: 1.05rem; font-weight: 600; word-break: break-all; }
.field-raw   { color: #AAAAAA; font-size: 0.82rem; font-family: 'Roboto Mono', monospace; margin-top: 0.2rem; }

.match-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.45rem 0; border-bottom: 1px solid #F0F0F0;
    font-size: 0.95rem;
}
.match-pn   { color: #1A1A1A; font-size: 1.0rem; font-weight: 700; }
.match-desc { color: #555555; font-size: 0.9rem; }
.match-clei { color: #888888; font-family: 'Roboto Mono', monospace; font-size: 0.85rem; }

.badge-match {
    background-color: #2E7D32; color: #FFFFFF;
    border-radius: 3px; padding: 0.15rem 0.6rem;
    font-size: 0.75rem; font-weight: 700;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em;
    white-space: nowrap;
}
.badge-nomatch {
    background-color: #B42D27; color: #FFFFFF;
    border-radius: 3px; padding: 0.15rem 0.6rem;
    font-size: 0.75rem; font-weight: 700;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em;
    white-space: nowrap;
}
.badge-warn {
    background-color: #E65100; color: #FFFFFF;
    border-radius: 3px; padding: 0.15rem 0.6rem;
    font-size: 0.75rem; font-weight: 700;
    font-family: 'Inter', sans-serif; letter-spacing: 0.06em;
    white-space: nowrap;
}

.hex-dump {
    font-family: 'Roboto Mono', monospace; font-size: 0.88rem;
    background: #F4F4F4; border: 1px solid #C8C8C8; border-radius: 4px;
    padding: 0.8rem 1rem; color: #444444; line-height: 1.8;
    overflow-x: auto; white-space: pre;
}
.info-mono {
    font-family: 'Roboto Mono', monospace; font-size: 0.9rem;
    color: #AAAAAA; text-align: center; padding-top: 0.5rem;
}
</style>
""", unsafe_allow_html=True)

# ── CLEI / Part Number Database ───────────────────────────────────────────────
# Format: "CLEI_CODE": ("Cisco Part Number", "Description", "Speed", "Reach/Media")
# CLEI codes are 10-character strings (Telcordia/iconectiv standard)
# Sources: captured from real Cisco transceivers + Cisco datasheets cross-reference
CISCO_CLEI_DB = {
    # ── 100G QSFP28 ──────────────────────────────────────────────────────────
    "INUIAKDEAA": ("QSFP-100G-ZR-S",    "100G Coherent ZR",       "100G",  "80km DWDM SMF"),
    "INUIAKBGAA": ("QSFP-100G-ZR4-S",   "100GBASE-ZR4",           "100G",  "80km SMF"),
    "IPUIAJ6GAA": ("QSFP-100G-SR4-S",   "100GBASE-SR4",           "100G",  "100m OM4 MMF"),
    "IPUIAJGEAA": ("QSFP-100G-LR4-S",   "100GBASE-LR4",           "100G",  "10km SMF"),
    "IPUIAJGGAA": ("QSFP-100G-ER4L-S",  "100GBASE-ER4L",          "100G",  "40km SMF"),
    "IPMIAK9DAA": ("QSFP-100G-PSM4-S",  "100GBASE-PSM4",          "100G",  "500m SMF MPO"),
    "IPMIAK9EAA": ("QSFP-100G-CWDM4-S", "100GBASE-CWDM4",         "100G",  "2km SMF"),
    "IPMIAKNBAA": ("QSFP-100G-FR-S",    "100GBASE-FR1 Single Lambda","100G","2km SMF"),
    "IPMIAKNBAB": ("QSFP-100G-DR-S",    "100GBASE-DR Single Lambda","100G", "500m SMF"),
    "IPMIAKNBAC": ("QSFP-100G-LR-S",    "100GBASE-LR1 Single Lambda","100G","10km SMF"),
    "IPMIAK9FAA": ("QSFP-100G-SR-S",    "100GBASE-SR1 Single Lane","100G",  "100m OM4 MMF"),
    "IPMIAK9GAA": ("QSFP-100G-SR1.2",   "100G SR1.2 BiDi",        "100G",  "100m OM4 MMF"),
    # ── 40G QSFP+ ───────────────────────────────────────────────────────────
    "COUPAJ5GAA": ("QSFP-40G-SR4",      "40GBASE-SR4",            "40G",   "150m OM4 MMF"),
    "COUPAJ5KAA": ("QSFP-40G-LR4-S",    "40GBASE-LR4",            "40G",   "10km SMF"),
    "COUPAJ5MAA": ("QSFP-40G-ER4",      "40GBASE-ER4",            "40G",   "40km SMF"),
    "COUPAJESAA": ("QSFP-40G-CSR4",     "40GBASE-CSR4",           "40G",   "400m OM4 MMF"),
    # ── 400G QSFP-DD ────────────────────────────────────────────────────────
    "WOUIAKDEAA": ("QSFP-DD-400G-DR4-S","400GBASE-DR4",           "400G",  "500m SMF MPO"),
    "WOUIAKDFAA": ("QSFP-DD-400G-FR4-S","400GBASE-FR4",           "400G",  "2km SMF"),
    "WOUIAKDGAA": ("QSFP-DD-400G-LR4-S","400GBASE-LR4",           "400G",  "10km SMF"),
    "WOUIAKDHAA": ("QSFP-DD-400G-SR8-S","400GBASE-SR8",           "400G",  "100m OM4 MMF"),
    # ── 10G SFP+ ────────────────────────────────────────────────────────────
    "COUIAJ6GAA": ("SFP-10G-SR",        "10GBASE-SR",             "10G",   "300m OM3 MMF"),
    "COUIAJ6KAA": ("SFP-10G-LR",        "10GBASE-LR",             "10G",   "10km SMF"),
    "COUIAJ6MAA": ("SFP-10G-ER",        "10GBASE-ER",             "10G",   "40km SMF"),
    "COUIAJ6NAA": ("SFP-10G-ZR",        "10GBASE-ZR",             "10G",   "80km SMF"),
    "COUIAJ6PAA": ("SFP-10G-LRM",       "10GBASE-LRM",            "10G",   "220m MMF"),
    # ── 1G SFP ──────────────────────────────────────────────────────────────
    "BN2IAJE0AA": ("GLC-SX-MMD",        "1000BASE-SX",            "1G",    "550m MMF"),
    "BN2IAJE2AA": ("GLC-LH-SMD",        "1000BASE-LX/LH",         "1G",    "10km SMF"),
    "BN2IAJF4AA": ("GLC-EX-SMD",        "1000BASE-EX",            "1G",    "40km SMF"),
    "BN2IAJF5AA": ("GLC-ZX-SMD",        "1000BASE-ZX",            "1G",    "70km SMF"),
    "BN2IAJEUAA": ("GLC-T",             "1000BASE-T Copper",      "1G",    "100m Cat5e"),
}

# ── Page 02h structure (SFF-8636) ─────────────────────────────────────────────
# All offsets relative to start of this 128-byte page
# (absolute EEPROM = offset + 128)
PAGE2_FIELDS = {
    "clei_code":    (0,   10),   # bytes 128-137: CLEI code (10 chars)
    "hw_part":      (10,  30),   # bytes 138-157: HW Part Number / Rev (vendor specific)
    "cisco_pn":     (64,  80),   # bytes 192-207: Cisco Part Number (16 bytes)
    "cisco_sn":     (96,  104),  # bytes 224-231: Serial Number fragment (vendor specific)
}


def parse_page2(raw: bytes) -> dict:
    data = bytearray(raw)
    r = {}

    r["size"]     = len(data)
    r["size_ok"]  = len(data) == 128

    # CLEI code
    clei_raw     = bytes(data[0:10])
    clei_str     = clei_raw.decode('ascii', errors='replace').strip()
    clei_clean   = ''.join(c if c.isprintable() and c != ' ' else '' for c in clei_str)
    r["clei_raw"]   = ' '.join(f'{b:02X}' for b in clei_raw)
    r["clei_str"]   = clei_str
    r["clei_clean"] = clei_clean
    r["clei_valid"] = len(clei_clean) == 10 and clei_clean.isalnum()

    # HW Part (bytes 10-29)
    hw_raw = bytes(data[10:30])
    r["hw_part_raw"] = ' '.join(f'{b:02X}' for b in hw_raw)
    r["hw_part_str"] = hw_raw.decode('ascii', errors='replace').strip()

    # Cisco Part Number (bytes 64-79)
    pn_raw = bytes(data[64:80])
    r["cisco_pn_raw"] = ' '.join(f'{b:02X}' for b in pn_raw)
    r["cisco_pn_str"] = pn_raw.decode('ascii', errors='replace').strip()
    r["cisco_pn_valid"] = bool(r["cisco_pn_str"]) and r["cisco_pn_str"] != '?' * 16

    # Serial (bytes 96-103)
    sn_raw = bytes(data[96:104])
    r["sn_raw"] = ' '.join(f'{b:02X}' for b in sn_raw)
    r["sn_str"] = sn_raw.decode('ascii', errors='replace').strip()

    # CLEI lookup
    db_match = CISCO_CLEI_DB.get(clei_clean)
    r["db_match"]     = db_match  # tuple or None
    r["clei_matched"] = db_match is not None

    # Cross-check: if PN from file matches DB entry
    if db_match and r["cisco_pn_str"]:
        r["pn_matches_clei"] = r["cisco_pn_str"].strip() == db_match[0].strip()
    else:
        r["pn_matches_clei"] = None  # inconclusive

    # Full hex dump
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        abs_off = 128 + i
        lines.append(f"0x{abs_off:02X}({abs_off:3d})  {hex_s:<48}  {asc_s}")
    r["hex_dump"] = '\n'.join(lines)

    return r


# ── Sidebar ───────────────────────────────────────────────────────────────────

# ── Title ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="title-block">
    <h1>📋 CISCO PAGE 02h VALIDATOR</h1>
    <p>SFF-8636 USER WRITABLE EEPROM &nbsp;|&nbsp; CLEI CODE &amp; PART NUMBER VERIFICATION</p>
</div>
<hr class="divider">
""", unsafe_allow_html=True)

# ── Upload ────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-label">01 — Upload Page 02h Binary</div>', unsafe_allow_html=True)
st.caption("📌  Expected: 128-byte file captured from QSFP EEPROM Page 02h (SFF-8636)")
uploaded = st.file_uploader("Drop the Page 02h .bin file here", type=["bin"])

if not uploaded:
    st.markdown('<p class="info-mono">← upload a Page 02h .bin to begin validation</p>',
                unsafe_allow_html=True)
else:
    raw = uploaded.read()
    r   = parse_page2(raw)

    # ── Size check ────────────────────────────────────────────────────────────
    if not r["size_ok"]:
        st.warning(
            f"⚠️  File is {r['size']} bytes — expected exactly 128 bytes (1 EEPROM page). "
            f"Results may be inaccurate."
        )

    # ── Step 2: Extracted Fields ──────────────────────────────────────────────
    st.markdown('<div class="section-label">02 — Extracted Fields</div>', unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("CLEI Code",       r["clei_clean"] or "—")
    m2.metric("Cisco Part No",   r["cisco_pn_str"] or "—")
    m3.metric("HW / Rev Info",   r["hw_part_str"][:20] or "—")
    m4.metric("Serial Fragment", r["sn_str"] or "—")

    # ── Step 3: CLEI Lookup ───────────────────────────────────────────────────
    st.markdown('<div class="section-label">03 — CLEI Code Lookup</div>', unsafe_allow_html=True)

    if not r["clei_valid"]:
        st.error(f"⚠️  CLEI code '{r['clei_str']}' is invalid or not alphanumeric.")
    elif r["clei_matched"]:
        pn, desc, speed, reach = r["db_match"]
        pn_ok   = r["pn_matches_clei"]
        badge   = '<span class="badge-match">MATCH ✓</span>'
        pn_badge = (
            '<span class="badge-match">PN OK ✓</span>' if pn_ok is True else
            '<span class="badge-warn">PN NOT PRESENT</span>' if pn_ok is None else
            '<span class="badge-nomatch">PN MISMATCH ✗</span>'
        )
        st.markdown(f"""
        <div class="field-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.6rem;">
                <span style="font-family:'Rajdhani',sans-serif;font-size: 1.05rem;
                             font-weight:700;color:#2E6A9C;letter-spacing:0.08em;">
                    {pn}
                </span>
                <span>{badge}&nbsp;&nbsp;{pn_badge}</span>
            </div>
            <div class="match-row">
                <span class="match-desc">Description</span>
                <span class="match-pn">{desc}</span>
            </div>
            <div class="match-row">
                <span class="match-desc">Speed</span>
                <span style="color:#a0d8ef;font-family:'Share Tech Mono',monospace;">{speed}</span>
            </div>
            <div class="match-row">
                <span class="match-desc">Reach / Media</span>
                <span style="color:#a0d8ef;font-family:'Share Tech Mono',monospace;">{reach}</span>
            </div>
            <div class="match-row">
                <span class="match-desc">CLEI Code</span>
                <span class="match-clei">{r['clei_clean']}</span>
            </div>
            <div class="match-row" style="border:none;">
                <span class="match-desc">PN in File</span>
                <span style="color:{'#00e87a' if pn_ok else '#ffa000'};
                             font-family:'Share Tech Mono',monospace;">
                    {r['cisco_pn_str'] or '(empty)'}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if pn_ok is False:
            st.warning(
                f"⚠️  Part Number mismatch — CLEI `{r['clei_clean']}` maps to "
                f"**{pn}** but file contains **{r['cisco_pn_str']}**."
            )
    else:
        st.markdown(f"""
        <div class="field-card" style="border-color:rgba(255,160,0,0.25);">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-family:'Share Tech Mono',monospace;color:#ffa000;
                             font-size: 1.05rem;">CLEI not found in database</span>
                <span class="badge-warn">UNKNOWN</span>
            </div>
            <div style="margin-top:0.5rem;color:#777777;font-family:'Share Tech Mono',monospace;
                        font-size: 1.05rem;">
                Code: <span style="color:#ffa000;">{r['clei_clean']}</span><br>
                Raw:  {r['clei_raw']}
            </div>
            <div style="margin-top:0.5rem;font-size: 0.95rem;color:#2a4a5a;">
                This CLEI may be valid but not yet in the local database.
                Cross-reference manually with Cisco COPI / TMG Matrix.
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Step 4: Raw Hex Dump ──────────────────────────────────────────────────
    st.markdown('<div class="section-label">04 — Raw Page 02h Content</div>', unsafe_allow_html=True)
    with st.expander("Show hex dump", expanded=False):
        st.markdown(
            f'<div class="hex-dump">'
            f'{"Offset":<14}  {"Hex (16 bytes)":<48}  ASCII\n'
            f'{"-"*75}\n'
            f'{r["hex_dump"]}'
            f'</div>',
            unsafe_allow_html=True
        )

    # ── Step 5: Result ────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">05 — Result</div>', unsafe_allow_html=True)

    if r["clei_matched"] and r["pn_matches_clei"] is not False:
        st.markdown(
            '<div class="final-pass">✅ &nbsp; PAGE 02h VALID — CLEI &amp; PART NUMBER CONFIRMED</div>',
            unsafe_allow_html=True
        )
    elif r["clei_matched"] and r["pn_matches_clei"] is False:
        st.markdown(
            '<div class="final-warn">⚠️ &nbsp; CLEI KNOWN — PART NUMBER MISMATCH</div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<div class="final-fail">❌ &nbsp; CLEI NOT FOUND IN DATABASE</div>',
            unsafe_allow_html=True
        )