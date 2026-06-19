import streamlit as st
import hashlib
import binascii
import struct
import zlib

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cisco Transceiver Validator",
    page_icon="🔬",
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

# ── Constants ─────────────────────────────────────────────────────────────────
MAGIC_KEYS = {
    0x02: bytes.fromhex("8DDAE6A46EC9DEF6100BF185059C3DAB"),  # Cisco / Finisar
    0x06: bytes.fromhex("175258fee9b4f0d9eab6006f7c65a8cb"),  # Cisco / Other
    0x08: bytes.fromhex("30DB1EE9C7913AE5A3C8161B574A9FF6"),  # Cisco
    0x0E: bytes.fromhex("4AF86716ED1E2F347CA13C9978AD8CA0"),  # Cisco
    0x11: bytes.fromhex("E14869FDA81B1C212D715E3BC1371D75"),  # QSFP28
}

TRANSCEIVER_NAMES = {
    0x03: ("SFP / SFP+",          "sfp"),
    0x0C: ("QSFP",                "qsfp"),
    0x0D: ("QSFP+",               "qsfp"),
    0x11: ("QSFP28",              "qsfp"),
    0x18: ("QSFP-DD / 400G CMIS", "400g"),
}

SFP_OFFSETS = {
    "vendor_name":   (0x14, 0x24),
    "part_number":   (0x28, 0x38),
    "serial_number": (0x44, 0x54),
    "manu_id_off":   0x62,
    "md5_off":       0x63,
    "zero_off":      0x73,
    "crc_off":       0x7C,
    "crc_region":    (0x60, 0x7C),
    "min_size":      0x80,
}

QSFP_OFFSETS = {
    # SFF-8636 Upper Page 00 (AN-2141 / AN-2171)
    # Vendor Name    : bytes 148-163 dec = 0x94-0xA3
    # Part Number    : bytes 168-183 dec = 0xA8-0xB7
    # Serial Number  : bytes 196-211 dec = 0xC4-0xD3
    "vendor_name":   (0x94, 0xA4),   # 16 bytes
    "part_number":   (0xA8, 0xB8),   # 16 bytes
    "serial_number": (0xC4, 0xD4),   # 16 bytes  ← FIXED (was 0xB4)
    # Cisco patch region (mirrors SFP but at 0xE0+):
    #   0xE0 = 00h  0xE1 = 00h  0xE2 = ManuID
    #   0xE3-0xF2 = MD5 (16 bytes)
    #   0xF3-0xFB = 9 zero bytes
    #   0xFC-0xFF = CRC32 reversed
    "manu_id_off":   0xE2,
    "md5_off":       0xE3,
    "zero_off":      0xF3,
    "crc_off":       0xFC,
    "crc_region":    (0xE0, 0xFC),
    "min_size":      0x100,
}

CMIS_OFFSETS = QSFP_OFFSETS

# ── SFF Checksum definitions per family ──────────────────────────────────────
# SFP  (SFF-8472): CC_BASE = byte 63,  sum bytes 0–62
#                  CC_EXT  = byte 95,  sum bytes 64–94
# QSFP (SFF-8636): CC_BASE = byte 191, sum bytes 128–190
#                  CC_EXT  = byte 223, sum bytes 192–222
# Upper-Page-Only: same as SFF-8636 but shifted -128 →
#                  CC_BASE = byte 63,  sum bytes 0–62
#                  CC_EXT  = byte 95,  sum bytes 64–94
SFF_CHECKSUMS = {
    "SFP Family": [
        {"name": "CC_BASE", "byte": 63,  "range": (0,  63),  "label": "0x3F"},
        {"name": "CC_EXT",  "byte": 95,  "range": (64, 95),  "label": "0x5F"},
    ],
    "QSFP Family": [
        {"name": "CC_BASE", "byte": 191, "range": (128, 191), "label": "0xBF"},
        {"name": "CC_EXT",  "byte": 223, "range": (192, 223), "label": "0xDF"},
    ],
    "400G Family": [
        {"name": "CC_BASE", "byte": 191, "range": (128, 191), "label": "0xBF"},
        {"name": "CC_EXT",  "byte": 223, "range": (192, 223), "label": "0xDF"},
    ],
    "upper_page_only": [
        {"name": "CC_BASE", "byte": 63,  "range": (0,  63),  "label": "0x3F"},
        {"name": "CC_EXT",  "byte": 95,  "range": (64, 95),  "label": "0x5F"},
    ],
}


def calc_sff_checksum(data, start, end):
    return sum(data[start:end]) & 0xFF


# ── Upper-Page-Only offsets ──────────────────────────────────────────────────
# When only the Upper Page (128 bytes) is dumped, byte 128 dec becomes byte 0.
# All QSFP addresses shift down by 128 (0x80), so the patch region
# that normally lives at 0xE0-0xFF now sits at 0x60-0x7F — same as SFP.
UPPER_PAGE_OFFSETS = {
    "vendor_name":   (0x14, 0x24),   # dec 148-163 → -128 = 20-35
    "part_number":   (0x28, 0x38),   # dec 168-183 → -128 = 40-55
    "serial_number": (0x44, 0x54),   # dec 196-211 → -128 = 68-83
    "manu_id_off":   0x62,           # dec 226     → -128 = 98
    "md5_off":       0x63,           # dec 227     → -128 = 99
    "zero_off":      0x73,           # dec 243     → -128 = 115
    "crc_off":       0x7C,           # dec 252     → -128 = 124
    "crc_region":    (0x60, 0x7C),   # dec 224-251 → -128 = 96-123
    "min_size":      0x80,
}


def detect_block_mode(data: bytearray):
    """
    Detects whether the binary is a full dump or Upper-Page-Only dump.

    Full dump  (≥512 bytes): Lower Page (0-127) + Upper Page (128-255+)
                              Identifier at byte 0x00 is typically 0x03/0x0C/0x0D/0x11/0x18
                              but Lower Page byte 0 = identifier AND byte 0x80 repeats it.
    Upper-Page-Only (128-255 bytes): The dump starts at what was byte 128 dec.
                              The file byte 0x00 contains the identifier (0x11 etc.)
                              but there is NO Lower Page — file size ≤ 256 and
                              byte 0x80 is 0x00 (or file is < 0x100 bytes).
    """
    size = len(data)
    identifier_b0 = data[0]

    # A full QSFP dump has the identifier repeated at byte 0 (Lower Page)
    # AND at byte 0x80 (Upper Page). If byte 0x80 is 0x00 and byte 0x00
    # is a known QSFP identifier → Upper Page Only.
    qsfp_identifiers = {0x0C, 0x0D, 0x11, 0x18}

    if identifier_b0 in qsfp_identifiers:
        if size <= 256:
            # Check if byte 0x80 also carries the identifier (full dump)
            if size > 0x80 and data[0x80] == identifier_b0:
                return "full"
            # byte 0x80 is 0x00 or file is exactly 128/256 bytes → Upper Page Only
            return "upper_page_only"

    return "full"


def detect_family(data):
    identifier = data[0]
    block_mode = detect_block_mode(data)

    if block_mode == "upper_page_only":
        name, badge = TRANSCEIVER_NAMES.get(identifier, (f"QSFP (0x{identifier:02X})", "qsfp"))
        return "QSFP Family", name, badge, UPPER_PAGE_OFFSETS, identifier, "upper_page_only"

    if identifier == 0x18:
        name, badge = TRANSCEIVER_NAMES.get(identifier, ("400G / CMIS", "400g"))
        return "400G Family", name, badge, CMIS_OFFSETS, identifier, "full"
    elif identifier == 0x03:
        name, badge = TRANSCEIVER_NAMES.get(identifier, ("SFP", "sfp"))
        return "SFP Family", name, badge, SFP_OFFSETS, identifier, "full"
    else:
        name, badge = TRANSCEIVER_NAMES.get(identifier, (f"Unknown (0x{identifier:02X})", "unknown"))
        return "QSFP Family", name, badge, QSFP_OFFSETS, identifier, "full"


def fmt_hex(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)


def is_all_zeros(b: bytes) -> bool:
    return all(x == 0x00 for x in b)


def validate_bin(raw: bytes):
    data = bytearray(raw)
    results = {}

    if len(data) < 4:
        return None, f"File too small ({len(data)} bytes)."

    family, t_name, badge, off, identifier, block_mode = detect_family(data)
    results["family"]     = family
    results["t_name"]     = t_name
    results["badge"]      = badge
    results["id_byte"]    = identifier
    results["block_mode"] = block_mode  # "full" or "upper_page_only"

    if len(data) < off["min_size"]:
        return None, f"File too small for {family} ({len(data)} bytes, need {off['min_size']})."

    vendor  = bytes(data[off["vendor_name"][0]  : off["vendor_name"][1]])
    pn      = bytes(data[off["part_number"][0]  : off["part_number"][1]])
    sn      = bytes(data[off["serial_number"][0]: off["serial_number"][1]])
    manu_id = data[off["manu_id_off"]]

    results["vendor"]       = vendor.decode("ascii", errors="replace").strip() or "—"
    results["pn"]           = pn.decode("ascii", errors="replace").strip()     or "—"
    results["sn"]           = sn.decode("ascii", errors="replace").strip()     or "—"
    results["manu_id"]      = manu_id
    results["vendor_raw"]   = fmt_hex(vendor)
    results["sn_raw"]       = fmt_hex(sn)

    # ── Manu ID check: must be known and non-zero ────────────────────────────
    known_key     = manu_id in MAGIC_KEYS
    manu_id_zero  = manu_id == 0x00
    results["manu_id_ok"]     = known_key and not manu_id_zero
    results["manu_id_known"]  = known_key
    results["manu_id_zero"]   = manu_id_zero

    # ── Zero prefix check: bytes before Manu ID must be 00 00 ────────────────
    # SFP:  0x60 and 0x61 must be 00h
    # QSFP: 0xE0 and 0xE1 must be 00h
    prefix_start  = off["manu_id_off"] - 2
    prefix_bytes  = bytes(data[prefix_start : prefix_start + 2])
    prefix_ok     = prefix_bytes == b'\x00\x00'
    results["prefix_ok"]      = prefix_ok
    results["prefix_stored"]  = fmt_hex(prefix_bytes)
    results["prefix_offsets"] = f"0x{prefix_start:02X} & 0x{prefix_start+1:02X}"

    # ── Vendor / SN zero checks ──────────────────────────────────────────────
    results["vendor_zero"] = is_all_zeros(vendor)
    results["sn_zero"]     = is_all_zeros(sn)

    # Use known key if available, otherwise use zeros as placeholder
    key = MAGIC_KEYS.get(manu_id, bytes(16))

    # MD5
    vendor_padded = vendor[:16].ljust(16, b'\x20')
    sn_padded     = sn[:16].ljust(16, b'\x20')
    payload       = bytes([manu_id]) + vendor_padded + sn_padded + key
    calc_md5      = hashlib.md5(payload).digest()
    stored_md5    = bytes(data[off["md5_off"] : off["md5_off"] + 16])
    # MD5 fails if: mismatch, Manu ID unknown/zero, vendor or SN all zeros
    md5_ok = (calc_md5 == stored_md5) and known_key and not manu_id_zero \
             and not results["vendor_zero"] and not results["sn_zero"]
    results["md5_calc"]   = calc_md5.hex()
    results["md5_stored"] = stored_md5.hex()
    results["md5_ok"]     = md5_ok

    # Zero padding
    zero_region = bytes(data[off["zero_off"] : off["zero_off"] + 9])
    zeros_ok    = zero_region == b'\x00' * 9
    results["zeros_ok"]     = zeros_ok
    results["zeros_stored"] = fmt_hex(zero_region)
    results["zero_range"]   = f"0x{off['zero_off']:02X} – 0x{off['zero_off']+8:02X}"

    # CRC32
    crc_start, crc_end = off["crc_region"]
    crc_input  = bytes(data[crc_start:crc_end])
    calc_crc   = zlib.crc32(crc_input) & 0xFFFFFFFF
    calc_crc_b = struct.pack(">I", calc_crc)[::-1]
    stored_crc = bytes(data[off["crc_off"] : off["crc_off"] + 4])
    crc_ok     = calc_crc_b == stored_crc
    results["crc_calc"]   = fmt_hex(calc_crc_b)
    results["crc_stored"] = fmt_hex(stored_crc)
    results["crc_ok"]     = crc_ok

    # ── SFF Checksums ────────────────────────────────────────────────────────────
    chk_key   = "upper_page_only" if block_mode == "upper_page_only" else family
    chk_defs  = SFF_CHECKSUMS.get(chk_key, [])
    chk_results = []
    all_chk_ok  = True
    for chk in chk_defs:
        start, end = chk["range"]
        if len(data) > chk["byte"] and len(data) >= end:
            calc  = calc_sff_checksum(data, start, end)
            stored = data[chk["byte"]]
            ok    = calc == stored
            chk_results.append({
                "name":   chk["name"],
                "label":  chk["label"],
                "calc":   f"0x{calc:02X}",
                "stored": f"0x{stored:02X}",
                "ok":     ok,
            })
            if not ok:
                all_chk_ok = False
        else:
            chk_results.append({
                "name":   chk["name"],
                "label":  chk["label"],
                "calc":   "—",
                "stored": "—",
                "ok":     False,
                "skip":   True,
            })
            all_chk_ok = False

    results["chk_results"]  = chk_results
    results["all_chk_ok"]   = all_chk_ok
    results["all_pass"] = md5_ok and zeros_ok and crc_ok and all_chk_ok and results["prefix_ok"]
    return results, None


# ── UI ────────────────────────────────────────────────────────────────────────


# Title
st.markdown("""
<div class="title-block">
    <h1>🔬 CISCO TRANSCEIVER VALIDATOR</h1>
    <p>SWITCH AUTHENTICATION SIMULATOR &nbsp;|&nbsp; SFP · QSFP · QSFP28 · 400G</p>
</div>
<hr class="divider">
""", unsafe_allow_html=True)

# Upload
st.markdown('<div class="section-label">01 — Upload Binary</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Drop the patched .bin file here", type=["bin"])

if not uploaded:
    st.markdown('<p class="info-mono">← upload a patched .bin to begin validation</p>',
                unsafe_allow_html=True)
else:
    raw = uploaded.read()
    results, error = validate_bin(raw)

    if error:
        st.error(f"⚠️  {error}")
    else:
        # ── Identification ────────────────────────────────────────────────────
        st.markdown('<div class="section-label">02 — Transceiver Identification</div>',
                    unsafe_allow_html=True)

        badge_cls = f"id-{results['badge']}"
        is_upper_only = results["block_mode"] == "upper_page_only"

        block_badge = ""
        if is_upper_only:
            block_badge = """
            <span style="font-family:'Share Tech Mono',monospace; font-size:1.4rem;
                         background:rgba(255,160,0,0.12); border:1px solid rgba(255,160,0,0.35);
                         color:#ffa000; border-radius:4px; padding:0.15rem 0.6rem;
                         margin-left:0.5rem; letter-spacing:0.08em;">
                ⚠ UPPER PAGE ONLY (A0h)
            </span>"""

        st.markdown(f"""
        <div style="margin-bottom:1rem;">
            <span class="id-badge {badge_cls}">
                0x{results['id_byte']:02X} — {results['t_name']}
            </span>
            <span style="font-family:'Share Tech Mono',monospace;
                         font-size:1.05rem; color:#2a5a6a;">
                {results['family']}
            </span>
            {block_badge}
        </div>
        """, unsafe_allow_html=True)

        if is_upper_only:
            st.info(
                "📦  **Upper Page Only (A0h)** — Este binário contém apenas a Upper Page "
                "(bytes 128–255 da EEPROM), carregada a partir do endereço 0. "
                "Os offsets foram ajustados automaticamente (−128 bytes). "
                "Campos como temperatura e monitoramento em tempo real não estão presentes neste bloco."
            )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Vendor",        results["vendor"])
        m2.metric("Part Number",   results["pn"])
        m3.metric("Serial Number", results["sn"])
        # Manu ID metric — highlight red if zero or unknown
        manu_label = f"0x{results['manu_id']:02X}"
        if results["manu_id_zero"]:
            manu_label += "  ⚠ ZERO"
        elif not results["manu_id_known"]:
            manu_label += "  ⚠ UNKNOWN"
        m4.metric("Manu ID", manu_label)

        # ── Warnings for bad field values ─────────────────────────────────────
        if results["manu_id_zero"]:
            st.warning("⚠️  Manu ID is 0x00 — patch was not applied or binary is unpatched.")
        elif not results["manu_id_known"]:
            st.warning(f"⚠️  Manu ID 0x{results['manu_id']:02X} is not in the known key list — cannot verify MD5. All checks shown below reflect raw stored values.")
        if results["vendor_zero"]:
            st.warning("⚠️  Vendor Name field is all zeros — field was not written.")
        if results["sn_zero"]:
            st.warning("⚠️  Serial Number field is all zeros — field was not written.")
        if not results["prefix_ok"]:
            st.warning(
                f"⚠️  Bytes before Manu ID ({results['prefix_offsets']}) "
                f"are **{results['prefix_stored']}** — expected **00 00**. "
                f"Patch incompleto: os dois zeros antes do Manu ID não foram inseridos."
            )

        # ── Validation checks ─────────────────────────────────────────────────
        st.markdown('<div class="section-label">03 — Authentication Checks</div>',
                    unsafe_allow_html=True)

        def check_block(title, ok, rows, note=None):
            badge     = '<span class="badge-pass">PASS</span>' if ok else '<span class="badge-fail">FAIL</span>'
            rows_html = ""
            for label, val, is_bad in rows:
                cls = "check-val-bad" if is_bad else "check-val"
                rows_html += f'<div class="check-row"><span class="check-key">{label}</span><span class="{cls}">{val}</span></div>'
            note_html = f'<div style="margin-top:0.5rem;font-size:1.0rem;color:#7a4a2a;">{note}</div>' if note else ""
            return f"""
            <div class="check-block">
                <div class="check-header">
                    <span class="check-name">{title}</span>
                    {badge}
                </div>
                {rows_html}
                {note_html}
            </div>"""

        # MD5 note if key unknown
        md5_note = None
        if not results["manu_id_known"]:
            md5_note = "⚠ Key unknown — calculated value is not meaningful"
        elif results["manu_id_zero"]:
            md5_note = "⚠ Manu ID is 0x00 — patch not applied"
        elif results["vendor_zero"] or results["sn_zero"]:
            md5_note = "⚠ Vendor or SN field is all zeros"

        md5_rows = [
            ("CALC",      results["md5_calc"],   False),
            ("STORED",    results["md5_stored"],  not results["md5_ok"]),
            ("VENDOR RAW",results["vendor_raw"],  results["vendor_zero"]),
            ("SN RAW",    results["sn_raw"],      results["sn_zero"]),
            ("MANU ID",   f"0x{results['manu_id']:02X}  {'(known ✓)' if results['manu_id_known'] else '(unknown ✗)'}", not results["manu_id_known"]),
        ]
        zero_rows = [
            ("RANGE",  results["zero_range"],           False),
            ("STORED", results["zeros_stored"] if not results["zeros_ok"] else "00 × 9 ✓",
                       not results["zeros_ok"]),
        ]
        crc_rows = [
            ("CALC",   results["crc_calc"],             False),
            ("STORED", results["crc_stored"],            not results["crc_ok"]),
        ]
        prefix_rows = [
            ("OFFSETS", results["prefix_offsets"],  False),
            ("STORED",  results["prefix_stored"],   not results["prefix_ok"]),
            ("EXPECTED","00 00",                    False),
        ]

        # Row 1 — MD5 (wide) + Zero Padding
        r1c1, r1c2 = st.columns([2, 1])
        with r1c1:
            st.markdown(check_block("MD5 HASH", results["md5_ok"], md5_rows, md5_note),
                        unsafe_allow_html=True)
        with r1c2:
            st.markdown(check_block("ZERO PADDING", results["zeros_ok"], zero_rows),
                        unsafe_allow_html=True)

        # Row 2 — CRC32 + 00 00 Prefix
        r2c1, r2c2 = st.columns(2)
        with r2c1:
            st.markdown(check_block("CRC32", results["crc_ok"], crc_rows),
                        unsafe_allow_html=True)
        with r2c2:
            st.markdown(check_block("00 00 PREFIX", results["prefix_ok"], prefix_rows),
                        unsafe_allow_html=True)

        # ── SFF Checksums row ─────────────────────────────────────────────────
        if results["chk_results"]:
            chk_cols = st.columns(len(results["chk_results"]))
            for col, chk in zip(chk_cols, results["chk_results"]):
                with col:
                    if chk.get("skip"):
                        rows = [("RANGE", f"bytes for {chk['name']}", False),
                                ("STATUS", "file too small", True)]
                    else:
                        rows = [
                            ("BYTE",   chk["label"],  False),
                            ("CALC",   chk["calc"],   False),
                            ("STORED", chk["stored"], not chk["ok"]),
                        ]
                    st.markdown(
                        check_block(f"SFF {chk['name']}", chk["ok"], rows),
                        unsafe_allow_html=True
                    )

        # ── Final result ──────────────────────────────────────────────────────
        st.markdown('<div class="section-label">04 — Result</div>', unsafe_allow_html=True)

        if results["all_pass"]:
            st.markdown(
                '<div class="final-pass">✅ &nbsp; ACCEPTED BY SWITCH</div>',
                unsafe_allow_html=True)
        else:
            # Build reason summary
            reasons = []
            if results["manu_id_zero"]:
                reasons.append("Manu ID is 0x00")
            elif not results["manu_id_known"]:
                reasons.append(f"Manu ID 0x{results['manu_id']:02X} unknown")
            if not results["md5_ok"]:
                reasons.append("MD5 mismatch")
            if not results["zeros_ok"]:
                reasons.append("Zero padding invalid")
            if not results["crc_ok"]:
                reasons.append("CRC32 mismatch")
            if results["vendor_zero"]:
                reasons.append("Vendor field empty")
            if results["sn_zero"]:
                reasons.append("Serial Number field empty")
            if not results["prefix_ok"]:
                reasons.append(f"00 00 prefix missing ({results['prefix_stored']} found)")
            reason_str = " &nbsp;·&nbsp; ".join(reasons)
            st.markdown(
                f'<div class="final-fail">❌ &nbsp; REJECTED BY SWITCH'
                f'<div style="font-size:1.5rem;font-weight:400;margin-top:0.4rem;'
                f'letter-spacing:0.05em;color:#ff9999;">{reason_str}</div></div>',
                unsafe_allow_html=True)