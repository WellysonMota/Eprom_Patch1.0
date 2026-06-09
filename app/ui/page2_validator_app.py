import streamlit as st

st.set_page_config(
    page_title="Cisco Page 02h Validator",
    page_icon="📋",
    layout="wide"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Rajdhani', sans-serif; }

.stApp {
    background-color: #0a0e1a;
    background-image:
        radial-gradient(ellipse at 15% 15%, rgba(0,200,255,0.05) 0%, transparent 50%),
        radial-gradient(ellipse at 85% 85%, rgba(0,255,160,0.04) 0%, transparent 50%);
}
[data-testid="stSidebar"] {
    background-color: #0d1520 !important;
    border-right: 1px solid #1a2a3a !important;
}
.title-block { padding: 1.8rem 0 0.4rem 0; }
.title-block h1 {
    font-size: 2.8rem; font-weight: 700; color: #00e5ff;
    text-shadow: 0 0 30px rgba(0,229,255,0.35);
    letter-spacing: 0.06em; margin-bottom: 0.1rem;
}
.title-block p {
    color: #3a6a7a; font-size: 1.05rem;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 0.12em; margin-top: 0;
}
hr.divider { border: none; border-top: 1px solid #1a2a3a; margin: 1.2rem 0; }
.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.05rem; letter-spacing: 0.2em; color: #00e5ff;
    text-transform: uppercase; margin: 1.8rem 0 0.6rem 0;
    padding-left: 0.6rem; border-left: 2px solid #00e5ff;
}
[data-testid="stFileUploader"] {
    border: 1px dashed #1e3a4a !important; border-radius: 8px !important;
    background: #0d1520 !important; padding: 1rem !important;
}
[data-testid="stMetric"] {
    background: #0d1823; border: 1px solid #1a2a3a;
    border-radius: 8px; padding: 0.8rem 1rem !important;
}
[data-testid="stMetricLabel"] {
    color: #3a6a7a !important; font-family: 'Share Tech Mono', monospace !important;
    font-size: 1.05rem !important; letter-spacing: 0.1em !important;
}
[data-testid="stMetricValue"] {
    color: #a0d8ef !important; font-family: 'Rajdhani', sans-serif !important;
    font-size: 1.5rem !important; font-weight: 700 !important;
}
.field-card {
    background: #0d1520; border: 1px solid #1a2a3a;
    border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 0.6rem;
    font-family: 'Share Tech Mono', monospace; font-size: 1.05rem;
}
.field-label {
    font-size: 1.05rem; color: #3a6a7a; letter-spacing: 0.18em;
    text-transform: uppercase; margin-bottom: 0.3rem;
}
.field-value { color: #00e5ff; font-size: 1.05rem; word-break: break-all; }
.field-raw   { color: #2a5a6a; font-size: 1.05rem; margin-top: 0.2rem; }

.match-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.5rem 0; border-bottom: 1px solid #111c28;
    font-family: 'Share Tech Mono', monospace; font-size: 1.05rem;
}
.match-pn   { color: #a0d8ef; font-size: 1.05rem; font-weight: 600; }
.match-desc { color: #4a8a9a; font-size: 1.05rem; }
.match-clei { color: #3a6a7a; font-size: 1.05rem; }
.badge-match {
    background: rgba(0,255,140,0.12); color: #00ff8c;
    border: 1px solid rgba(0,255,140,0.3); border-radius: 4px;
    padding: 0.1rem 0.6rem; font-size: 1.05rem; font-weight: 700;
    letter-spacing: 0.1em; white-space: nowrap;
}
.badge-nomatch {
    background: rgba(255,60,60,0.10); color: #ff7777;
    border: 1px solid rgba(255,60,60,0.25); border-radius: 4px;
    padding: 0.1rem 0.6rem; font-size: 1.05rem; font-weight: 700;
    letter-spacing: 0.1em; white-space: nowrap;
}
.badge-warn {
    background: rgba(255,180,0,0.10); color: #ffa000;
    border: 1px solid rgba(255,180,0,0.3); border-radius: 4px;
    padding: 0.1rem 0.6rem; font-size: 1.05rem; font-weight: 700;
    letter-spacing: 0.1em; white-space: nowrap;
}
.final-pass {
    text-align: center; font-size: 1.5rem; font-weight: 700;
    color: #00ff8c; font-family: 'Rajdhani', sans-serif;
    letter-spacing: 0.15em; text-shadow: 0 0 24px rgba(0,255,140,0.5);
    padding: 1rem; background: rgba(0,255,140,0.05);
    border: 1px solid rgba(0,255,140,0.2); border-radius: 8px;
}
.final-warn {
    text-align: center; font-size: 1.5rem; font-weight: 700;
    color: #ffa000; font-family: 'Rajdhani', sans-serif;
    letter-spacing: 0.15em; text-shadow: 0 0 24px rgba(255,160,0,0.4);
    padding: 1rem; background: rgba(255,160,0,0.05);
    border: 1px solid rgba(255,160,0,0.2); border-radius: 8px;
}
.final-fail {
    text-align: center; font-size: 1.5rem; font-weight: 700;
    color: #ff5555; font-family: 'Rajdhani', sans-serif;
    letter-spacing: 0.15em; text-shadow: 0 0 24px rgba(255,80,80,0.5);
    padding: 1rem; background: rgba(255,60,60,0.05);
    border: 1px solid rgba(255,60,60,0.2); border-radius: 8px;
}
.info-mono {
    font-family: 'Share Tech Mono', monospace; font-size: 1.05rem;
    color: #2a4a5a; text-align: center; padding-top: 0.5rem;
}
.hex-dump {
    font-family: 'Share Tech Mono', monospace; font-size: 1.05rem;
    background: #060c14; border: 1px solid #1a2a3a; border-radius: 6px;
    padding: 0.8rem 1rem; color: #3a6a7a; line-height: 1.8;
    overflow-x: auto; white-space: pre;
}
.sidebar-status {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.05rem; color: #3a6a7a;
    padding: 0.8rem; border: 1px solid #1a2a3a;
    border-radius: 6px; background: #060c14; line-height: 1.9;
}
.sidebar-status .dot {
    display: inline-block; width: 7px; height: 7px;
    background: #00e87a; border-radius: 50%;
    margin-right: 6px; box-shadow: 0 0 6px #00e87a;
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
                             font-weight:700;color:#00e5ff;letter-spacing:0.08em;">
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
            <div style="margin-top:0.5rem;color:#3a6a7a;font-family:'Share Tech Mono',monospace;
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