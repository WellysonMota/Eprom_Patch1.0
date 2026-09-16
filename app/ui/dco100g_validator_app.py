"""
100G DCO Validator — Configurable Register Validation Tool  v1.0
EPS Global · Vendor-agnostic (no Cisco/Arista patch logic) validation of
Coherent 100G DCO (FTLC335x/FTLC3353) I2C memory dumps against a
pre-configured set of expected register values.

Unlike FTLC Validator / Arista Validator, this page does NOT assume a
fixed check list. You define the checks (Page + Offset + expected value)
in the configuration table before uploading dumps, save/load that
configuration as JSON, then validate one or many dumps against it —
same PASS/FAIL report pattern as the other validators.
"""

import streamlit as st
import json, re
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# PARSER (same I2C dump format as FTLC / Arista Validator)
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
            # Lower Memory (physical bytes 0x00-0x7F) is merged into Page 00 —
            # this app addresses everything by numeric hex page only, never
            # a "lower" string, matching how the confirmed register map below
            # (e.g. Page 00:0x6B, Page 00:0x8E) is written.
            current_page = 0
            if 0 not in pages:
                pages[0] = {}
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
    return bytes([p.get(start + i, 0x20) for i in range(n)]).decode("ascii", "replace")

# ─────────────────────────────────────────────────────────────────────────────
# ITU CHANNEL TABLES — informational "Channel set" readout
# (identical source table to FTLC Validator; Page 12h offset 0x88/0x89)
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
GRID_SPACING_MAP = {
    0x0: "3.125GHz", 0x1: "6.25GHz", 0x2: "12.5GHz", 0x3: "25GHz",
    0x4: "50GHz",    0x5: "100GHz",  0x6: "33GHz",   0x7: "75GHz",
}
def resolve_channel(ch_raw, grid_spacing_code=0x5):
    if ch_raw > 32767: ch_raw -= 65536
    if grid_spacing_code == 0x4:
        info, label = CHAN_50GHZ.get(ch_raw), "50GHz"
    else:
        info, label = CHAN_100GHZ.get(ch_raw), "100GHz"
    if info:
        return (info[0], info[1], info[2], label)
    return None

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT CHECK CONFIGURATION
# CONFIRMED = pulled from real-dump-validated offsets already used elsewhere in
# this app (FTLC/Arista Validator, ftlc_field_encoder). TO CONFIRM = requested
# by Welly but not yet field-confirmed against a real 100G DCO dump — included
# as ready-to-fill rows, disabled by default so an unconfirmed offset can never
# silently produce a false PASS.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CHECKS = [
    # ── Core 11-step procedure — confirmed against Welly's notepad
    #    ("Procedures made in the Samples we tested and was approved by the
    #    customer" / Leandro Script CH36). Page is always numeric hex.
    {"Enabled": True,  "Label": "(1) FlexTune Enable",                    "Page": "1E", "Offset": "C8", "Width": 1, "Compare": "Equals", "Expected": "00", "Note": "00=Disabled, 01=Enabled"},
    {"Enabled": True,  "Label": "(1.2) Nominal Wavelength = Actual",      "Page": "B0", "Offset": "81", "Width": 1, "Compare": "Equals", "Expected": "01", "Note": "Writes actual tuned wavelength to nominal (reported to host)"},
    {"Enabled": True,  "Label": "(2) Channel Set",                        "Page": "12", "Offset": "88", "Width": 2, "Compare": "Equals", "Expected": "0006", "Note": "Ch37 example. Positive ch: 00+N — Negative ch: FF+N"},
    {"Enabled": True,  "Label": "(3) Override PowerClass",                "Page": "1E", "Offset": "FD", "Width": 1, "Compare": "Equals", "Expected": "01", "Note": "Leandro script=01h, Firouz script=02h — set per target"},
    {"Enabled": True,  "Label": "(4) Disabled PowerClass 8",              "Page": "00", "Offset": "81", "Width": 1, "Compare": "Equals", "Expected": "CD", "Note": "Solved PowerClass8 host issue on Huawei S6730"},
    {"Enabled": True,  "Label": "(5) Extended Link (Chromatic Dispersion)","Page": "1E", "Offset": "C7", "Width": 1, "Compare": "Equals", "Expected": "01", "Note": "00=Disabled, 01=Enabled"},
    {"Enabled": True,  "Label": "(6) Decreased RX Alarm",                 "Page": "03", "Offset": "B2", "Width": 2, "Compare": "Equals", "Expected": "0001", "Note": "RX threshold alarm, 2 bytes"},
    {"Enabled": True,  "Label": "(7) Decreased RX Warning",               "Page": "03", "Offset": "B6", "Width": 2, "Compare": "Equals", "Expected": "0002", "Note": "RX threshold warning, 2 bytes"},
    {"Enabled": True,  "Label": "(8) Decreased LosAssert RX",             "Page": "1E", "Offset": "C2", "Width": 2, "Compare": "Equals", "Expected": "F254", "Note": "-35dBm"},
    {"Enabled": True,  "Label": "(9) Decreased LosDeAssert RX",           "Page": "1E", "Offset": "C4", "Width": 2, "Compare": "Equals", "Expected": "F286", "Note": "-34.5dBm"},
    {"Enabled": True,  "Label": "(10) Extended Reach SMF (Link Length)",  "Page": "00", "Offset": "8E", "Width": 1, "Compare": "Equals", "Expected": "78",   "Note": "120km, units of 1km"},
    {"Enabled": True,  "Label": "(11) MaxPower Change",                   "Page": "00", "Offset": "6B", "Width": 1, "Compare": "Equals", "Expected": "1A",   "Note": "2.6W, units of 0.1W"},
    {"Enabled": True,  "Label": "Transceiver Type / Ext. Compliance Code","Page": "B0", "Offset": "80", "Width": 1, "Compare": "Equals", "Expected": "06",   "Note": "LR4=06h, LR1/ZR1=01h"},

    # ── Additional registers from the notepad — supplementary/ambiguous,
    #    left OFF by default; enable once you confirm the expected value.
    {"Enabled": False, "Label": "FlexTune Grid Spacing",                  "Page": "1E", "Offset": "CB", "Width": 1, "Compare": "Equals", "Expected": "05", "Note": "0100b/04=50GHz(default), 0101b/05=100GHz"},
    {"Enabled": False, "Label": "FlexTune Status (read-only)",            "Page": "1E", "Offset": "CA", "Width": 1, "Compare": "Equals", "Expected": "",   "Note": "Status register — set Expected once a known-good value is confirmed"},
    {"Enabled": False, "Label": "Add Channel (nm) to Vendor PN",          "Page": "1E", "Offset": "C1", "Width": 1, "Compare": "Equals", "Expected": "00", "Note": "00=Normal/default, 01=Enable — module must be in LOW POWER to set; non-volatile"},
    {"Enabled": False, "Label": "High/Low Power Mode",                    "Page": "00", "Offset": "5D", "Width": 1, "Compare": "Equals", "Expected": "0D", "Note": "0D=High Power, 00=Low Power — confirm before enabling, notes were ambiguous"},
    {"Enabled": False, "Label": "SFF Unlock Registers (write-only)",      "Page": "00", "Offset": "7B", "Width": 4, "Compare": "Equals", "Expected": "556E6C6B", "Note": "⚠️ transient write-trigger ('Unlk') — won't read back after Save, not useful as a PASS/FAIL check"},
    {"Enabled": False, "Label": "SFF Save Registers (write-only)",        "Page": "00", "Offset": "7B", "Width": 4, "Compare": "Equals", "Expected": "53617665", "Note": "⚠️ transient write-trigger ('Save') — same caveat as above"},
    {"Enabled": False, "Label": "CMIS Unlock Registers (write-only)",     "Page": "00", "Offset": "7A", "Width": 4, "Compare": "Equals", "Expected": "556E6C6B", "Note": "⚠️ transient write-trigger — CMIS variant of the SFF unlock, same caveat"},
    {"Enabled": False, "Label": "CMIS Save Registers (write-only)",       "Page": "00", "Offset": "7A", "Width": 4, "Compare": "Equals", "Expected": "53617665", "Note": "⚠️ transient write-trigger — CMIS variant of the SFF save, same caveat"},
]

COMPARE_OPS = ["Equals", "Not Equals", ">=", "<="]

def get_value(pages: dict, page_str: str, offset_str: str, width: int):
    """Resolve a page/offset/width combo to an integer, or None if unavailable.
    Page is always a numeric hex page number (00, 1E, B0, 03, 12, ...) —
    Page 00 covers both Lower Memory (0x00-0x7F) and Page 00h Upper (0x80-0xFF),
    since parse_dump merges them into the same dict."""
    try:
        page_key = int((page_str or "").strip(), 16)
    except (ValueError, TypeError):
        return None
    p = pages.get(page_key)
    if not p:
        return None
    try:
        offset = int((offset_str or "").strip(), 16)
    except (ValueError, TypeError):
        return None
    val = 0
    for i in range(max(width, 1)):
        b = p.get(offset + i)
        if b is None:
            return None
        val = (val << 8) | b
    return val

def run_checks(pages: dict, checks_df: pd.DataFrame):
    results = []
    for _, row in checks_df.iterrows():
        if not row.get("Enabled", False):
            continue
        label   = row.get("Label", "").strip() or "(unnamed check)"
        page    = str(row.get("Page", "")).strip()
        offset  = str(row.get("Offset", "")).strip()
        width   = int(row.get("Width", 1) or 1)
        compare = row.get("Compare", "Equals")
        exp_raw = str(row.get("Expected", "")).strip()

        if not offset:
            results.append((label, False, "not run", "(offset not set)", "Set an Offset to run this check"))
            continue
        if not exp_raw:
            results.append((label, False, "not run", "(expected not set)", "Set an Expected value to run this check"))
            continue

        try:
            expected = int(exp_raw, 16)
        except ValueError:
            results.append((label, False, "not run", f"invalid expected '{exp_raw}'", ""))
            continue

        cur = get_value(pages, page, offset, width)
        if cur is None:
            results.append((label, False, f"Page {page}h:{offset} absent", f"0x{expected:0{width*2}X}", ""))
            continue

        if compare == "Equals":
            ok = cur == expected
        elif compare == "Not Equals":
            ok = cur != expected
        elif compare == ">=":
            ok = cur >= expected
        elif compare == "<=":
            ok = cur <= expected
        else:
            ok = cur == expected

        results.append((label, ok, f"0x{cur:0{width*2}X}", f"{compare} 0x{expected:0{width*2}X}", ""))
    return results

def validate_dump(text: str, checks_df: pd.DataFrame) -> dict:
    pages = parse_dump(text)
    if not pages:
        return {"error": "No valid pages found — invalid or empty file."}

    p0  = pages.get(0, {})
    p12 = pages.get(0x12, {})
    sn  = asc(p0, 196, 16).rstrip() if p0 else ""
    pn  = asc(p0, 168, 16).rstrip() if p0 else ""

    ch_msb = p12.get(0x88) if p12 else None
    ch_lsb = p12.get(0x89) if p12 else None
    ch_info = None
    if ch_msb is not None and ch_lsb is not None:
        ch_raw = (ch_msb << 8) | ch_lsb
        ch_info = resolve_channel(ch_raw)

    checks = run_checks(pages, checks_df)
    all_ok = all(c[1] for c in checks) if checks else False

    return {
        "error": None, "sn": sn, "pn": pn,
        "ch_msb": ch_msb, "ch_lsb": ch_lsb, "ch_info": ch_info,
        "checks": checks, "all_ok": all_ok, "n_checks": len(checks),
    }

# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="100G DCO Validator", page_icon="🛰️", layout="wide")
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
.check-label{min-width:340px;font-weight:600;color:#2A2A2A}
.check-cur{font-family:monospace;font-size:11px;min-width:120px}
.check-exp{font-family:monospace;font-size:11px;color:#888}
.ch-badge{background:#2E6A9C;color:#fff;padding:2px 8px;border-radius:3px;
          font-size:12px;font-weight:bold;font-family:monospace;margin-right:6px}
.ch-detail{color:#444;font-size:12px}
.tbc-warn{background:#FFF3E0;border-left:4px solid #E65100;color:#BF360C;
          padding:10px 14px;border-radius:0 4px 4px 0;font-family:Arial,sans-serif;
          font-size:13px;margin:8px 0 16px 0}
</style>
""", unsafe_allow_html=True)

ha, hb = st.columns([1, 10])
with ha: st.markdown("### 🛰️")
with hb:
    st.markdown("""
    <p class="report-title">100G DCO Validator — Configurable Register Report
    <span style="font-size:13px;color:#999;font-weight:normal">v1.0</span></p>
    <p class="report-sub">EPS Global · Vendor-agnostic Coherent 100G DCO validation · pre-configured Page/Offset checks · SFF-8636 dump format</p>
    """, unsafe_allow_html=True)
st.markdown("---")

# ── Init session state ──────────────────────────────────────────────────────
if "dco_checks_df" not in st.session_state:
    st.session_state.dco_checks_df = pd.DataFrame(DEFAULT_CHECKS)

# ── Configuration panel ─────────────────────────────────────────────────────
st.markdown('<div class="sec">1 · Configure Checks</div>', unsafe_allow_html=True)
st.caption(
    "Enable/disable each check, and set Page (numeric hex only — 00, 1E, B0, 03, 12, "
    "etc. Page 00 covers both Lower Memory 0x00–0x7F and Page 00h Upper 0x80–0xFF), "
    "Offset (hex), Width (bytes), Compare operator and Expected value (hex). "
    "Rows marked ⚠️ in Note are write-only trigger registers or need a value you "
    "haven't confirmed yet — leave them off until you're sure."
)

edited_df = st.data_editor(
    st.session_state.dco_checks_df,
    num_rows="dynamic",
    use_container_width=True,
    key="dco_checks_editor",
    column_config={
        "Enabled": st.column_config.CheckboxColumn("Run?", width="small"),
        "Label":   st.column_config.TextColumn("Check", width="large"),
        "Page":    st.column_config.TextColumn("Page", width="small", help="Numeric hex page only, e.g. 00, 1E, B0, 03, 12"),
        "Offset":  st.column_config.TextColumn("Offset", width="small", help="Hex byte offset within the page, e.g. C8"),
        "Width":   st.column_config.NumberColumn("Width (B)", width="small", min_value=1, max_value=4, step=1),
        "Compare": st.column_config.SelectboxColumn("Compare", width="small", options=COMPARE_OPS),
        "Expected":st.column_config.TextColumn("Expected", width="small", help="Hex value, e.g. 02"),
        "Note":    st.column_config.TextColumn("Note", width="large"),
    },
)
st.session_state.dco_checks_df = edited_df

n_tbc = int((~edited_df["Enabled"]) .sum()) if "Enabled" in edited_df else 0
n_on  = int(edited_df["Enabled"].sum()) if "Enabled" in edited_df else 0
if n_tbc:
    st.markdown(
        f'<div class="tbc-warn">⚠️ {n_tbc} check(s) currently disabled — fill in Page/Offset/Expected '
        f'once confirmed against a real dump, then tick "Run?" to include them. {n_on} check(s) will run now.</div>',
        unsafe_allow_html=True)

cc1, cc2, cc3 = st.columns([1, 1, 4])
with cc1:
    if st.button("↺ Reset to defaults"):
        st.session_state.dco_checks_df = pd.DataFrame(DEFAULT_CHECKS)
        st.rerun()
with cc2:
    cfg_json = json.dumps(edited_df.to_dict(orient="records"), indent=2)
    st.download_button("💾 Export config (JSON)", data=cfg_json,
                        file_name="100g_dco_validator_config.json", mime="application/json")
with cc3:
    uploaded_cfg = st.file_uploader("📂 Import config (JSON)", type=["json"],
                                     key="cfg_upload", label_visibility="collapsed")
    if uploaded_cfg is not None:
        try:
            loaded = json.load(uploaded_cfg)
            st.session_state.dco_checks_df = pd.DataFrame(loaded)
            st.success("Configuration loaded — review the table above, then upload dumps below.")
            st.rerun()
        except Exception as e:
            st.error(f"Could not load config: {e}")

st.markdown("---")

# ── File upload ──────────────────────────────────────────────────────────────
st.markdown('<div class="sec">2 · Upload Dump Files & Validate</div>', unsafe_allow_html=True)
files = st.file_uploader(
    "I2C Memory Dump TXT files (select one or multiple for batch validation)",
    type=["txt"], accept_multiple_files=True, key="dco_batch_upload")

if not files:
    st.markdown("""
    <div style="background:#fff;border-radius:6px;padding:16px;color:#555;font-family:Arial;font-size:13px">
    Awaiting upload. The checks configured above will run against every file you drop here.
    </div>""", unsafe_allow_html=True)
    st.stop()

results = []
for f in files:
    text = f.read().decode("utf-8", errors="replace")
    r = validate_dump(text, edited_df)
    r["filename"] = f.name
    results.append(r)

n_total = len(results)
n_ok    = sum(1 for r in results if not r["error"] and r["all_ok"])
n_fail  = n_total - n_ok

st.markdown('<div class="sec">Batch Summary</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Units", n_total)
m2.metric("✅ PASS", n_ok)
m3.metric("❌ FAIL", n_fail)
rate = f"{100*n_ok//n_total}%" if n_total else "—"
m4.metric("Pass Rate", rate)
st.markdown("---")

st.markdown('<div class="sec">Unit Reports</div>', unsafe_allow_html=True)
for r in results:
    if r["error"]:
        st.error(f"**{r['filename']}** — {r['error']}")
        continue

    badge_cls = "badge-pass" if r["all_ok"] else "badge-fail"
    badge_txt = "PASS" if r["all_ok"] else "FAIL"
    exp_label = f"{'✅' if r['all_ok'] else '❌'}  {r['filename']}  |  SN: {r['sn'] or '—'}  |  PN: {r['pn'] or '—'}"

    with st.expander(exp_label, expanded=not r["all_ok"]):
        st.markdown(f'<span class="{badge_cls}">{badge_txt}</span>', unsafe_allow_html=True)
        st.markdown("")

        st.markdown('<div class="sec">Unit Summary</div>', unsafe_allow_html=True)
        ch_disp = "Page 12h absent"
        if r["ch_info"]:
            itu_ch, freq_thz, wl_nm, grid_lbl = r["ch_info"]
            ch_disp = (f"<span class='ch-badge'>Ch {itu_ch} ({grid_lbl})</span>"
                       f"<span class='ch-detail'>{freq_thz:.3f} THz &nbsp;·&nbsp; {wl_nm:.2f} nm "
                       f"&nbsp;·&nbsp; raw: 0x{r['ch_msb']:02X} 0x{r['ch_lsb']:02X}</span>")
        elif r.get("ch_msb") is not None:
            ch_disp = f"raw: 0x{r['ch_msb']:02X} 0x{r['ch_lsb']:02X} (not in supported channel table)"

        summary_rows = [
            ("Part Number (Programmed)", r["pn"] or "—"),
            ("Serial Number (Programmed)", r["sn"] or "—"),
            ("Channel (Page 12h 0x88/0x89)", ch_disp),
            ("Checks run", str(r["n_checks"])),
        ]
        rows_html = "".join(
            f"<div class='summary-row'><span class='summary-lbl'>{lbl}</span>"
            f"<span class='summary-val'>{val}</span></div>"
            for lbl, val in summary_rows)
        st.markdown(f"<div class='summary-box'>{rows_html}</div>", unsafe_allow_html=True)

        st.markdown('<div class="sec">Configured Checks</div>', unsafe_allow_html=True)
        if not r["checks"]:
            st.info("No checks are enabled — tick \"Run?\" on at least one row above and re-upload.")
        for label, ok, cur, tgt, hint in r["checks"]:
            icon  = "✅" if ok else "❌"
            color = "#1A5A2A" if ok else "#B42D27"
            st.markdown(
                f"<div class='check-row'>"
                f"<div style='width:20px'>{icon}</div>"
                f"<div class='check-label'>{label}</div>"
                f"<code class='check-cur' style='color:{color}'>{cur}</code>"
                f"<span style='color:#aaa;font-size:11px'>expected:</span>"
                f"<code class='check-exp'>{tgt}</code>"
                f"{f'<span style=\"color:#E65100;font-size:11px\">{hint}</span>' if hint else ''}"
                f"</div>", unsafe_allow_html=True)

# ── CSV Export ────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="sec">Export</div>', unsafe_allow_html=True)
csv_lines = ["filename,sn,pn,channel_itu,result,checks_run,failed_checks"]
for r in results:
    if r["error"]:
        csv_lines.append(f'{r["filename"]},,,,"ERROR","{r["error"]}",')
        continue
    ch_itu = r["ch_info"][0] if r["ch_info"] else ""
    failed = [c[0] for c in r["checks"] if not c[1]]
    status = "PASS" if r["all_ok"] else "FAIL"
    csv_lines.append(
        f'{r["filename"]},{r["sn"]},{r["pn"]},{ch_itu},{status},{r["n_checks"]},"{"; ".join(failed)}"')
csv_data = "\n".join(csv_lines)
st.download_button("📥 Download Validation Report (CSV)",
                   data=csv_data, file_name="100G_DCO_Validation_Report.csv",
                   mime="text/csv")
st.markdown("---")
st.caption("EPS Global · 100G DCO Validator v1.0 · Configurable Page/Offset register validation · SFF-8636 dump format")
