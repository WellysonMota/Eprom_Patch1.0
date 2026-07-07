import streamlit as st
import sys
from pathlib import Path

#updated 20/06

# --- 🛠️ PATH FIX ---
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.core.algorithms import apply_cisco_patch, calculate_sff_checksum
from app.core.constants import MAGIC_KEYS, TRANSCEIVER_IDENTIFIERS

# ── SHARED CSS ────────────────────────────────────────────────────────────────
SHARED_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; font-size: 16px; color: #1A1A1A; }
.stApp { background-color: #E8E8E8; }
[data-testid="stSidebar"] { background-color: #2A2A2A !important; border-right: 3px solid #B42D27 !important; }
[data-testid="stSidebar"] * { font-family: 'Inter', sans-serif !important; color: #E8E8E8 !important; }
[data-testid="stSidebar"] .stButton button { background-color: #3A3A3A !important; border: 1px solid #555 !important; color: #E8E8E8 !important; font-family: 'Inter', sans-serif !important; font-size: 1.0rem !important; font-weight: 500 !important; border-radius: 4px !important; text-align: left !important; padding: 0.5rem 0.8rem !important; }
[data-testid="stSidebar"] .stButton button[kind="primary"] { background-color: #B42D27 !important; border-color: #B42D27 !important; color: #FFFFFF !important; font-weight: 700 !important; }
[data-testid="stSidebar"] .stButton button:hover { background-color: #B42D27 !important; border-color: #B42D27 !important; color: #FFFFFF !important; }
.title-block { background-color: #2A2A2A; border-left: 5px solid #B42D27; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; border-radius: 0 4px 4px 0; }
.title-block h1 { font-size: 1.8rem; font-weight: 700; color: #FFFFFF; letter-spacing: 0.03em; margin: 0 0 0.2rem 0; }
.title-block p { color: #AAAAAA; font-size: 0.9rem; font-family: 'Roboto Mono', monospace; letter-spacing: 0.05em; margin: 0; }
.section-label { font-family: 'Inter', sans-serif; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.15em; color: #777777; text-transform: uppercase; margin: 1.8rem 0 0.6rem 0; padding: 0.3rem 0.6rem; background-color: #DCDCDC; border-left: 3px solid #2E6A9C; border-radius: 0 3px 3px 0; }
hr.divider { border: none; border-top: 2px solid #C8C8C8; margin: 1rem 0; }
[data-testid="stSelectbox"] > div, [data-testid="stTextInput"] > div > div { background-color: #FFFFFF !important; border: 1px solid #AAAAAA !important; border-radius: 4px !important; color: #1A1A1A !important; font-family: 'Inter', sans-serif !important; font-size: 1.0rem !important; }
[data-testid="stSelectbox"] > div:focus-within, [data-testid="stTextInput"] > div > div:focus-within { border-color: #2E6A9C !important; box-shadow: 0 0 0 2px rgba(46,106,156,0.2) !important; }
label, .stTextInput label, .stSelectbox label { color: #444444 !important; font-family: 'Inter', sans-serif !important; font-size: 0.9rem !important; font-weight: 600 !important; letter-spacing: 0.02em !important; }
[data-testid="stExpander"] { background-color: #F4F4F4 !important; border: 1px solid #C8C8C8 !important; border-radius: 4px !important; }
[data-testid="stExpander"] summary { color: #444444 !important; font-family: 'Inter', sans-serif !important; font-size: 0.95rem !important; font-weight: 600 !important; }
[data-testid="stFileUploader"] { border: 2px dashed #AAAAAA !important; border-radius: 4px !important; background: #F4F4F4 !important; padding: 1rem !important; }
[data-testid="stMetric"] { background: #FFFFFF; border: 1px solid #C8C8C8; border-top: 3px solid #2E6A9C; border-radius: 4px; padding: 0.8rem 1rem !important; }
[data-testid="stMetricLabel"] { color: #777777 !important; font-family: 'Inter', sans-serif !important; font-size: 0.8rem !important; font-weight: 600 !important; letter-spacing: 0.06em !important; text-transform: uppercase !important; }
[data-testid="stMetricValue"] { color: #1A1A1A !important; font-family: 'Inter', sans-serif !important; font-size: 1.3rem !important; font-weight: 700 !important; }
.stDownloadButton button { width: 100%; background-color: #B42D27 !important; border: none !important; color: #FFFFFF !important; font-family: 'Inter', sans-serif !important; font-weight: 700 !important; font-size: 1.05rem !important; letter-spacing: 0.06em !important; border-radius: 4px !important; padding: 0.65rem 1rem !important; transition: background-color 0.15s ease; }
.stDownloadButton button:hover { background-color: #8B1F1A !important; }
.stSuccess > div { background-color: #E8F5E9 !important; border-left: 4px solid #2E7D32 !important; color: #1B5E20 !important; border-radius: 0 4px 4px 0 !important; font-family: 'Inter', sans-serif !important; font-size: 0.95rem !important; font-weight: 500 !important; }
.stError > div { background-color: #FFEBEE !important; border-left: 4px solid #B42D27 !important; color: #7F0000 !important; border-radius: 0 4px 4px 0 !important; font-family: 'Inter', sans-serif !important; font-size: 0.95rem !important; }
.stWarning > div { background-color: #FFF3E0 !important; border-left: 4px solid #E65100 !important; color: #BF360C !important; border-radius: 0 4px 4px 0 !important; font-family: 'Inter', sans-serif !important; font-size: 0.95rem !important; }
.stInfo > div { background-color: #E3F2FD !important; border-left: 4px solid #2E6A9C !important; color: #0D47A1 !important; border-radius: 0 4px 4px 0 !important; font-family: 'Inter', sans-serif !important; font-size: 0.95rem !important; }
.stCode, [data-testid="stCode"] { background: #F4F4F4 !important; border: 1px solid #C8C8C8 !important; border-radius: 4px !important; font-family: 'Roboto Mono', monospace !important; color: #1A1A1A !important; font-size: 0.9rem !important; }
.sig-card { background: #FFFFFF; border: 1px solid #C8C8C8; border-left: 3px solid #2E6A9C; border-radius: 0 4px 4px 0; padding: 0.8rem 1rem; font-family: 'Roboto Mono', monospace; font-size: 0.95rem; color: #1A1A1A; word-break: break-all; line-height: 1.8; }
.sig-label { font-size: 0.78rem; font-weight: 700; color: #777777; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 0.3rem; }
.sidebar-status { font-family: 'Roboto Mono', monospace; font-size: 0.85rem; color: #AAAAAA; padding: 0.8rem; border: 1px solid #444444; border-radius: 4px; background: #1A1A1A; line-height: 2.0; }
.sidebar-status .dot { display: inline-block; width: 8px; height: 8px; background: #4CAF50; border-radius: 50%; margin-right: 6px; box-shadow: 0 0 5px #4CAF50; }
.check-block { background: #FFFFFF; border: 1px solid #C8C8C8; border-top: 3px solid #C8C8C8; border-radius: 0 0 4px 4px; padding: 0.9rem 1.1rem; margin-bottom: 0.6rem; font-family: 'Roboto Mono', monospace; font-size: 0.88rem; }
.check-block.pass-block { border-top-color: #2E7D32; }
.check-block.fail-block { border-top-color: #B42D27; }
.check-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.check-name { font-family: 'Inter', sans-serif; font-size: 0.78rem; font-weight: 700; color: #444444; letter-spacing: 0.12em; text-transform: uppercase; }
.badge-pass { background-color: #2E7D32; color: #FFFFFF; border-radius: 3px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.08em; }
.badge-fail { background-color: #B42D27; color: #FFFFFF; border-radius: 3px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.08em; }
.check-row { display: flex; gap: 0.8rem; margin-top: 0.2rem; border-top: 1px solid #F0F0F0; padding-top: 0.2rem; }
.check-key { color: #888888; min-width: 80px; font-size: 0.82rem; }
.check-val { color: #1A1A1A; word-break: break-all; }
.check-val-bad { color: #B42D27; font-weight: 600; word-break: break-all; }
.final-pass { text-align: center; font-size: 1.4rem; font-weight: 700; color: #FFFFFF; font-family: 'Inter', sans-serif; letter-spacing: 0.08em; padding: 1rem; background-color: #2E7D32; border-radius: 4px; border-left: 6px solid #1B5E20; }
.final-fail { text-align: center; font-size: 1.4rem; font-weight: 700; color: #FFFFFF; font-family: 'Inter', sans-serif; letter-spacing: 0.08em; padding: 1rem; background-color: #B42D27; border-radius: 4px; border-left: 6px solid #7F0000; }
.final-warn { text-align: center; font-size: 1.4rem; font-weight: 700; color: #FFFFFF; font-family: 'Inter', sans-serif; letter-spacing: 0.08em; padding: 1rem; background-color: #E65100; border-radius: 4px; border-left: 6px solid #BF360C; }
.id-badge { display: inline-block; font-family: 'Roboto Mono', monospace; font-size: 0.85rem; font-weight: 500; padding: 0.2rem 0.8rem; border-radius: 3px; margin-right: 0.5rem; border: 1px solid; }
.id-sfp    { background: #E3F2FD; border-color: #2E6A9C; color: #1A3A6B; }
.id-qsfp   { background: #F3E5F5; border-color: #6A1B9A; color: #4A148C; }
.id-400g   { background: #FFF3E0; border-color: #E65100; color: #BF360C; }
.id-unknown{ background: #F5F5F5; border-color: #9E9E9E; color: #616161; }
.field-card { background: #FFFFFF; border: 1px solid #C8C8C8; border-radius: 4px; padding: 1rem 1.2rem; margin-bottom: 0.6rem; font-family: 'Inter', sans-serif; font-size: 0.95rem; }
.field-label { font-size: 0.75rem; font-weight: 700; color: #777777; letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 0.3rem; }
.field-value { color: #1A1A1A; font-size: 1.05rem; font-weight: 600; word-break: break-all; }
.field-raw   { color: #AAAAAA; font-size: 0.82rem; font-family: 'Roboto Mono', monospace; margin-top: 0.2rem; }
.match-row { display: flex; justify-content: space-between; align-items: center; padding: 0.45rem 0; border-bottom: 1px solid #F0F0F0; font-size: 0.95rem; }
.match-pn   { color: #1A1A1A; font-size: 1.0rem; font-weight: 700; }
.match-desc { color: #555555; font-size: 0.9rem; }
.match-clei { color: #888888; font-family: 'Roboto Mono', monospace; font-size: 0.85rem; }
.badge-match   { background-color: #2E7D32; color: #FFFFFF; border-radius: 3px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.06em; white-space: nowrap; }
.badge-nomatch { background-color: #B42D27; color: #FFFFFF; border-radius: 3px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.06em; white-space: nowrap; }
.badge-warn    { background-color: #E65100; color: #FFFFFF; border-radius: 3px; padding: 0.15rem 0.6rem; font-size: 0.75rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.06em; white-space: nowrap; }
.hex-dump { font-family: 'Roboto Mono', monospace; font-size: 0.88rem; background: #F4F4F4; border: 1px solid #C8C8C8; border-radius: 4px; padding: 0.8rem 1rem; color: #444444; line-height: 1.8; overflow-x: auto; white-space: pre; }
.info-mono { font-family: 'Roboto Mono', monospace; font-size: 0.9rem; color: #AAAAAA; text-align: center; padding-top: 0.5rem; }
</style>
"""


# ── PAGE DEFINITIONS ──────────────────────────────────────────────────────────
def page_patcher():
    st.markdown(SHARED_CSS, unsafe_allow_html=True)
    st.markdown("""
    <div class="title-block">
        <h1>🔐 TRANSCEIVER COMPATIBILITY & REBRAND TOOL</h1>
        <p>ENGINEERING UTILITY FOR OPTICAL TRANSCEIVERS v0.1 &nbsp;|&nbsp; EPS GLOBAL</p>
    </div>
    <hr class="divider">
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-label">01 — Compatibility Settings</div>', unsafe_allow_html=True)
    col_k1, _ = st.columns([2, 1])
    with col_k1:
        key_selection = st.selectbox(
            "Target Manufacturer Compatibility (Magic Key):",
            list(MAGIC_KEYS.keys()),
            help="Select the desired compatibility key. Cisco has different options."
        )
    selected_key_hex     = MAGIC_KEYS[key_selection]
    selected_manu_id_hex = key_selection[:2]

    st.markdown('<div class="section-label">02 — Optional Rebranding</div>', unsafe_allow_html=True)
    with st.expander("📝  Overwrite Original Strings — leave blank to keep original", expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1: new_v = st.text_input("New Vendor Name",   placeholder="Ex: CISCO-FINISAR")
        with c2: new_p = st.text_input("New Part Number",   placeholder="Ex: QSFP-400G-DR4")
        with c3: new_s = st.text_input("New Serial Number", placeholder="Ex: EPS20260216")

    st.markdown('<div class="section-label">03 — Upload Original Dump</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Drop the .bin file here", type=["bin"])

    # ── Process + cache in session_state (survives rerun on download click) ──
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        cache_key  = f"patch_{uploaded_file.name}_{key_selection}_{new_v}_{new_p}_{new_s}"

        if len(file_bytes) < 256:
            st.error("⚠️  Invalid file — must have at least 256 bytes (A0 memory section).")
            st.session_state.pop("patch_result",    None)
            st.session_state.pop("patch_cache_key", None)
        else:
            NOT_DEPLOYED = {"JUNIPER", "INTEL", "HUAWEI"}
            if key_selection in NOT_DEPLOYED:
                st.error(f"⚠️  {key_selection} coding not deployed yet.")
                st.info("Check algorithms.py and add the corresponding patch function.")
            elif key_selection not in MAGIC_KEYS:
                st.error("⚠️  This compatibility vendor has not been deployed yet.")
                st.info("Check algorithms.py and certify it is accepting rebrand options.")
            else:
                if st.session_state.get("patch_cache_key") != cache_key:
                    try:
                        result = apply_cisco_patch(
                            file_bytes, selected_key_hex, selected_manu_id_hex,
                            new_vendor=new_v or None,
                            new_pn=new_p    or None,
                            new_sn=new_s    or None,
                        )
                        st.session_state["patch_result"]    = result
                        st.session_state["patch_cache_key"] = cache_key
                        st.session_state["patch_filename"]  = uploaded_file.name
                    except Exception as e:
                        st.error(f"⚠️  Processing Error: {e}")
                        st.info("Check algorithms.py — certify it is accepting rebrand options.")
                        st.session_state.pop("patch_result",    None)
                        st.session_state.pop("patch_cache_key", None)

    # ── Results block — reads from session_state, always survives rerun ───────
    if "patch_result" in st.session_state:
        (patched_bin, vendor, part, sn, t_type, media,
         distance, rev, status, md5_res, crc_res) = st.session_state["patch_result"]

        st.success("✅  Analysis & Patching Complete!")

        st.markdown('<div class="section-label">04 — Hardware Metadata</div>', unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Vendor", vendor)
        m2.metric("Serial Number", sn)
        m3.metric("Reach / Distance", distance)
        m4.metric("Form Factor", t_type)
        m5, m6, m7 = st.columns([2, 1, 1])
        m5.metric("Part Number", part)
        m6.metric("Media Type", media)
        m7.metric("Status", status)

        st.markdown('<div class="section-label">05 — Compatibility Signatures</div>', unsafe_allow_html=True)
        st.info(f"Using Key **{selected_manu_id_hex}** for MD5 generation.")
        h1, h2 = st.columns(2)
        with h1:
            st.markdown('<div class="sig-label">INJECTED MD5 — 16 BYTES</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="sig-card">{md5_res}</div>', unsafe_allow_html=True)
        with h2:
            st.markdown('<div class="sig-label">REVERSED CRC32 — 4 BYTES</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="sig-card">{crc_res}</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-label">06 — Export</div>', unsafe_allow_html=True)
        st.download_button(
            label="🚀  DOWNLOAD PATCHED BINARY",
            data=bytes(patched_bin),
            file_name=f"patched_{sn}_{selected_manu_id_hex}.bin",
            mime="application/octet-stream",
        )

        st.markdown('<div class="section-label">07 — String (Copy for EEPROM IDE)</div>',
                    unsafe_allow_html=True)
        st.caption("Single-line hex string — paste directly into your EEPROM programming IDE.")
        st.code(bytes(patched_bin).hex().upper(), language="text")


def page_validator():
    import hashlib, zlib, struct
    st.markdown(SHARED_CSS, unsafe_allow_html=True)
    validator_path = current_dir / "sfp_validator_app.py"
    if validator_path.exists():
        with open(validator_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        code = code.replace(
            '# st.set_page_config(\n    page_title="Cisco Transceiver Validator",\n    page_icon="🔬",\n    layout="wide"\n)',
            ''
        )
        exec(code, {"__name__": "__validator__"})
    else:
        st.error("sfp_validator_app.py not found in the same directory.")
        st.info("Place sfp_validator_app.py alongside main.py and restart.")


def page_page2():
    page2_path = current_dir / "page2_validator_app.py"
    if page2_path.exists():
        with open(page2_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        code = code.replace(
            '# st.set_page_config(\n    page_title="Cisco Page 02h Validator",\n    page_icon="📋",\n    layout="wide"\n)',
            ''
        )
        exec(code, {"__name__": "__page2__"})
    else:
        st.error("page2_validator_app.py not found in the same directory.")
        st.info("Place page2_validator_app.py alongside main.py and restart.")


def page_tools():
    tools_path = current_dir / "tools_app.py"
    if tools_path.exists():
        with open(tools_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        exec(code, {"__name__": "__tools__"})
    else:
        st.error("tools_app.py not found in the same directory.")
        st.info("Place tools_app.py alongside main.py and restart.")


def page_ftlc():
    ftlc_path = current_dir / "ftlc_field_encoder.py"
    if ftlc_path.exists():
        with open(ftlc_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        exec(code, {"__name__": "__ftlc__"})
    else:
        st.error("ftlc_field_encoder.py not found in the same directory.")
        st.info("Place ftlc_field_encoder.py alongside main.py and restart.")


def page_ftlc_validator():
    validator_path = current_dir / "ftlc_validator_app.py"
    if validator_path.exists():
        with open(validator_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        exec(code, {"__name__": "__ftlc_validator__"})
    else:
        st.error("ftlc_validator_app.py not found in the same directory.")
        st.info("Place ftlc_validator_app.py alongside main.py and restart.")


def page_arista():
    arista_path = current_dir / "arista_encoder_app.py"
    if arista_path.exists():
        with open(arista_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        exec(code, {"__name__": "__arista__"})
    else:
        st.error("arista_encoder_app.py not found in the same directory.")
        st.info("Place arista_encoder_app.py alongside main.py and restart.")


def page_arista_validator():
    validator_path = current_dir / "arista_validator_app.py"
    if validator_path.exists():
        with open(validator_path) as f:
            code = f.read()
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        exec(code, {"__name__": "__arista_validator__"})
    else:
        st.error("arista_validator_app.py not found in the same directory.")
        st.info("Place arista_validator_app.py alongside main.py and restart.")


# ── NAVIGATION ────────────────────────────────────────────────────────────────
PAGES = {
    "patcher":    {"icon": "🔐", "label": "Patch Tool",            "fn": page_patcher},
    "validator":  {"icon": "🔬", "label": "Transceiver Validator", "fn": page_validator},
    "page2":      {"icon": "📋", "label": "Page 02h Validator",    "fn": page_page2},
    "tools":      {"icon": "🔧", "label": "Tools",                 "fn": page_tools},
    "ftlc":       {"icon": "📡", "label": "Field Encoder (FTLC)",  "fn": page_ftlc},
    "ftlc_val":   {"icon": "✅", "label": "FTLC Validator",        "fn": page_ftlc_validator},
    "arista":     {"icon": "🅰️", "label": "Arista Encoder",        "fn": page_arista},
    "arista_val": {"icon": "🅰️", "label": "Arista Validator",      "fn": page_arista_validator},
}


def main():
    st.set_page_config(
        page_title="EPS Transceiver Tools",
        layout="wide",
        page_icon="🔐"
    )

    if "active_page" not in st.session_state:
        st.session_state.active_page = "patcher"

    with st.sidebar:
        st.markdown("""
        <div style="padding:1rem 0.5rem 1.5rem 0.5rem;border-bottom:1px solid #444;margin-bottom:1rem;">
            <div style="display:flex;align-items:center;gap:0.6rem;">
                <div style="background:#B42D27;width:4px;height:2.5rem;border-radius:2px;flex-shrink:0;"></div>
                <div>
                    <div style="font-family:'Inter',sans-serif;font-size:1.2rem;
                                font-weight:700;color:#FFFFFF;letter-spacing:0.05em;line-height:1.2;">
                        EPS GLOBAL
                    </div>
                    <div style="font-family:'Roboto Mono',monospace;font-size:0.75rem;
                                color:#AAAAAA;letter-spacing:0.1em;margin-top:0.1rem;">
                        TRANSCEIVER TOOLS
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(
            '<div style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;'
            'color:#AAAAAA;letter-spacing:0.15em;padding:0 0.4rem 0.5rem 0.4rem;'
            'text-transform:uppercase;">NAVIGATION</div>',
            unsafe_allow_html=True
        )

        for key, page in PAGES.items():
            is_active = st.session_state.active_page == key
            if st.button(
                f"{page['icon']}  {page['label']}",
                key=f"nav_{key}",
                use_container_width=True,
                type="primary" if is_active else "secondary",
            ):
                st.session_state.active_page = key
                st.rerun()

        st.markdown(
            "<hr style='border:none;border-top:1px solid #1a2a3a;margin:1rem 0;'>",
            unsafe_allow_html=True
        )

        st.markdown("""
        <div class="sidebar-status">
            <div><span class="dot"></span>SYSTEM ONLINE</div>
            <div style="margin-top:0.4rem;color:#AAAAAA;">USER&nbsp;&nbsp;&nbsp;&nbsp;Wellyson Mota</div>
            <div style="color:#AAAAAA;">VERSION&nbsp;&nbsp;v0.1</div>
        </div>
        """, unsafe_allow_html=True)

    PAGES[st.session_state.active_page]["fn"]()


if __name__ == "__main__":
    main()