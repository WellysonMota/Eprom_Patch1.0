import streamlit as st
import sys
from pathlib import Path

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
[data-testid="stSidebar"] * { font-family: 'Rajdhani', sans-serif !important; }

.title-block { padding: 1.8rem 0 0.5rem 0; }
.title-block h1 {
    font-size: 2.8rem; font-weight: 700; color: #00e5ff;
    text-shadow: 0 0 30px rgba(0,229,255,0.35);
    letter-spacing: 0.06em; margin-bottom: 0.1rem;
}
.title-block p {
    color: #3a6a7a; font-size: 1.4rem;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 0.12em; margin-top: 0;
}
.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.0rem; letter-spacing: 0.2em;
    color: #00e5ff; text-transform: uppercase;
    margin: 1.8rem 0 0.6rem 0;
    padding-left: 0.6rem; border-left: 2px solid #00e5ff;
}
hr.divider { border: none; border-top: 1px solid #1a2a3a; margin: 1.2rem 0; }

[data-testid="stSelectbox"] > div,
[data-testid="stTextInput"] > div > div {
    background-color: #0d1823 !important;
    border: 1px solid #1e3a4a !important;
    border-radius: 6px !important;
    color: #a0d8ef !important;
    font-family: 'Share Tech Mono', monospace !important;
}
label, .stTextInput label, .stSelectbox label {
    color: #4a8a9a !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important; letter-spacing: 0.08em !important;
}
[data-testid="stExpander"] {
    background-color: #0d1520 !important;
    border: 1px solid #1a2a3a !important; border-radius: 8px !important;
}
[data-testid="stExpander"] summary {
    color: #4a8a9a !important;
    font-family: 'Share Tech Mono', monospace !important; font-size: 1.15rem !important;
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
    font-size: 1.0rem !important; letter-spacing: 0.1em !important;
}
[data-testid="stMetricValue"] {
    color: #a0d8ef !important; font-family: 'Rajdhani', sans-serif !important;
    font-size: 1.5rem !important; font-weight: 700 !important;
}
.stCode, [data-testid="stCode"] {
    background: #060c14 !important; border: 1px solid #1a2a3a !important;
    border-radius: 6px !important; font-family: 'Share Tech Mono', monospace !important;
    color: #00e87a !important; font-size: 1.5rem !important;
}
.stDownloadButton button {
    width: 100%;
    background: rgba(0,229,255,0.08) !important;
    border: 1px solid rgba(0,229,255,0.3) !important;
    color: #00e5ff !important; font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important; font-size: 1.5rem !important;
    letter-spacing: 0.12em !important; border-radius: 6px !important;
    padding: 0.6rem !important; transition: all 0.2s ease;
}
.stDownloadButton button:hover {
    background: rgba(0,229,255,0.15) !important;
    box-shadow: 0 0 20px rgba(0,229,255,0.2) !important;
}
.stSuccess {
    background: rgba(0,255,140,0.07) !important;
    border: 1px solid rgba(0,255,140,0.25) !important;
    color: #ccffee !important; border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important; font-size: 1.15rem !important;
}
.stError {
    background: rgba(255,60,60,0.07) !important;
    border: 1px solid rgba(255,60,60,0.25) !important;
    border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important; font-size: 1.15rem !important;
}
.stInfo {
    background: rgba(0,180,255,0.06) !important;
    border: 1px solid rgba(0,180,255,0.2) !important;
    border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 1.5rem !important; color: #7ac8e8 !important;
}
.sig-card {
    background: #060c14; border: 1px solid #1a2a3a; border-radius: 8px;
    padding: 1rem 1.2rem; font-family: 'Share Tech Mono', monospace;
    font-size: 1.5rem; color: #00e87a; word-break: break-all; line-height: 1.8;
}
.sig-label {
    font-size: 1.0rem; color: #3a6a7a;
    letter-spacing: 0.12em; margin-bottom: 0.3rem;
}
.sidebar-status {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.05rem; color: #3a6a7a;
    padding: 0.8rem; border: 1px solid #1a2a3a;
    border-radius: 6px; background: #060c14; line-height: 1.8;
}
.sidebar-status .dot {
    display: inline-block; width: 7px; height: 7px;
    background: #00e87a; border-radius: 50%;
    margin-right: 6px; box-shadow: 0 0 6px #00e87a;
}

/* ── Nav links in sidebar ── */
.nav-link {
    display: flex; align-items: center; gap: 0.6rem;
    padding: 0.55rem 0.8rem; border-radius: 6px; margin-bottom: 0.3rem;
    font-family: 'Share Tech Mono', monospace; font-size: 1.5rem;
    text-decoration: none; transition: background 0.15s ease;
    border: 1px solid transparent; cursor: pointer;
    color: #4a8a9a;
}
.nav-link:hover  { background: rgba(0,229,255,0.07); color: #00e5ff;
                   border-color: rgba(0,229,255,0.2); }
.nav-link.active { background: rgba(0,229,255,0.1);  color: #00e5ff;
                   border-color: rgba(0,229,255,0.3); }
.nav-icon { font-size: 1.5rem; }
.nav-label { letter-spacing: 0.08em; }
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

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        if len(file_bytes) < 256:
            st.error("⚠️  Invalid file — must have at least 256 bytes (A0 memory section).")
        else:
            NOT_DEPLOYED = {"JUNIPER", "INTEL", "HUAWEI"}
            if key_selection in NOT_DEPLOYED:
                st.error(f"⚠️  {key_selection} coding not deployed yet.")
                st.info("Check algorithms.py and add the corresponding patch function.")
            elif key_selection not in MAGIC_KEYS:
                st.error("⚠️  This compatibility vendor has not been deployed yet.")
                st.info("Check algorithms.py and certify it is accepting rebrand options.")
            else:
                try:
                    (patched_bin, vendor, part, sn, t_type, media,
                     distance, rev, status, md5_res, crc_res) = apply_cisco_patch(
                        file_bytes, selected_key_hex, selected_manu_id_hex,
                        new_vendor=new_v, new_pn=new_p, new_sn=new_s
                    )
                    st.success("✅  Analysis & Patching Complete!")

                    st.markdown('<div class="section-label">04 — Hardware Metadata</div>', unsafe_allow_html=True)
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Vendor", vendor); m2.metric("Serial Number", sn)
                    m3.metric("Reach / Distance", distance); m4.metric("Form Factor", t_type)
                    m5, m6, m7 = st.columns([2, 1, 1])
                    m5.metric("Part Number", part); m6.metric("Media Type", media); m7.metric("Status", status)

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
                        file_name=f"patched_{sn}_cisco.bin",
                        mime="application/octet-stream",
                    )
                except Exception as e:
                    st.error(f"⚠️  Processing Error: {e}")
                    st.info("Check algorithms.py — certify it is accepting rebrand options.")


def page_validator():
    # Import validator logic inline to avoid circular deps
    import hashlib, zlib, struct

    st.markdown(SHARED_CSS, unsafe_allow_html=True)

    # paste full sfp_validator_app CSS + logic here via import
    # We exec the validator file with streamlit context intact
    validator_path = current_dir / "sfp_validator_app.py"
    if validator_path.exists():
        with open(validator_path) as f:
            code = f.read()
        # Remove set_page_config (already set) and run
        code = code.replace("st.set_page_config(", "# st.set_page_config(")
        # Close the parenthesis that was opened
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


# ── NAVIGATION ────────────────────────────────────────────────────────────────
PAGES = {
    "patcher":   {"icon": "🔐", "label": "Patch Tool",         "fn": page_patcher},
    "validator": {"icon": "🔬", "label": "Transceiver Validator","fn": page_validator},
    "page2":     {"icon": "📋", "label": "Page 02h Validator",  "fn": page_page2},
}

def main():
    st.set_page_config(
        page_title="EPS Transceiver Tools",
        layout="wide",
        page_icon="🔐"
    )

    # Track active page in session state
    if "active_page" not in st.session_state:
        st.session_state.active_page = "patcher"

    # ── Sidebar — standard across all pages ─────────────────────────────────
    with st.sidebar:
        # Logo + brand
        st.markdown("""
        <div style="text-align:center; padding:1rem 0 1.5rem 0;">
            <div style="font-size:2.8rem;">🔐</div>
            <div style="font-family:'Rajdhani',sans-serif; font-size:1.4rem;
                        font-weight:700; color:#00e5ff; letter-spacing:0.1em;">
                EPS GLOBAL
            </div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.95rem;
                        color:#3a6a7a; letter-spacing:0.15em;">
                TRANSCEIVER TOOLS
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Navigation label
        st.markdown(
            '<div style="font-family:&#39;Share Tech Mono&#39;,monospace;font-size:0.95rem;'
            'color:#2a4a5a;letter-spacing:0.2em;padding:0 0.4rem 0.5rem 0.4rem;">NAVIGATION</div>',
            unsafe_allow_html=True
        )

        # Nav buttons
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

        # Divider
        st.markdown(
            "<hr style='border:none;border-top:1px solid #1a2a3a;margin:1rem 0;'>",
            unsafe_allow_html=True
        )

        # User / version — identical on every page
        st.markdown("""
        <div class="sidebar-status">
            <div><span class="dot"></span>SYSTEM ONLINE</div>
            <div style="margin-top:0.5rem;color:#4a8a9a;">USER&nbsp;&nbsp;&nbsp;&nbsp;Wellyson Mota</div>
            <div style="color:#4a8a9a;">VERSION&nbsp;&nbsp;v0.1</div>
        </div>
        """, unsafe_allow_html=True)

    # ── Render active page ────────────────────────────────────────────────────
    PAGES[st.session_state.active_page]["fn"]()


if __name__ == "__main__":
    main()