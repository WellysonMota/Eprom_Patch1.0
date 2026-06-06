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


def main():
    st.set_page_config(
        page_title="EPS Transceiver Coder",
        layout="wide",
        page_icon="🔐"
    )

    # ── CSS ──────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Rajdhani', sans-serif;
    }

    .stApp {
        background-color: #0a0e1a;
        background-image:
            radial-gradient(ellipse at 15% 15%, rgba(0,200,255,0.05) 0%, transparent 50%),
            radial-gradient(ellipse at 85% 85%, rgba(0,255,160,0.04) 0%, transparent 50%);
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background-color: #0d1520 !important;
        border-right: 1px solid #1a2a3a !important;
    }
    [data-testid="stSidebar"] * { font-family: 'Rajdhani', sans-serif !important; }

    /* ── Title block ── */
    .title-block {
        padding: 1.8rem 0 0.5rem 0;
    }
    .title-block h1 {
        font-size: 2.4rem;
        font-weight: 700;
        color: #00e5ff;
        text-shadow: 0 0 30px rgba(0,229,255,0.35);
        letter-spacing: 0.06em;
        margin-bottom: 0.1rem;
    }
    .title-block p {
        color: #3a6a7a;
        font-size: 0.88rem;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 0.12em;
        margin-top: 0;
    }

    /* ── Section labels ── */
    .section-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.72rem;
        letter-spacing: 0.2em;
        color: #00e5ff;
        text-transform: uppercase;
        margin: 1.8rem 0 0.6rem 0;
        padding-left: 0.6rem;
        border-left: 2px solid #00e5ff;
    }

    hr.divider {
        border: none;
        border-top: 1px solid #1a2a3a;
        margin: 1.2rem 0;
    }

    /* ── Selectbox / inputs ── */
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
        font-size: 0.8rem !important;
        letter-spacing: 0.08em !important;
    }

    /* ── Expander ── */
    [data-testid="stExpander"] {
        background-color: #0d1520 !important;
        border: 1px solid #1a2a3a !important;
        border-radius: 8px !important;
    }
    [data-testid="stExpander"] summary {
        color: #4a8a9a !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.85rem !important;
    }

    /* ── File uploader ── */
    [data-testid="stFileUploader"] {
        border: 1px dashed #1e3a4a !important;
        border-radius: 8px !important;
        background: #0d1520 !important;
        padding: 1rem !important;
    }

    /* ── Metrics ── */
    [data-testid="stMetric"] {
        background: #0d1823;
        border: 1px solid #1a2a3a;
        border-radius: 8px;
        padding: 0.8rem 1rem !important;
    }
    [data-testid="stMetricLabel"] {
        color: #3a6a7a !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.75rem !important;
        letter-spacing: 0.1em !important;
    }
    [data-testid="stMetricValue"] {
        color: #a0d8ef !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-size: 1.2rem !important;
        font-weight: 700 !important;
    }

    /* ── Code blocks ── */
    .stCode, [data-testid="stCode"] {
        background: #060c14 !important;
        border: 1px solid #1a2a3a !important;
        border-radius: 6px !important;
        font-family: 'Share Tech Mono', monospace !important;
        color: #00e87a !important;
        font-size: 0.82rem !important;
    }

    /* ── Buttons ── */
    .stDownloadButton button {
        width: 100%;
        background: rgba(0,229,255,0.08) !important;
        border: 1px solid rgba(0,229,255,0.3) !important;
        color: #00e5ff !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-weight: 700 !important;
        font-size: 1rem !important;
        letter-spacing: 0.12em !important;
        border-radius: 6px !important;
        padding: 0.6rem !important;
        transition: all 0.2s ease;
    }
    .stDownloadButton button:hover {
        background: rgba(0,229,255,0.15) !important;
        box-shadow: 0 0 20px rgba(0,229,255,0.2) !important;
    }

    /* ── Alerts ── */
    .stSuccess {
        background: rgba(0,255,140,0.07) !important;
        border: 1px solid rgba(0,255,140,0.25) !important;
        color: #ccffee !important;
        border-radius: 6px !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.85rem !important;
    }
    .stError {
        background: rgba(255,60,60,0.07) !important;
        border: 1px solid rgba(255,60,60,0.25) !important;
        border-radius: 6px !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.85rem !important;
    }
    .stInfo {
        background: rgba(0,180,255,0.06) !important;
        border: 1px solid rgba(0,180,255,0.2) !important;
        border-radius: 6px !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.82rem !important;
        color: #7ac8e8 !important;
    }

    /* ── Signature card ── */
    .sig-card {
        background: #060c14;
        border: 1px solid #1a2a3a;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.82rem;
        color: #00e87a;
        word-break: break-all;
        line-height: 1.8;
    }
    .sig-label {
        font-size: 0.72rem;
        color: #3a6a7a;
        letter-spacing: 0.12em;
        margin-bottom: 0.3rem;
    }

    /* ── Sidebar status ── */
    .sidebar-status {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem;
        color: #3a6a7a;
        padding: 0.8rem;
        border: 1px solid #1a2a3a;
        border-radius: 6px;
        background: #060c14;
        line-height: 1.8;
    }
    .sidebar-status .dot {
        display: inline-block;
        width: 7px; height: 7px;
        background: #00e87a;
        border-radius: 50%;
        margin-right: 6px;
        box-shadow: 0 0 6px #00e87a;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Title ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="title-block">
        <h1>🔐 TRANSCEIVER COMPATIBILITY & REBRAND TOOL</h1>
        <p>ENGINEERING UTILITY FOR OPTICAL TRANSCEIVERS v0.1 &nbsp;|&nbsp; EPS GLOBAL</p>
    </div>
    <hr class="divider">
    """, unsafe_allow_html=True)

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding: 1rem 0 1.5rem 0;">
            <div style="font-size:2rem;">🔐</div>
            <div style="font-family:'Rajdhani',sans-serif; font-size:1.1rem;
                        font-weight:700; color:#00e5ff; letter-spacing:0.1em;">
                EPS GLOBAL
            </div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.7rem;
                        color:#3a6a7a; letter-spacing:0.15em;">
                TRANSCEIVER TOOLS
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="sidebar-status">
            <div><span class="dot"></span>SYSTEM ONLINE</div>
            <div style="margin-top:0.5rem; color:#4a8a9a;">USER&nbsp;&nbsp;&nbsp;&nbsp;Wellyson Mota</div>
            <div style="color:#4a8a9a;">VERSION&nbsp;&nbsp;v0.1</div>
        </div>
        """, unsafe_allow_html=True)

    # ── STEP 1: Compatibility Settings ───────────────────────────────────────
    st.markdown('<div class="section-label">01 — Compatibility Settings</div>', unsafe_allow_html=True)

    col_k1, col_k2 = st.columns([2, 1])
    with col_k1:
        key_selection = st.selectbox(
            "Target Manufacturer Compatibility (Magic Key):",
            list(MAGIC_KEYS.keys()),
            help="Select the desired compatibility key. Cisco has different options."
        )

    selected_key_hex     = MAGIC_KEYS[key_selection]
    selected_manu_id_hex = key_selection[:2]

    # ── STEP 2: Optional Rebranding ──────────────────────────────────────────
    st.markdown('<div class="section-label">02 — Optional Rebranding</div>', unsafe_allow_html=True)

    with st.expander("📝 Overwrite Original Strings  (leave blank to keep original)"):
        c1, c2, c3 = st.columns(3)
        with c1:
            new_v = st.text_input("New Vendor Name",   placeholder="Ex: CISCO-FINISAR")
        with c2:
            new_p = st.text_input("New Part Number",   placeholder="Ex: QSFP-400G-DR4")
        with c3:
            new_s = st.text_input("New Serial Number", placeholder="Ex: EPS20260216")

    # ── STEP 3: Upload ───────────────────────────────────────────────────────
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

                    # ── STEP 4: Hardware Metadata ─────────────────────────────
                    st.markdown('<div class="section-label">04 — Hardware Metadata</div>',
                                unsafe_allow_html=True)

                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Vendor",       vendor)
                    m2.metric("Serial Number", sn)
                    m3.metric("Reach / Distance", distance)
                    m4.metric("Form Factor",  t_type)

                    m5, m6, m7 = st.columns([2, 1, 1])
                    m5.metric("Part Number",  part)
                    m6.metric("Media Type",   media)
                    m7.metric("Status",       status)

                    # ── STEP 5: Compatibility Signatures ─────────────────────
                    st.markdown('<div class="section-label">05 — Compatibility Signatures</div>',
                                unsafe_allow_html=True)

                    st.info(f"Using Key **{selected_manu_id_hex}** for MD5 generation.")

                    h1, h2 = st.columns(2)
                    with h1:
                        st.markdown('<div class="sig-label">INJECTED MD5 — 16 BYTES</div>',
                                    unsafe_allow_html=True)
                        st.markdown(f'<div class="sig-card">{md5_res}</div>',
                                    unsafe_allow_html=True)
                    with h2:
                        st.markdown('<div class="sig-label">REVERSED CRC32 — 4 BYTES</div>',
                                    unsafe_allow_html=True)
                        st.markdown(f'<div class="sig-card">{crc_res}</div>',
                                    unsafe_allow_html=True)

                    # ── STEP 6: Export ────────────────────────────────────────
                    st.markdown('<div class="section-label">06 — Export</div>',
                                unsafe_allow_html=True)

                    st.download_button(
                        label="🚀  DOWNLOAD PATCHED BINARY",
                        data=bytes(patched_bin),
                        file_name=f"patched_{sn}_cisco.bin",
                        mime="application/octet-stream",
                    )

                except Exception as e:
                    st.error(f"⚠️  Processing Error: {e}")
                    st.info("Check algorithms.py — certify it is accepting rebrand options.")


if __name__ == "__main__":
    main()
