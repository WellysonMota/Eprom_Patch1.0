import streamlit as st
import sys
from pathlib import Path

# --- Absolute Path Fix for Linux/PyCharm Environment ---
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.core.algorithms import apply_cisco_patch
from app.core.constants import MAGIC_KEYS


def main():
    # MANDATORY: Must be the first Streamlit command
    st.set_page_config(page_title="EPS Transceiver Coder", layout="wide")

    st.title("🔐 Transceiver Compatibility Tool")
    st.write("Engineering Utility for Optical Transceivers | EPS Global")

    # Sidebar Configuration
    st.sidebar.header("System Configs")
    st.sidebar.info("Application optimized for QSFP28 (100G) and SFP+ (10G) standards.")

    # 1. Target Manufacturer Selection (Main Page as per your change)
    st.subheader("1. 🎛️ Please Select the Target Manufacturer Compatibility")
    key_selection = st.selectbox("Target Manufacturer (Magic Key):", list(MAGIC_KEYS.keys()))
    selected_key_hex = MAGIC_KEYS[key_selection]
    selected_manu_id_hex = key_selection[:2]
    st.divider()

    # 2. File Upload Section
    st.subheader("2. 📤 Upload Original Dump")
    uploaded_file = st.file_uploader("", type=["bin"])
    st.info("💡 **Note:** Only the complete BIN file allowed, not only the A0, or A2 file.")

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()

        if len(file_bytes) < 256:
            st.error("Invalid file! The dump must be at least 256 bytes (Page 00h).")
        else:
            # --- Processing: Unpacking all 11 return values from the engine ---
            # Added 'distance' to match our 20km logic
            patched_bin, vendor, part, sn, t_type, media_type, distance, rev_name, status, md5_res, crc_res = apply_cisco_patch(
                file_bytes, selected_key_hex, selected_manu_id_hex
            )

            st.success(f"✅ Analysis complete!")
            st.divider()

            # 3. ⚙️ Transceivers Details & Hardware Check
            st.subheader("3.⚙️ Transceivers Details & Hardware Check")

            # Row 1: Core Identification
            row1_col1, row1_col2, row1_col3 = st.columns(3)
            with row1_col1:
                st.metric("Vendor", vendor)
            with row1_col2:
                st.metric("Serial Number", sn)
            with row1_col3:
                st.metric("Reach / Distance", distance)  # Crucial for 20km validation

            # Row 2: Technical Specifications
            row2_col1, row2_col2, row2_col3, = st.columns(3)
            with row2_col1:
                st.metric("Part Number", part)
            with row2_col2:
                st.metric("Form Factor", t_type)
            with row2_col3:
                st.metric("Revision", rev_name)

            row2_col4, = st.columns(1)
            # Row 3: Technical Specifications
            with row2_col4:
                st.metric("Media Type", media_type)
            st.divider()

            # 4. Technical Signatures for Engineering
            st.write("### 🛠️ Compatibility Signatures")
            h_col1, h_col2 = st.columns(2)
            with h_col1:
                st.write("**Generated MD5 (Injected at 0xE3):**")
                st.code(md5_res, language="text")
            with h_col2:
                st.write("**Reversed CRC32 (Injected at 0xFC):**")
                st.code(crc_res, language="text")

            # 5. Export Button
            st.divider()
            st.subheader("4. 📥 Export")
            st.download_button(
                label="🚀 Download Patched Binary",
                data=bytes(patched_bin),
                file_name=f"patched_{sn}_cisco.bin",
                mime="application/octet-stream",
                use_container_width=True

            )



if __name__ == "__main__":
    main()