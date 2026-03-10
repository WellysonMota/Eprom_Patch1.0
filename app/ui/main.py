import streamlit as st
import sys
from pathlib import Path

#Foi corrigdo o bug no checksum
# --- 🛠️ CORREÇÃO DE CAMINHO (PATH FIX) ---
# Garante que o Python encontre a pasta 'app' no Debian/GCP ou PyCharm
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.core.algorithms import apply_cisco_patch, calculate_sff_checksum
from app.core.constants import MAGIC_KEYS, TRANSCEIVER_IDENTIFIERS


def main():
    # Configuração da Página
    st.set_page_config(page_title="EPS Transceiver Coder", layout="wide", page_icon="🔐")

    st.title("🔐 Transceiver Compatibility & Rebrand Tool")
    st.write("Engineering Utility for Optical Transceivers v0.1| **EPS Global**")

    # --- SIDEBAR ---
    st.sidebar.header("🚀 System Status")
    st.sidebar.info(f"**User:** Wellyson Mota")


    # --- ETAPA 1: CONFIGURAÇÃO DE COMPATIBILIDADE ---
    st.subheader("1. 🎛️ Compatibility Settings")
    col_k1, col_k2 = st.columns([2, 1])

    with col_k1:
        key_selection = st.selectbox(
            "Target Manufacturer Compatibility (Magic Key):",
            list(MAGIC_KEYS.keys()),
            help="Select the desired compatibility key, Cisco has different options"
        )

    # Extrai o ID (ex: "08") e a Key Hex do dicionário
    selected_key_hex = MAGIC_KEYS[key_selection]
    selected_manu_id_hex = key_selection[:2]  # Pega os 2 primeiros caracteres (ex: 08)

    st.divider()

    # --- ETAPA 2: REBRANDING OPCIONAL ---
    with st.expander("📝 Optional Rebranding (Overwrite Original Strings)"):
        st.write("Leave it blank to keep to original values from the dump.")
        c1, c2, c3 = st.columns(3)
        with c1:
            new_v = st.text_input("New Vendor Name", placeholder="Ex: CISCO-FINISAR")
        with c2:
            new_p = st.text_input("New Part Number", placeholder="Ex: QSFP-400G-DR4")
        with c3:
            new_s = st.text_input("New Serial Number", placeholder="Ex: EPS20260216")

    st.divider()

    # --- ETAPA 3: UPLOAD E PROCESSAMENTO ---
    st.subheader("2. 📤 Upload Original Dump")
    uploaded_file = st.file_uploader("Drop the .bin file here", type=["bin"])

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()

        if len(file_bytes) < 256:
            st.error("Invalid file! The file must have at least 256 bytes - Normal A0 memory section")
        else:
            # PROCESSAMENTO NO ALGORITHMS
            # Passamos os novos campos de texto para a função
            print(MAGIC_KEYS)
            print(f"User selected: " + key_selection)

            if key_selection in MAGIC_KEYS and key_selection != "JUNIPER" and key_selection != "INTEL" and key_selection != "HUAWEI":

                try:
                    # O algoritmo retorna 11 valores
                    (patched_bin, vendor, part, sn, t_type, media,
                     distance, rev, status, md5_res, crc_res) = apply_cisco_patch(
                        file_bytes, selected_key_hex, selected_manu_id_hex,
                        new_vendor=new_v, new_pn=new_p, new_sn=new_s
                    )

                    st.success("✅ Analysis & Patching Complete!")

                    # --- DASHBOARD DE MÉTRICAS ---
                    st.subheader("3. ⚙️ Hardware Metadata Check")

                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Current Vendor", vendor)
                    m2.metric("Serial Number", sn)
                    m3.metric("Reach / Distance", distance)
                    m4.metric("Form Factor", t_type)

                    m5, m6, m7 = st.columns([2, 1, 1])
                    m5.metric("Part Number", part)
                    m6.metric("Media Type", media)
                    m7.metric("Status", status)

                    # --- ASSINATURAS TÉCNICAS ---
                    st.write("### 🛠️ Compatibility Signatures")
                    st.info(f"Using **Key {selected_manu_id_hex}** for MD5 Generation.")

                    h1, h2 = st.columns(2)
                    with h1:
                        st.write("**Injected MD5 (16 bytes):**")
                        st.code(md5_res, language="text")
                    with h2:
                        st.write("**Reversed CRC32 (4 bytes):**")
                        st.code(crc_res, language="text")

                    # --- EXPORTAÇÃO ---
                    st.divider()
                    st.subheader("4. 📥 Export")
                    st.download_button(
                        label="🚀 Download Patched Binary",
                        data=bytes(patched_bin),
                        file_name=f"patched_{sn}_cisco.bin",
                        mime="application/octet-stream",
                        use_container_width=True
                    )

                except Exception as e:
                    st.error(f"Processing Error: {e}")
                    st.info("Check the functions on algorithms.py, certify it is accepting rebrand options. ")

            elif key_selection == "JUNIPER":


                st.error(f"Processing Error: Juniper coding not deployed yet. ")
                st.info("Check the functions on algorithms.py, certify it is accepting rebrand options.")


            elif key_selection == "INTEL":


                st.error(f"Processing Error: Intel coding not deployed yet. ")
                st.info("Check the functions on algorithms.py, certify it is accepting rebrand options.")

            else:


                st.error(f"Processing Error: This compatibility vendor has not been deployed yet. ")
                st.info("Check the functions on algorithms.py, certify it is accepting rebrand options.")

if __name__ == "__main__":
    main()