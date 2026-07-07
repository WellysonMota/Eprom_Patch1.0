"""
Bulk Code Generator — EPS Global
Generates up to 20 Cisco-patched binaries from a single base template,
each with a different Serial Number (MD5 + CRC32 recomputed per SN).
"""
import io
import zipfile
import streamlit as st
from app.core.algorithms import apply_cisco_patch
from app.core.constants  import MAGIC_KEYS

# ─────────────────────────────────────────────────────────────────────────────
def page_bulk():
    # ── Title ─────────────────────────────────────────────────────────────────
    st.markdown("""
    <div class="title-block">
        <h1>⚡ BULK CODE GENERATOR</h1>
        <p>BATCH ENCODING — UP TO 20 UNITS FROM A SINGLE TEMPLATE &nbsp;|&nbsp; EPS GLOBAL</p>
    </div>
    <hr class="divider">
    """, unsafe_allow_html=True)

    # ── Section 01 — Base template ────────────────────────────────────────────
    st.markdown('<div class="section-label">01 — Base Template File</div>',
                unsafe_allow_html=True)
    st.caption("Upload the reference .bin. All 20 units will be identical to this file "
               "except for the Serial Number, MD5 and CRC32.")
    base_file = st.file_uploader("Drop the base .bin here", type=["bin"], key="bulk_base")

    # ── Section 02 — Cisco Key ────────────────────────────────────────────────
    st.markdown('<div class="section-label">02 — Cisco Compatibility Key</div>',
                unsafe_allow_html=True)
    col_key, _ = st.columns([2, 2])
    with col_key:
        key_selection    = st.selectbox("Magic Key", list(MAGIC_KEYS.keys()), key="bulk_key")
    selected_key_hex     = MAGIC_KEYS[key_selection]
    selected_manu_id_hex = key_selection[:2]

    # ── Section 03 — Common optional rebranding ───────────────────────────────
    st.markdown('<div class="section-label">03 — Common Fields (optional — same for all units)</div>',
                unsafe_allow_html=True)
    with st.expander("📝  Overwrite Vendor / Part Number — leave blank to keep original",
                     expanded=False):
        cb1, cb2 = st.columns(2)
        with cb1: common_vendor = st.text_input("Vendor Name", placeholder="Ex: CISCO-FINISAR",
                                                 key="bulk_vendor")
        with cb2: common_pn     = st.text_input("Part Number",  placeholder="Ex: QSFP-100G-AOC1M",
                                                 key="bulk_pn")

    # ── Section 04 — Serial Numbers ───────────────────────────────────────────
    st.markdown('<div class="section-label">04 — Serial Numbers (up to 20 units)</div>',
                unsafe_allow_html=True)
    st.caption("Fill in the serial numbers for each unit. Blank fields are skipped.")

    serial_numbers = []
    cols_per_row   = 4
    rows           = 5   # 4 × 5 = 20 fields
    idx            = 0
    for r in range(rows):
        cols = st.columns(cols_per_row)
        for c in range(cols_per_row):
            idx += 1
            with cols[c]:
                sn = st.text_input(f"SN {idx:02d}", key=f"bulk_sn_{idx:02d}",
                                   placeholder=f"Unit {idx:02d} SN")
                serial_numbers.append(sn.strip())

    # Filter out empty entries
    valid_sns = [(i+1, sn) for i, sn in enumerate(serial_numbers) if sn]

    st.markdown("")
    if not valid_sns:
        st.info("Fill in at least one Serial Number to enable batch generation.")

    # ── Section 05 — Generate ─────────────────────────────────────────────────
    st.markdown('<div class="section-label">05 — Generate Batch</div>', unsafe_allow_html=True)

    generate = st.button("⚡  GENERATE BATCH",
                          disabled=(base_file is None or len(valid_sns) == 0),
                          type="primary", use_container_width=True)

    if generate and base_file and valid_sns:
        base_bytes = base_file.read()
        if len(base_bytes) < 256:
            st.error("⚠️  Invalid base file — must have at least 256 bytes.")
            st.stop()

        results   = []
        errors    = []
        zip_buf   = io.BytesIO()

        with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            progress = st.progress(0, text="Generating…")
            for i, (slot, sn) in enumerate(valid_sns):
                try:
                    (patched, vendor, pn, sn_out, t_type, media,
                     dist, rev, status, md5_res, crc_res) = apply_cisco_patch(
                        base_bytes,
                        selected_key_hex,
                        selected_manu_id_hex,
                        new_vendor=common_vendor or None,
                        new_pn=common_pn         or None,
                        new_sn=sn,
                    )
                    fname = f"patched_{sn}_{selected_manu_id_hex}.bin"
                    zf.writestr(fname, bytes(patched))
                    results.append({
                        "slot":  slot,
                        "sn":    sn_out,
                        "md5":   md5_res,
                        "crc32": crc_res,
                        "file":  fname,
                        "data":  bytes(patched),
                        "ok":    True,
                    })
                except Exception as e:
                    errors.append({"slot": slot, "sn": sn, "error": str(e)})
                    results.append({"slot": slot, "sn": sn, "ok": False,
                                    "error": str(e), "md5": "—", "crc32": "—"})

                progress.progress((i+1) / len(valid_sns),
                                   text=f"Processed {i+1}/{len(valid_sns)}: {sn}")

            progress.empty()

        st.session_state["bulk_results"]  = results
        st.session_state["bulk_zip"]      = zip_buf.getvalue()
        st.session_state["bulk_zip_name"] = f"bulk_{selected_manu_id_hex}_{len(valid_sns)}units.zip"

    # ── Section 06 — Results ──────────────────────────────────────────────────
    if "bulk_results" in st.session_state:
        results  = st.session_state["bulk_results"]
        n_ok     = sum(1 for r in results if r["ok"])
        n_fail   = len(results) - n_ok

        st.markdown('<div class="section-label">06 — Results</div>', unsafe_allow_html=True)

        # Metrics
        mc1, mc2, mc3 = st.columns(3)
        mc1.metric("Total Units",  len(results))
        mc2.metric("✅ Generated", n_ok)
        mc3.metric("❌ Errors",    n_fail)

        if n_fail:
            st.error(f"⚠️  {n_fail} unit(s) failed — check SN values and base file.")

        # Results table
        st.markdown("""
        <div style="background:#FFFFFF;border:1px solid #C8C8C8;border-radius:4px;
                    padding:0.8rem 1rem;margin:0.8rem 0;font-family:'Roboto Mono',monospace;
                    font-size:0.8rem;">
        """, unsafe_allow_html=True)

        # Header
        hc1, hc2, hc3, hc4, hc5 = st.columns([1, 3, 6, 3, 3])
        hc1.markdown("**#**")
        hc2.markdown("**Serial Number**")
        hc3.markdown("**MD5 (16 bytes)**")
        hc4.markdown("**CRC32**")
        hc5.markdown("**Download**")

        st.markdown('<hr style="margin:0.3rem 0;border-color:#E0E0E0;">', unsafe_allow_html=True)

        for r in results:
            rc1, rc2, rc3, rc4, rc5 = st.columns([1, 3, 6, 3, 3])
            icon = "✅" if r["ok"] else "❌"
            rc1.markdown(f"{icon} **{r['slot']:02d}**")
            rc2.markdown(f"`{r['sn']}`")
            rc3.markdown(f"`{r['md5'][:16]}…`" if r["ok"] else f"*{r.get('error','')}*")
            rc4.markdown(f"`{r['crc32']}`")
            if r["ok"]:
                rc5.download_button(
                    "📥",
                    data=r["data"],
                    file_name=r["file"],
                    mime="application/octet-stream",
                    key=f"dl_unit_{r['slot']}",
                    help=f"Download {r['file']}",
                )

        st.markdown("</div>", unsafe_allow_html=True)

        # ── ZIP download ─────────────────────────────────────────────────────
        st.markdown('<div class="section-label">07 — Download All</div>', unsafe_allow_html=True)
        st.download_button(
            label=f"📦  DOWNLOAD ALL {n_ok} UNITS AS ZIP",
            data=st.session_state["bulk_zip"],
            file_name=st.session_state["bulk_zip_name"],
            mime="application/zip",
            key="dl_bulk_zip",
            disabled=(n_ok == 0),
        )
        st.caption(f"ZIP contains {n_ok} .bin file(s) — one per unit, named by Serial Number.")
