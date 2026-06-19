import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="EPS Tools", page_icon="🔧", layout="wide")

# ── CSS (EPS Industrial Theme) ────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; font-size: 16px; color: #1A1A1A; }
.stApp { background-color: #E8E8E8; }

[data-testid="stSidebar"] { background-color: #2A2A2A !important; border-right: 3px solid #B42D27 !important; }
[data-testid="stSidebar"] * { font-family: 'Inter', sans-serif !important; color: #E8E8E8 !important; }

.title-block {
    background-color: #2A2A2A; border-left: 5px solid #B42D27;
    padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; border-radius: 0 4px 4px 0;
}
.title-block h1 { font-size: 1.8rem; font-weight: 700; color: #FFFFFF; letter-spacing: 0.03em; margin: 0 0 0.2rem 0; }
.title-block p  { color: #AAAAAA; font-size: 0.9rem; font-family: 'Roboto Mono', monospace; letter-spacing: 0.05em; margin: 0; }

.section-label {
    font-family: 'Inter', sans-serif; font-size: 0.78rem; font-weight: 700;
    letter-spacing: 0.15em; color: #777777; text-transform: uppercase;
    margin: 1.8rem 0 0.6rem 0; padding: 0.3rem 0.6rem;
    background-color: #DCDCDC; border-left: 3px solid #2E6A9C; border-radius: 0 3px 3px 0;
}
hr.divider { border: none; border-top: 2px solid #C8C8C8; margin: 1rem 0; }

[data-testid="stFileUploader"] {
    border: 2px dashed #AAAAAA !important; border-radius: 4px !important;
    background: #F4F4F4 !important; padding: 1rem !important;
}
[data-testid="stMetric"] {
    background: #FFFFFF; border: 1px solid #C8C8C8;
    border-top: 3px solid #2E6A9C; border-radius: 4px; padding: 0.8rem 1rem !important;
}
[data-testid="stMetricLabel"] {
    color: #777777 !important; font-family: 'Inter', sans-serif !important;
    font-size: 0.8rem !important; font-weight: 600 !important;
    letter-spacing: 0.06em !important; text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    color: #1A1A1A !important; font-family: 'Inter', sans-serif !important;
    font-size: 1.3rem !important; font-weight: 700 !important;
}

/* Hex dump panels */
.hex-panel {
    background: #FFFFFF; border: 1px solid #C8C8C8; border-radius: 4px;
    padding: 0 0 0.5rem 0; overflow: hidden;
}
.hex-panel-header {
    background: #2A2A2A; color: #FFFFFF; padding: 0.5rem 1rem;
    font-family: 'Inter', sans-serif; font-size: 0.85rem; font-weight: 700;
    letter-spacing: 0.05em; border-radius: 4px 4px 0 0;
}
.hex-panel-header.left  { border-left: 4px solid #2E6A9C; }
.hex-panel-header.right { border-left: 4px solid #B42D27; }

.hex-table {
    width: 100%; border-collapse: collapse;
    font-family: 'Roboto Mono', monospace; font-size: 0.82rem;
}
.hex-table td, .hex-table th {
    padding: 0.15rem 0.4rem; border-bottom: 1px solid #F0F0F0;
    white-space: nowrap;
}
.hex-table th {
    background: #F4F4F4; color: #777777; font-size: 0.72rem;
    font-family: 'Inter', sans-serif; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    position: sticky; top: 0;
}
.hex-table .col-offset { color: #AAAAAA; font-size: 0.78rem; }
.hex-table .col-ascii  { color: #777777; border-left: 1px solid #E8E8E8; padding-left: 0.6rem; }

/* Diff highlight classes */
.byte-same { color: #1A1A1A; }
.byte-diff { background-color: #FFEBEE; color: #B42D27; font-weight: 700; border-radius: 2px; padding: 0 2px; }
.byte-only { background-color: #FFF3E0; color: #E65100; font-weight: 700; border-radius: 2px; padding: 0 2px; }
.ascii-diff { color: #B42D27; font-weight: 700; }
.ascii-same { color: #777777; }

/* Field decode table */
.decode-table {
    width: 100%; border-collapse: collapse;
    font-family: 'Inter', sans-serif; font-size: 0.88rem;
}
.decode-table th {
    background: #2A2A2A; color: #FFFFFF; padding: 0.4rem 0.8rem;
    font-size: 0.75rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
}
.decode-table td { padding: 0.4rem 0.8rem; border-bottom: 1px solid #E8E8E8; vertical-align: top; }
.decode-table tr:hover td { background: #F8F8F8; }
.field-name  { color: #555555; font-size: 0.82rem; font-weight: 600; white-space: nowrap; }
.field-match { color: #2E7D32; font-family: 'Roboto Mono', monospace; }
.field-diff  { color: #B42D27; font-family: 'Roboto Mono', monospace; font-weight: 700; }
.field-na    { color: #AAAAAA; font-style: italic; }

.stat-match { display:inline-block; background:#2E7D32; color:#FFF; border-radius:3px; padding:0.1rem 0.5rem; font-size:0.78rem; font-weight:700; }
.stat-diff  { display:inline-block; background:#B42D27; color:#FFF; border-radius:3px; padding:0.1rem 0.5rem; font-size:0.78rem; font-weight:700; }

.summary-bar {
    background: #FFFFFF; border: 1px solid #C8C8C8; border-radius: 4px;
    padding: 0.8rem 1.2rem; margin-bottom: 1rem;
    display: flex; gap: 2rem; align-items: center;
    font-family: 'Inter', sans-serif;
}
.info-mono { font-family: 'Roboto Mono', monospace; font-size: 0.9rem; color: #AAAAAA; text-align: center; padding-top: 0.5rem; }
.sidebar-status {
    font-family: 'Roboto Mono', monospace; font-size: 0.85rem; color: #AAAAAA;
    padding: 0.8rem; border: 1px solid #444444; border-radius: 4px;
    background: #1A1A1A; line-height: 2.0;
}
.sidebar-status .dot {
    display: inline-block; width: 8px; height: 8px; background: #4CAF50;
    border-radius: 50%; margin-right: 6px; box-shadow: 0 0 5px #4CAF50;
}
</style>
""", unsafe_allow_html=True)

# ── SFF Field Map ─────────────────────────────────────────────────────────────
TRANSCEIVER_NAMES = {
    0x03: "SFP / SFP+", 0x0C: "QSFP", 0x0D: "QSFP+",
    0x11: "QSFP28",     0x18: "QSFP-DD / 400G CMIS",
}

def detect_offsets(data):
    """Detect family and return SFF field map."""
    if not data:
        return {}, "Unknown"
    id0 = data[0]
    name = TRANSCEIVER_NAMES.get(id0, f"Unknown (0x{id0:02X})")
    is_upper_only = (id0 in {0x0C,0x0D,0x11,0x18}
                     and len(data) <= 256
                     and not (len(data) > 0x80 and data[0x80] == id0))

    if id0 == 0x03 or is_upper_only:
        fields = {
            "Identifier":    (0x00, 0x01),
            "Vendor Name":   (0x14, 0x24),
            "Part Number":   (0x28, 0x38),
            "Serial Number": (0x44, 0x54),
            "Date Code":     (0x68, 0x70),
            "CC_BASE":       (0x3F, 0x40),
            "CC_EXT":        (0x5F, 0x60),
            "Manu ID":       (0x62, 0x63),
            "MD5 Hash":      (0x63, 0x73),
            "Zero Pad":      (0x73, 0x7C),
            "CRC32":         (0x7C, 0x80),
        }
    else:
        fields = {
            "Identifier":    (0x80, 0x81),
            "Vendor Name":   (0x94, 0xA4),
            "Part Number":   (0xA8, 0xB8),
            "Serial Number": (0xC4, 0xD4),
            "Date Code":     (0xD4, 0xDC),
            "CC_BASE":       (0xBF, 0xC0),
            "CC_EXT":        (0xDF, 0xE0),
            "Manu ID":       (0xE2, 0xE3),
            "MD5 Hash":      (0xE3, 0xF3),
            "Zero Pad":      (0xF3, 0xFC),
            "CRC32":         (0xFC, 0x100),
        }
    return fields, name + (" [Upper Page Only]" if is_upper_only else "")


def make_hex_table(data_a, data_b, bytes_per_row=16):
    """Build an HTML hex table with diff highlighting."""
    max_len = max(len(data_a), len(data_b))
    rows_a, rows_b = [], []

    for row_start in range(0, max_len, bytes_per_row):
        chunk_a = data_a[row_start:row_start + bytes_per_row] if row_start < len(data_a) else b''
        chunk_b = data_b[row_start:row_start + bytes_per_row] if row_start < len(data_b) else b''
        offset  = f"0x{row_start:04X}"

        def build_row(chunk_main, chunk_other, side):
            hex_cells, asc_cells = [], []
            for i in range(bytes_per_row):
                if i < len(chunk_main):
                    b    = chunk_main[i]
                    same = (i < len(chunk_other) and b == chunk_other[i])
                    cls_h = "byte-same" if same else "byte-diff"
                    cls_a = "ascii-same" if same else "ascii-diff"
                    hex_cells.append(f'<span class="{cls_h}">{b:02X}</span>')
                    asc_cells.append(f'<span class="{cls_a}">{chr(b) if 32 <= b < 127 else "."}</span>')
                else:
                    hex_cells.append('<span style="color:#DDDDDD;">--</span>')
                    asc_cells.append('<span style="color:#DDDDDD;">.</span>')

            hex_str = ' '.join(hex_cells)
            asc_str = ''.join(asc_cells)
            return (f'<tr><td class="col-offset">{offset}</td>'
                    f'<td>{hex_str}</td>'
                    f'<td class="col-ascii">{asc_str}</td></tr>')

        rows_a.append(build_row(chunk_a, chunk_b, 'a'))
        rows_b.append(build_row(chunk_b, chunk_a, 'b'))

    header = ('<tr><th>Offset</th>'
              '<th>00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</th>'
              '<th>ASCII</th></tr>')

    html_a = f'<table class="hex-table">{header}{"".join(rows_a)}</table>'
    html_b = f'<table class="hex-table">{header}{"".join(rows_b)}</table>'
    return html_a, html_b


def build_field_compare(data_a, data_b, fields):
    """Build field-by-field comparison table."""
    rows = []
    for fname, (start, end) in fields.items():
        def get_field(data, s, e):
            if len(data) >= e:
                raw = bytes(data[s:e])
                txt = raw.decode('ascii', errors='replace').strip()
                hex_s = ' '.join(f'{b:02X}' for b in raw)
                return txt, hex_s
            return None, None

        txt_a, hex_a = get_field(data_a, start, end)
        txt_b, hex_b = get_field(data_b, start, end)

        if txt_a is None and txt_b is None:
            continue

        same = (hex_a == hex_b)
        badge = '<span class="stat-match">EQUAL</span>' if same else '<span class="stat-diff">DIFF</span>'
        cls   = "field-match" if same else "field-diff"

        val_a = f'<span class="{cls}">{txt_a or "—"}</span><br><small style="color:#AAAAAA;font-family:\'Roboto Mono\',monospace;font-size:0.75rem;">{hex_a or ""}</small>' if txt_a is not None else '<span class="field-na">—</span>'
        val_b = f'<span class="{cls}">{txt_b or "—"}</span><br><small style="color:#AAAAAA;font-family:\'Roboto Mono\',monospace;font-size:0.75rem;">{hex_b or ""}</small>' if txt_b is not None else '<span class="field-na">—</span>'

        rows.append(f'''
        <tr>
            <td class="field-name">{fname}</td>
            <td>{val_a}</td>
            <td style="text-align:center;">{badge}</td>
            <td>{val_b}</td>
        </tr>''')

    return f'''
    <table class="decode-table">
        <tr>
            <th>Field</th>
            <th>📄 File A</th>
            <th>Status</th>
            <th>📄 File B</th>
        </tr>
        {"".join(rows)}
    </table>'''


def diff_stats(data_a, data_b):
    max_len  = max(len(data_a), len(data_b))
    min_len  = min(len(data_a), len(data_b))
    diffs    = sum(1 for i in range(min_len) if data_a[i] != data_b[i])
    diffs   += abs(len(data_a) - len(data_b))
    return max_len, diffs, max_len - diffs


# ── UI ────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="title-block">
    <h1>🔧 TOOLS — BIN COMPARATOR</h1>
    <p>SIDE-BY-SIDE HEX DIFF &nbsp;|&nbsp; SFF FIELD DECODE &nbsp;|&nbsp; EPS GLOBAL</p>
</div>
<hr class="divider">
""", unsafe_allow_html=True)

# ── Upload ────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-label">01 — Upload Files</div>', unsafe_allow_html=True)

col_up1, col_up2 = st.columns(2)
with col_up1:
    st.markdown("**📄 File A** — Reference / Original")
    file_a = st.file_uploader("File A (.bin)", type=["bin"], key="file_a")
with col_up2:
    st.markdown("**📄 File B** — Modified / Patched")
    file_b = st.file_uploader("File B (.bin)", type=["bin"], key="file_b")

if not file_a and not file_b:
    st.markdown('<p class="info-mono">← upload two .bin files to begin comparison</p>',
                unsafe_allow_html=True)

elif not file_a or not file_b:
    st.info("📋  Upload both files to start the comparison.")

else:
    data_a = bytearray(file_a.read())
    data_b = bytearray(file_b.read())

    # ── Stats ─────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">02 — Summary</div>', unsafe_allow_html=True)

    total, diffs, equal = diff_stats(data_a, data_b)
    pct = round((equal / total) * 100, 1) if total else 0

    fields_a, name_a = detect_offsets(data_a)
    fields_b, name_b = detect_offsets(data_b)
    fields = fields_a or fields_b

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("File A Size",    f"{len(data_a)} B")
    m2.metric("File B Size",    f"{len(data_b)} B")
    m3.metric("Bytes Different", str(diffs),
              delta=f"-{diffs}" if diffs else None,
              delta_color="inverse")
    m4.metric("Bytes Equal",    str(equal))
    m5.metric("Match %",        f"{pct}%")

    st.markdown(f"""
    <div style="background:#F4F4F4;border:1px solid #C8C8C8;border-radius:4px;
                padding:0.6rem 1rem;margin:0.5rem 0;font-size:0.88rem;
                font-family:'Inter',sans-serif;display:flex;gap:2rem;">
        <span><b>File A:</b> {file_a.name} &nbsp;—&nbsp; <span style="color:#2E6A9C;">{name_a}</span></span>
        <span><b>File B:</b> {file_b.name} &nbsp;—&nbsp; <span style="color:#B42D27;">{name_b}</span></span>
        <span><b>Size match:</b> {'✅ Yes' if len(data_a)==len(data_b) else f'⚠️ No ({len(data_a)} vs {len(data_b)} bytes)'}</span>
    </div>
    """, unsafe_allow_html=True)

    # ── Field Decode ──────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">03 — Field Comparison (SFF Decode)</div>',
                unsafe_allow_html=True)

    if fields:
        # Use components.html to avoid CSS bleed-through with complex HTML tables
        field_html = build_field_compare(data_a, data_b, fields)
        # Inject minimal scoped CSS so the table renders correctly
        scoped_css = """
        <style>
        body { margin:0; font-family:'Inter',sans-serif; background:#E8E8E8; }
        .decode-table { width:100%; border-collapse:collapse; font-family:'Inter',sans-serif; font-size:0.9rem; }
        .decode-table th { background:#2A2A2A; color:#FFFFFF; padding:0.5rem 0.8rem;
                           font-size:0.78rem; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; }
        .decode-table td { padding:0.45rem 0.8rem; border-bottom:1px solid #E8E8E8; vertical-align:top; }
        .decode-table tr:hover td { background:#F8F8F8; }
        .field-name  { color:#555555; font-size:0.85rem; font-weight:600; white-space:nowrap; }
        .field-match { color:#2E7D32; font-family:'Roboto Mono',monospace; font-size:0.85rem; }
        .field-diff  { color:#B42D27; font-family:'Roboto Mono',monospace; font-size:0.85rem; font-weight:700; }
        .field-na    { color:#AAAAAA; font-style:italic; }
        .stat-match  { display:inline-block; background:#2E7D32; color:#FFF;
                       border-radius:3px; padding:0.1rem 0.5rem; font-size:0.78rem; font-weight:700; }
        .stat-diff   { display:inline-block; background:#B42D27; color:#FFF;
                       border-radius:3px; padding:0.1rem 0.5rem; font-size:0.78rem; font-weight:700; }
        </style>
        """
        n_rows = len(fields)
        row_height = 52
        table_height = max(200, n_rows * row_height + 60)
        components.html(scoped_css + field_html, height=table_height, scrolling=True)
    else:
        st.info("Could not detect SFF family for field decode.")

    # ── Hex Diff ──────────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">04 — Hex Dump Comparison</div>',
                unsafe_allow_html=True)

    # Options
    opt1, opt2 = st.columns([1, 3])
    with opt1:
        show_equal = st.checkbox("Show equal rows", value=True)
    with opt2:
        if diffs == 0:
            st.success("✅  Files are identical — no differences found.")

    # Build tables
    html_a, html_b = make_hex_table(data_a, data_b)

    # If hide equal rows, filter
    if not show_equal and diffs > 0:
        st.info("Showing only rows with differences.")

    hex_css = """
    <style>
    body { margin:0; font-family:'Roboto Mono',monospace; background:#FFFFFF; }
    .hex-panel { background:#FFFFFF; border:1px solid #C8C8C8; border-radius:4px; overflow:hidden; }
    .hex-panel-header { color:#FFFFFF; padding:0.5rem 1rem; font-family:'Inter',sans-serif;
                        font-size:0.85rem; font-weight:700; letter-spacing:0.05em; }
    .hex-panel-header.left  { background:#2A2A2A; border-left:4px solid #2E6A9C; }
    .hex-panel-header.right { background:#2A2A2A; border-left:4px solid #B42D27; }
    .hex-table { width:100%; border-collapse:collapse; font-family:'Roboto Mono',monospace; font-size:0.82rem; }
    .hex-table td, .hex-table th { padding:0.15rem 0.4rem; border-bottom:1px solid #F0F0F0; white-space:nowrap; }
    .hex-table th { background:#F4F4F4; color:#777777; font-size:0.72rem; font-family:'Inter',sans-serif;
                    font-weight:700; letter-spacing:0.1em; text-transform:uppercase; }
    .col-offset { color:#AAAAAA; font-size:0.78rem; }
    .col-ascii  { color:#777777; border-left:1px solid #E8E8E8; padding-left:0.6rem; }
    .byte-same  { color:#1A1A1A; }
    .byte-diff  { background-color:#FFEBEE; color:#B42D27; font-weight:700; border-radius:2px; padding:0 2px; }
    .ascii-diff { color:#B42D27; font-weight:700; }
    .ascii-same { color:#999999; }
    </style>
    """

    col_hex1, col_hex2 = st.columns(2)
    hex_height = min(600, max(300, (max(len(data_a), len(data_b)) // 16) * 22 + 60))

    with col_hex1:
        components.html(
            hex_css + f'''
            <div class="hex-panel">
                <div class="hex-panel-header left">📄 {file_a.name} &nbsp;({len(data_a)} bytes)</div>
                <div style="overflow-x:auto;padding:0.3rem 0.5rem;">
                    {html_a}
                </div>
            </div>''',
            height=hex_height, scrolling=True
        )

    with col_hex2:
        components.html(
            hex_css + f'''
            <div class="hex-panel">
                <div class="hex-panel-header right">📄 {file_b.name} &nbsp;({len(data_b)} bytes)</div>
                <div style="overflow-x:auto;padding:0.3rem 0.5rem;">
                    {html_b}
                </div>
            </div>''',
            height=hex_height, scrolling=True
        )

    # ── Legend ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="margin-top:0.8rem;font-family:'Inter',sans-serif;font-size:0.82rem;color:#777777;
                display:flex;gap:1.5rem;align-items:center;">
        <span><span class="byte-same" style="font-family:'Roboto Mono',monospace;">FF</span> &nbsp;— bytes iguais</span>
        <span><span class="byte-diff" style="font-family:'Roboto Mono',monospace;">FF</span> &nbsp;— bytes diferentes</span>
        <span><span style="color:#DDDDDD;font-family:'Roboto Mono',monospace;">--</span> &nbsp;— byte não presente</span>
    </div>
    """, unsafe_allow_html=True)

    # ── String export ──────────────────────────────────────────────────────────
    st.markdown('<div class="section-label">05 — String (Copy for EEPROM IDE)</div>',
                unsafe_allow_html=True)
    s1, s2 = st.columns(2)
    with s1:
        st.markdown("**📄 File A — String**")
        st.code(data_a.hex().upper(), language="text")
    with s2:
        st.markdown("**📄 File B — String**")
        st.code(data_b.hex().upper(), language="text")