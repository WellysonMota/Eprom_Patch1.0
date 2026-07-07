"""
Arista Encoder - converte TXT da Coherent IDE em EEPROM patchada para Arista (100G ZR 80km DWDM DCO)

Regras aplicadas (confirmadas em Full_Page_Arista_10km_LR.bin):
  1) Vendor Name (abs 148-163)  -> "Arista Networks" (16 bytes, igual à referência)
  2) Vendor OUI  (abs 165-167)  -> 38:86:02 (igual à referência Arista LR4)
  3) Vendor PN   (abs 168-183)  -> mantém o PN original do arquivo, acrescenta "-A" no final
  4) Vendor SN   (abs 196-211)  -> mantém o SN original do arquivo, acrescenta "-1" no final
  5) Zera bytes abs 0xE0-0xFB   (224-251)  - limpa a região antes usada pelo patch Cisco
  6) CRC32 Arista/Flexoptix     -> zlib.crc32 sobre abs 128-251 (Page00h inteira, exceto
                                    os 4 bytes finais), gravado BIG-ENDIAN em abs 252-255 (0xFC-0xFF)
  7) Recalcula CC_BASE (abs 191 = soma 128-190) e CC_EXT (abs 223 = soma 192-222).

Formato de entrada: TXT exportado direto da Coherent EEPROM Programming IDE
(seções "Lower Memory" / "Page : XXh", linhas "Page Not Valid" para páginas não implementadas).
Também aceita, como fallback, um TXT "flat" de hex puro (ex: export do ELNEC).
"""

import re
import struct
import zlib

import streamlit as st

# ---------------------------------------------------------------------------
# Constantes de campo (endereçamento absoluto SFF-8636, igual usado no projeto)
# ---------------------------------------------------------------------------
VENDOR_NAME_OFF, VENDOR_NAME_LEN = 148, 16
VENDOR_OUI_OFF, VENDOR_OUI_LEN = 165, 3
VENDOR_PN_OFF, VENDOR_PN_LEN = 168, 16
VENDOR_SN_OFF, VENDOR_SN_LEN = 196, 16
CC_BASE_OFF = 191          # soma(128-190) & 0xFF
CC_EXT_OFF = 223           # soma(192-222) & 0xFF
CLEAR_START, CLEAR_END = 0xE0, 0xFB     # 224-251, limpa (inclusive)
CRC_REGION_START, CRC_REGION_END = 128, 251   # Page00h inteira, exceto os 4 bytes finais
CRC_OFF = 252              # abs 0xFC-0xFF, 4 bytes, big-endian

ARISTA_VENDOR_NAME = b"Arista Networks"   # 15 chars + 1 espaço = 16 bytes
ARISTA_OUI = bytes.fromhex("388602")      # confirmado em Full_Page_Arista_10km_LR.bin


def pad16(b: bytes) -> bytes:
    b = b[:16]
    return b + b" " * (16 - len(b))


def append_suffix(field: bytes, suffix: str) -> bytes:
    """Remove padding, acrescenta sufixo, repadroniza pra 16 bytes.
    Se não couber, corta o texto original o quanto for preciso pra caber o sufixo."""
    text = field.decode("latin1").rstrip(" ").rstrip("\x00")
    combined = text + suffix
    if len(combined) > 16:
        combined = text[: 16 - len(suffix)] + suffix
    return pad16(combined.encode("latin1"))


# ---------------------------------------------------------------------------
# Parser: TXT da Coherent IDE (seções "Lower Memory" / "Page : XXh")
# ---------------------------------------------------------------------------
def parse_coherent_txt(raw_text: str):
    """Retorna (flat_bytes, page_labels). Cada página vira um bloco de 128 bytes,
    concatenados na ordem em que aparecem no arquivo (Lower Memory primeiro,
    depois Page:00h, 01h, 02h... conforme o export)."""
    lines = raw_text.splitlines()
    pages = []
    page_labels = []
    current_page = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("Lower Memory") or re.match(r"^Page\s*:\s*[0-9A-Fa-f]+h", line):
            current_page = bytearray(128)
            pages.append(current_page)
            page_labels.append(line)
            i += 1
            # pula cabeçalho de colunas ("Address ...") e linha de traços
            while i < len(lines) and (
                lines[i].strip().startswith("Address")
                or (lines[i].strip() and set(lines[i].strip()) <= {"-", " "})
            ):
                i += 1
            continue
        if current_page is not None:
            tokens = line.split()
            if tokens and re.fullmatch(r"[0-9A-Fa-f]{1,2}", tokens[0]):
                row_addr = int(tokens[0], 16)
                byte_vals = [t for t in tokens[1:] if re.fullmatch(r"[0-9A-Fa-f]{2}", t)]
                local_base = row_addr % 128
                for offset, bv in enumerate(byte_vals):
                    idx = local_base + offset
                    if idx < 128:
                        current_page[idx] = int(bv, 16)
        i += 1

    if not pages:
        raise ValueError("Não reconheci nenhuma seção 'Lower Memory' / 'Page : XXh' nesse TXT.")

    flat = bytearray()
    for p in pages:
        flat += p
    return flat, page_labels


def parse_flat_hex_txt(raw_text: str) -> bytearray:
    """Fallback: TXT com hex solto (ex: export do ELNEC), sem seções nomeadas."""
    hex_tokens = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[0-9A-Fa-f]{1,8}[:hH]?\s+", "", line)
        hex_tokens.extend(re.findall(r"\b[0-9A-Fa-f]{2}\b", line))
    if not hex_tokens:
        raise ValueError("Não encontrei nenhum byte hex reconhecível no TXT.")
    return bytearray(int(t, 16) for t in hex_tokens)


def parse_any_txt(raw_text: str):
    if "Page :" in raw_text or "Lower Memory" in raw_text:
        flat, labels = parse_coherent_txt(raw_text)
        return flat, labels
    return parse_flat_hex_txt(raw_text), None


# ---------------------------------------------------------------------------
# Patch
# ---------------------------------------------------------------------------
def patch_for_arista(data: bytearray) -> tuple[bytearray, dict]:
    if len(data) < 256:
        raise ValueError(
            f"Arquivo tem só {len(data)} bytes - preciso de pelo menos 256 "
            "(Lower Page + Page00h) pra aplicar o patch."
        )

    log = {}

    # 1) Vendor Name -> Arista Networks
    old_vn = bytes(data[VENDOR_NAME_OFF: VENDOR_NAME_OFF + VENDOR_NAME_LEN])
    data[VENDOR_NAME_OFF: VENDOR_NAME_OFF + VENDOR_NAME_LEN] = pad16(ARISTA_VENDOR_NAME)
    log["Vendor Name"] = (old_vn, bytes(data[VENDOR_NAME_OFF: VENDOR_NAME_OFF + VENDOR_NAME_LEN]))

    # 2) Vendor OUI -> 38:86:02 (Arista, conforme referência LR4)
    old_oui = bytes(data[VENDOR_OUI_OFF: VENDOR_OUI_OFF + VENDOR_OUI_LEN])
    data[VENDOR_OUI_OFF: VENDOR_OUI_OFF + VENDOR_OUI_LEN] = ARISTA_OUI
    log["Vendor OUI"] = (old_oui, ARISTA_OUI)

    # 3) Vendor PN -> mantém original + "-A"
    old_pn = bytes(data[VENDOR_PN_OFF: VENDOR_PN_OFF + VENDOR_PN_LEN])
    new_pn = append_suffix(old_pn, "-A")
    data[VENDOR_PN_OFF: VENDOR_PN_OFF + VENDOR_PN_LEN] = new_pn
    log["Vendor PN"] = (old_pn, new_pn)

    # 4) Vendor SN -> mantém original + "-1"
    old_sn = bytes(data[VENDOR_SN_OFF: VENDOR_SN_OFF + VENDOR_SN_LEN])
    new_sn = append_suffix(old_sn, "-1")
    data[VENDOR_SN_OFF: VENDOR_SN_OFF + VENDOR_SN_LEN] = new_sn
    log["Vendor SN"] = (old_sn, new_sn)

    # 5) Limpa bytes 0xE0-0xFB
    old_clear = bytes(data[CLEAR_START: CLEAR_END + 1])
    data[CLEAR_START: CLEAR_END + 1] = b"\x00" * (CLEAR_END + 1 - CLEAR_START)
    log["Bytes 0xE0-0xFB"] = (old_clear, bytes(data[CLEAR_START: CLEAR_END + 1]))

    # 6) Recalcula CC_BASE e CC_EXT
    old_cc_base = data[CC_BASE_OFF]
    data[CC_BASE_OFF] = sum(data[128:191]) & 0xFF
    log["CC_BASE (0xBF)"] = (old_cc_base, data[CC_BASE_OFF])

    old_cc_ext = data[CC_EXT_OFF]
    data[CC_EXT_OFF] = sum(data[192:223]) & 0xFF
    log["CC_EXT (0xDF)"] = (old_cc_ext, data[CC_EXT_OFF])

    # 7) CRC32 Arista/Flexoptix - sobre 128-251, big-endian, gravado em 252-255
    old_crc = bytes(data[CRC_OFF: CRC_OFF + 4])
    crc = zlib.crc32(bytes(data[CRC_REGION_START: CRC_REGION_END + 1])) & 0xFFFFFFFF
    new_crc = struct.pack(">I", crc)
    data[CRC_OFF: CRC_OFF + 4] = new_crc
    log["CRC32 Arista (0xFC-0xFF, BE)"] = (old_crc, new_crc)

    return data, log


def hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        row = data[i: i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{base + i:06d} (0x{base + i:04x})  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Arista Encoder - 100G ZR 80km DCO", layout="wide")
st.title("Arista Encoder — 100G ZR 80km DWDM (DCO)")
st.caption(
    "Recebe o TXT exportado direto da Coherent EEPROM Programming IDE "
    "(ou, como fallback, um TXT hex flat tipo ELNEC), aplica o patch Arista "
    "(Vendor Name, OUI, PN -A, SN -1, limpeza 0xE0-0xFB, CRC32) e devolve o arquivo pronto."
)

uploaded = st.file_uploader("TXT (Coherent IDE ou flat hex)", type=["txt"])

if uploaded is not None:
    raw_text = uploaded.read().decode("latin1", errors="ignore")
    try:
        data, page_labels = parse_any_txt(raw_text)
        n_pages = len(data) // 128
        st.success(f"Li {len(data)} bytes ({n_pages} páginas de 128 bytes) do TXT.")
        if page_labels:
            valid_pages = [
                lbl for lbl in page_labels
                if lbl not in ("Lower Memory",) and "Not Valid" not in lbl
            ]
            with st.expander(f"Páginas encontradas ({len(page_labels)})"):
                st.write(page_labels)
    except ValueError as e:
        st.error(str(e))
        st.stop()

    if st.button("Aplicar patch Arista", type="primary"):
        try:
            patched, log = patch_for_arista(bytearray(data))
        except ValueError as e:
            st.error(str(e))
            st.stop()

        st.subheader("Mudanças aplicadas")
        for field, (old, new) in log.items():
            old_repr = old.hex() if isinstance(old, (bytes, bytearray)) else f"0x{old:02x}"
            new_repr = new.hex() if isinstance(new, (bytes, bytearray)) else f"0x{new:02x}"
            if isinstance(old, (bytes, bytearray)):
                try:
                    old_repr += f"  ({old.decode('latin1').rstrip(chr(0)).rstrip()!r})"
                    new_repr += f"  ({new.decode('latin1').rstrip(chr(0)).rstrip()!r})"
                except Exception:
                    pass
            st.write(f"**{field}**")
            st.code(f"antes:  {old_repr}\ndepois: {new_repr}")

        st.subheader("Hex dump final (Page00h, abs 128-255)")
        st.code(hexdump(bytes(patched[128:256]), base=128))

        bin_bytes = bytes(patched)
        base_name = uploaded.name.rsplit(".", 1)[0]
        st.download_button(
            "Baixar .bin patchado",
            data=bin_bytes,
            file_name=f"{base_name}_ARISTA.bin",
            mime="application/octet-stream",
        )

        hex_string = bin_bytes.hex().upper()
        st.download_button(
            "Baixar string hex (formato Coherent IDE)",
            data=hex_string,
            file_name=f"{base_name}_ARISTA.txt",
            mime="text/plain",
        )