"""
Arista Encoder - converte TXT do ELNEC em EEPROM patchada para Arista (100G ZR 80km DWDM DCO)

Regras aplicadas (confirmadas em Full_Page_Arista_10km_LR.bin):
  1) Vendor Name (abs 148-163)  -> "Arista Networks" (16 bytes, igual à referência)
  2) Zera bytes abs 0xE0-0xFB   (224-251)  - limpa a região antes usada pelo patch Cisco
  3) CRC32 Arista/Flexoptix     -> zlib.crc32 sobre abs 128-251 (Page00h inteira, exceto
                                    os 4 bytes finais), gravado BIG-ENDIAN em abs 252-255 (0xFC-0xFF)
  4) Vendor PN  (abs 168-183)   -> acrescenta "-A" no final (dentro do campo de 16 bytes)
  5) Vendor SN  (abs 196-211)   -> acrescenta "-1" no final (dentro do campo de 16 bytes)
  6) Recalcula CC_BASE (abs 191 = soma 128-190) e CC_EXT (abs 223 = soma 192-222),
     já que Vendor Name/PN/SN caem dentro dessas faixas.

Layout assumido (padrão que já usamos em todo o projeto):
  Lower Page  : abs 0-127
  Page 00h    : abs 128-255
  (Page01h, Page02h etc, se presentes no arquivo, são preservados sem alteração)
"""

import io
import re
import struct
import zlib

import streamlit as st

# ---------------------------------------------------------------------------
# Constantes de campo (endereçamento absoluto SFF-8636, igual usado no projeto aaaa
# ---------------------------------------------------------------------------
VENDOR_NAME_OFF, VENDOR_NAME_LEN = 148, 16
VENDOR_PN_OFF, VENDOR_PN_LEN = 168, 16
VENDOR_SN_OFF, VENDOR_SN_LEN = 196, 16
CC_BASE_OFF = 191          # soma(128-190) & 0xFF
CC_EXT_OFF = 223           # soma(192-222) & 0xFF
CLEAR_START, CLEAR_END = 0xE0, 0xFB     # 224-251, limpa (inclusive)
CRC_REGION_START, CRC_REGION_END = 128, 251   # Page00h inteira, exceto os 4 bytes finais
CRC_OFF = 252              # abs 0xFC-0xFF, 4 bytes, big-endian

ARISTA_VENDOR_NAME = b"Arista Networks"  # 15 chars + 1 espaço de padding = 16 bytes


def pad16(b: bytes) -> bytes:
    b = b[:16]
    return b + b" " * (16 - len(b))


def append_suffix(field: bytes, suffix: str) -> bytes:
    """Remove padding com espaço, acrescenta sufixo, repadroniza pra 16 bytes.
    Se não couber, corta o campo original o quanto for preciso pra caber o sufixo."""
    text = field.decode("latin1").rstrip(" ").rstrip("\x00")
    combined = text + suffix
    if len(combined) > 16:
        # corta o texto original o suficiente pra caber o sufixo
        combined = text[: 16 - len(suffix)] + suffix
    return pad16(combined.encode("latin1"))


def parse_elnec_txt(raw_text: str) -> bytearray:
    """Extrai os bytes de um export TXT do ELNEC.
    Aceita tanto linhas 'endereco: XX XX XX ...' quanto texto só com pares hex soltos."""
    hex_tokens = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # remove um endereço no início da linha, se existir (ex: "00000000:" ou "0000h")
        line = re.sub(r"^[0-9A-Fa-f]{1,8}[:hH]?\s+", "", line)
        tokens = re.findall(r"\b[0-9A-Fa-f]{2}\b", line)
        hex_tokens.extend(tokens)
    if not hex_tokens:
        raise ValueError("Não encontrei nenhum byte hex reconhecível no TXT.")
    return bytearray(int(t, 16) for t in hex_tokens)


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

    # 2) Limpa bytes 0xE0-0xFB
    old_clear = bytes(data[CLEAR_START: CLEAR_END + 1])
    data[CLEAR_START: CLEAR_END + 1] = b"\x00" * (CLEAR_END + 1 - CLEAR_START)
    log["Bytes 0xE0-0xFB"] = (old_clear, bytes(data[CLEAR_START: CLEAR_END + 1]))

    # 4) Vendor PN -> acrescenta "-A"
    old_pn = bytes(data[VENDOR_PN_OFF: VENDOR_PN_OFF + VENDOR_PN_LEN])
    new_pn = append_suffix(old_pn, "-A")
    data[VENDOR_PN_OFF: VENDOR_PN_OFF + VENDOR_PN_LEN] = new_pn
    log["Vendor PN"] = (old_pn, new_pn)

    # 5) Vendor SN -> acrescenta "-1"
    old_sn = bytes(data[VENDOR_SN_OFF: VENDOR_SN_OFF + VENDOR_SN_LEN])
    new_sn = append_suffix(old_sn, "-1")
    data[VENDOR_SN_OFF: VENDOR_SN_OFF + VENDOR_SN_LEN] = new_sn
    log["Vendor SN"] = (old_sn, new_sn)

    # 6) Recalcula CC_BASE e CC_EXT (checksums padrão SFF-8636)
    old_cc_base = data[CC_BASE_OFF]
    data[CC_BASE_OFF] = sum(data[128:191]) & 0xFF
    log["CC_BASE (0xBF)"] = (old_cc_base, data[CC_BASE_OFF])

    old_cc_ext = data[CC_EXT_OFF]
    data[CC_EXT_OFF] = sum(data[192:223]) & 0xFF
    log["CC_EXT (0xDF)"] = (old_cc_ext, data[CC_EXT_OFF])

    # 3) CRC32 Arista/Flexoptix - sobre 128-251, big-endian, gravado em 252-255
    old_crc = bytes(data[CRC_OFF: CRC_OFF + 4])
    crc = zlib.crc32(bytes(data[CRC_REGION_START: CRC_REGION_END + 1])) & 0xFFFFFFFF
    new_crc = struct.pack(">I", crc)
    data[CRC_OFF: CRC_OFF + 4] = new_crc
    log["CRC32 Arista (0xFC-0xFF, BE)"] = (old_crc, new_crc)

    return data, log


def hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        row = data[i : i + 16]
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
    "Recebe o TXT exportado do ELNEC, aplica o patch Arista/Flexoptix "
    "(Vendor Name, limpeza 0xE0-0xFB, CRC32, sufixo -A no PN e -1 no SN) "
    "e devolve o arquivo pronto pra regravar."
)

uploaded = st.file_uploader("TXT do ELNEC", type=["txt"])

if uploaded is not None:
    raw_text = uploaded.read().decode("latin1", errors="ignore")
    try:
        data = parse_elnec_txt(raw_text)
        st.success(f"Li {len(data)} bytes do TXT.")
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
        st.download_button(
            "Baixar .bin patchado",
            data=bin_bytes,
            file_name=f"{uploaded.name.rsplit('.', 1)[0]}_ARISTA.bin",
            mime="application/octet-stream",
        )

        hex_string = bin_bytes.hex().upper()
        st.download_button(
            "Baixar string hex (formato Coherent IDE)",
            data=hex_string,
            file_name=f"{uploaded.name.rsplit('.', 1)[0]}_ARISTA.txt",
            mime="text/plain",
        )
