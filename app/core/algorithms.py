import hashlib
import zlib


from app.core.constants import (
    SFP_MAP, QSFP_MAP, CMIS_MAP, TRANSCEIVER_IDENTIFIERS,
    REVISION_COMPLIANCE, MAGIC_KEYS
)


def calculate_sff_checksum(data_block):
    """Soma mod 256 para conformidade SFF/CMIS."""
    return sum(data_block) & 0xFF


def format_sff_string(text, length=16):
    """Garante 16 bytes com preenchimento de espaços (0x20)."""
    clean_text = str(text).encode('ascii', errors='ignore').strip()
    return clean_text.ljust(length, b'\x20')[:length]


def calculate_reach(data, family):
    """Calcula distância baseada na família."""
    if family == "400G Family":
        smf = data[182] if len(data) > 182 else 0
        return (f"{smf} km", smf) if smf > 0 else ("0.3 km", 0)
    elif family == "SFP Family":
        smf = data[14] if len(data) > 14 else 0
        return (f"{smf} km", smf) if smf > 0 else ("0.3 km", 0)
    elif family == "QSFP Family":
        smf = data[142] if len(data) > 142 else 0
        return (f"{smf} km", smf) if smf > 0 else ("0.3 km", 0)
    return ("Unknown", 0)


def apply_cisco_patch(binary_data, magic_key_hex, manu_id_hex,
                      new_vendor=None, new_pn=None, new_sn=None):
    data = bytearray(binary_data)
    if len(data) < 512: data.extend(b'\x00' * (512 - len(data)))

    identifier = data[0]
    if identifier == 0x18:
        offsets, family = CMIS_MAP, "400G Family"
    elif identifier == 0x03:
        offsets, family = SFP_MAP, "SFP Family"
    else:
        offsets, family = QSFP_MAP, "QSFP Family"

    # --- PASSO 1: REBRANDING (Opcional) ---
    if new_vendor:
        start, end = offsets["vendor_name"]
        data[start:end] = format_sff_string(new_vendor)
    if new_pn:
        start, end = offsets["part_number"]
        data[start:end] = format_sff_string(new_pn)
    if new_sn:
        start, end = offsets["serial_number"]
        data[start:end] = format_sff_string(new_sn)

    # --- PASSO 2: EXTRAÇÃO FINAL PARA MD5 ---
    v_start, v_end = offsets["vendor_name"]
    vendor_final = data[v_start:v_end].decode('ascii', errors='ignore').strip()
    s_start, s_end = offsets["serial_number"]
    sn_final = data[s_start:s_end].decode('ascii', errors='ignore').strip()
    p_start, p_end = offsets["part_number"]
    pn_final = data[p_start:p_end].decode('ascii', errors='ignore').strip()

    # --- PASSO 3: CÁLCULO DAS ASSINATURAS ---
    manu_id_bytes = bytes.fromhex(manu_id_hex.zfill(2))
    vendor_padded = vendor_final.encode('ascii').ljust(16, b'\x20')
    serial_padded = sn_final.encode('ascii').ljust(16, b'\x20')
    magic_bytes = bytes.fromhex(magic_key_hex.replace(' ', ''))

    md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes
    md5_digest = hashlib.md5(md5_input).digest()

    # Reversed CRC32
    crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + (b'\x00' * 9)
    crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF
    crc32_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]

    # --- PASSO 4: RECÁLCULO DE CHECKSUMS PADRÃO ---
    if family == "SFP Family":
        data[63] = calculate_sff_checksum(data[0:63])
        data[95] = calculate_sff_checksum(data[64:95])
    elif family == "QSFP Family":
        data[191] = calculate_sff_checksum(data[128:191])
        data[223] = calculate_sff_checksum(data[192:223])
    elif family == "400G Family":
        data[255] = calculate_sff_checksum(data[128:255]) ##PRECISA CORRIGIR!!!
        #corrigido checksum

    # --- PASSO 5: INJEÇÃO DO PATCH CISCO ---
    if family == "SFP Family":
        data[96:98] = b'\x00\x00'  # 0x60, 0x61 — 2 bytes ← CORRIGIDO
        data[98] = manu_id_bytes[0]  # 0x62 — Manu ID
        data[99:115] = md5_digest  # 0x63-0x72 — MD5 (16 bytes)
        data[115:124] = b'\x00' * 9  # 0x73-0x7B — Zero padding ← FALTAVA
        data[124:128] = crc32_reversed  # 0x7C-0x7F — CRC32
    else:
        data[224:226] = b'\x00\x00'  # 0xE0, 0xE1 — 2 bytes ← também corrigir
        data[226] = manu_id_bytes[0]  # 0xE2 — Manu ID
        data[227:243] = md5_digest  # 0xE3-0xF2 — MD5 (16 bytes)
        data[243:252] = b'\x00' * 9  # 0xF3-0xFB — Zero padding ← FALTAVA
        data[252:256] = crc32_reversed  # 0xFC-0xFF — CRC32

    distance_str, _ = calculate_reach(data, family)
    t_type = TRANSCEIVER_IDENTIFIERS.get(identifier, family)

    return (data, vendor_final, pn_final, sn_final, t_type, "Optical",
            distance_str, "Rev 1.0", "Ready",
               md5_digest.hex().upper(), crc32_reversed.hex().upper())


def apply_juniper_patch(binary_data, magic_key_hex, manu_id_hex,
                      new_vendor=None, new_pn=None, new_sn=None):
    data = bytearray(binary_data)

    new_vendor, new_pn, new_sn, t_type = "Teste", "Teste", "Teste", "Teste"
    vendor_final = new_vendor
    pn_final = new_pn
    sn_final = new_sn
    t_type = t_type.upper()
    md5_digest = ("0102030401")
    crc32_reversed = ("01020304")
    distance_str = 10

    return (data, vendor_final, pn_final, sn_final, t_type, "Optical",
            distance_str, "Rev 1.0", "Ready",
            md5_digest().upper(), crc32_reversed.hex().upper())