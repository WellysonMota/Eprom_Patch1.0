import hashlib
import zlib
from app.core.constants import (
    SFP_MAP, QSFP_MAP, CMIS_MAP, TRANSCEIVER_IDENTIFIERS,
    REVISION_COMPLIANCE, ETH_100G_COMPLIANCE, EXTENDED_COMPLIANCE
)


def calculate_sff_checksum(data_block):
    """Calcula a soma de verificação de 8 bits (Soma mod 256)."""
    return sum(data_block) & 0xFF


def calculate_reach(data, family):
    """
    Calcula a distância baseada nos multiplicadores SFF/CMIS.
    Retorna (String formatada, valor SMF puro).
    """
    total_meters = 0

    if family == "400G Family":
        # CMIS (400G): SMF km no 182, OM3 no 184 (*2m), OM4 no 185 (*2m)
        smf_km = data[182] if len(data) > 182 else 0
        om4_2m = (data[185] if len(data) > 185 else 0) * 2
        om3_2m = (data[184] if len(data) > 184 else 0) * 2
        if smf_km > 0: return f"{smf_km} km", smf_km
        total_meters = max(om4_2m, om3_2m)

    elif family == "QSFP Family":
        # SFF-8636: Byte 142 (km), 143 (OM3 * 2m), 146 (OM4 * 2m)
        smf_km = data[142] if len(data) > 142 else 0
        om4_2m = (data[146] if len(data) > 146 else 0) * 2
        om3_2m = (data[143] if len(data) > 143 else 0) * 2
        if smf_km > 0: return f"{smf_km} km", smf_km
        total_meters = max(om4_2m, om3_2m)

    elif family == "SFP Family":
        # SFF-8472: Byte 14 (km), 18 (OM4 * 10m), 19 (OM3 * 10m)
        smf_km = data[14] if len(data) > 14 else 0
        om4_10m = (data[18] if len(data) > 18 else 0) * 10
        om3_10m = (data[19] if len(data) > 19 else 0) * 10
        if smf_km > 0: return f"{smf_km} km", smf_km
        total_meters = max(om4_10m, om3_10m)

    if total_meters > 0:
        km_decimal = total_meters / 1000
        return f"{km_decimal:.1f} km", 0
    return "0 km", 0


def apply_cisco_patch(binary_data, magic_key_hex, manu_id_hex):
    data = bytearray(binary_data)
    # Garantir tamanho mínimo para processamento
    if len(data) < 256:
        data.extend(b'\x00' * (256 - len(data)))

    identifier = data[0]

    # 1. Determinar Família e Seleção de Offsets
    if identifier == 0x18:  # QSFP-DD (400G)
        offsets = CMIS_MAP
        family = "400G Family"
    elif identifier == 0x03:
        offsets = SFP_MAP
        family = "SFP Family"
    else:
        offsets = QSFP_MAP
        family = "QSFP Family"

    # 2. Extração de Identidade e Distância
    distance_str, smf_val = calculate_reach(data, family)

    try:
        v_start, v_end = offsets["vendor_name"]
        vendor_name = data[v_start:v_end].decode('ascii', errors='ignore').strip()
        p_start, p_end = offsets["part_number"]
        part_number = data[p_start:p_end].decode('ascii', errors='ignore').strip()
        s_start, s_end = offsets["serial_number"]
        serial_number = data[s_start:s_end].decode('ascii', errors='ignore').strip()
    except Exception:
        vendor_name, part_number, serial_number = "Unknown", "Unknown", "Unknown"

    # 3. Metadados e Status
    transceiver_type = TRANSCEIVER_IDENTIFIERS.get(identifier, f"{family} ({hex(identifier)})")
    rev_byte = data[1]
    revision_name = REVISION_COMPLIANCE.get(rev_byte, f"Rev {hex(rev_byte)}")
    status_msg = "Module Ready" if (data[2] & 0x01) == 0 else "Data Not Ready"
    media_type = "400G Optical" if family == "400G Family" else "Optical Module"

    # 4. Cálculo de Patch (MD5 e CRC32)
    if len(data) < 512:
        data.extend(b'\x00' * (512 - len(data)))

    manu_id_bytes = bytes.fromhex(manu_id_hex.zfill(2))
    vendor_padded = vendor_name.encode('ascii').ljust(16, b'\x20')
    serial_padded = serial_number.encode('ascii').ljust(16, b'\x20')
    magic_bytes = bytes.fromhex(magic_key_hex.replace(' ', ''))

    md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes
    md5_digest = hashlib.md5(md5_input).digest()

    crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + (b'\x00' * 9)
    crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF
    crc32_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]

    # 5. Recálculo de Checksums Padrão SFF/CMIS
    if family == "SFP Family":
        data[63] = calculate_sff_checksum(data[0:62])
        data[95] = calculate_sff_checksum(data[64:94])
    elif family == "QSFP Family":
        data[191] = calculate_sff_checksum(data[128:190])
        data[223] = calculate_sff_checksum(data[192:222])
    elif family == "400G Family":
        data[255] = calculate_sff_checksum(data[128:254])

    # 6. Injeção Final do Patch (Logica por Familia)
    if family == "SFP Family":
        # Cisco SFP Offsets: E2=ManuID, E3=MD5, FC=CRC
        data[226] = manu_id_bytes[0]
        data[227:243] = md5_digest
        data[252:256] = crc32_reversed
    else:  # QSFP e 400G usam offsets similares para Patch Cisco
        data[226] = manu_id_bytes[0]
        data[227:243] = md5_digest
        data[252:256] = crc32_reversed

    # Retorno compatível com os 11 valores esperados pelo main.py
    return (
        data, vendor_name, part_number, serial_number,
        transceiver_type, media_type, distance_str,
        revision_name, status_msg,
        md5_digest.hex().upper(), crc32_reversed.hex().upper()
    )