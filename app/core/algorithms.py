import hashlib
import zlib
from app.core.constants import (
    SFP_MAP, QSFP_MAP, TRANSCEIVER_IDENTIFIERS,
    REVISION_COMPLIANCE, ETH_100G_COMPLIANCE, EXTENDED_COMPLIANCE
)


def calculate_sff_checksum(data_block):
# Soma todos os bytes do bloco e retorna apenas o byte menos significativo (LSB)
    return sum(data_block) & 0xFF


def calculate_reach(data, family):
    """
    Calcula a distância real baseada nos multiplicadores da norma SFF.
    Prioriza SMF (km) e depois as fibras Multimodo (OM4/OM3).
    """
    total_meters = 0

    if family == "QSFP Family":
        # SFF-8636: Byte 142 (km), 143 (OM3 * 2m), 146 (OM4 * 2m)
        smf_km = data[142]
        om4_2m = data[146] * 2
        om3_2m = data[143] * 2

        if smf_km > 0:
            return f"{smf_km} km", smf_km
        total_meters = max(om4_2m, om3_2m)

    elif family == "SFP Family":
        # SFF-8472: Byte 14 (km), 18 (OM4 * 10m), 19 (OM3 * 10m)
        smf_km = data[14]
        om4_10m = data[18] * 10
        om3_10m = data[19] * 10

        if smf_km > 0:
            return f"{smf_km} km", smf_km
        total_meters = max(om4_10m, om3_10m)

    # Formatação: Se menor que 1km, mostra decimal (ex: 0.3 km)
    if total_meters > 0:
        km_decimal = total_meters / 1000
        return f"{km_decimal:.1f} km", 0

    return "0 km", 0


def apply_cisco_patch(binary_data, magic_key_hex, manu_id_hex):
    data = bytearray(binary_data)
    identifier = data[0]

    # 1. Determinar Família e Offsets
    if identifier == 0x03:
        offsets = SFP_MAP
        family = "SFP Family"
    elif identifier in [0x0D, 0x11, 0x18]:
        offsets = QSFP_MAP
        family = "QSFP Family"
    else:
        offsets = QSFP_MAP
        family = "Unknown"

    # 2. Cálculo de Distância Inteligente
    # Retorna a string formatada para a UI e o valor SMF puro para a lógica de media_type
    distance_str, smf_val = calculate_reach(data, family)

    # 3. Extração Dinâmica de Dados (Vendor, PN, SN)
    try:
        v_start, v_end = offsets["vendor_name"]
        vendor_name = data[v_start:v_end].decode('ascii', errors='ignore').strip()

        p_start, p_end = offsets["part_number"]
        part_number = data[p_start:p_end].decode('ascii', errors='ignore').strip()

        s_start, s_end = offsets["serial_number"]
        serial_number = data[s_start:s_end].decode('ascii', errors='ignore').strip()
    except Exception:
        vendor_name, part_number, serial_number = "Unknown", "Unknown", "Unknown"

    # 4. Identificação do Tipo de Transceiver (SFF-8024)
    transceiver_type = TRANSCEIVER_IDENTIFIERS.get(identifier, f"{family} ({hex(identifier)})")

    # 5. Lógica de Media Type (QSFP Specific)
    media_type = "Unknown"
    if family == "QSFP Family":
        compliance_131 = data[131]
        extended_192 = data[192]

        # Lógica para variantes de 20km (usa o valor SMF puro)
        if smf_val == 20:
            media_type = "100G-4WDM-20" if extended_192 == 0x41 else "100G-LR4 (20km)"

        elif compliance_131 != 0:
            if compliance_131 & 0x02:
                media_type = "100GBASE-LR4"
            elif compliance_131 & 0x01:
                media_type = "100GBASE-ER4"
            elif compliance_131 & 0x80:
                # Se houver distância física, provavelmente não é um AOC (mesmo com bit 0x80)
                media_type = "100G-AOC" if smf_val == 0 and "0.0" in distance_str else "100G-SR4/Optical"

        if media_type == "Unknown" and extended_192 != 0:
            media_type = EXTENDED_COMPLIANCE.get(extended_192, f"Ext ({hex(extended_192)})")
    else:
        media_type = "SFP Standard"

    # 6. Check de Revisão e Status
    rev_byte = data[1]
    revision_name = REVISION_COMPLIANCE.get(rev_byte, f"Rev {hex(rev_byte)}")
    status_msg = "Module Ready" if (data[2] & 0x01) == 0 else "Data Not Ready"

    # 7. Expansão de Memória e Criptografia
    if len(data) < 512:
        data.extend(b'\x00' * (512 - len(data)))

    manu_id_bytes = bytes.fromhex(manu_id_hex.zfill(2))
    vendor_padded = vendor_name.encode('ascii').ljust(16, b'\x20')
    serial_padded = serial_number.encode('ascii').ljust(16, b'\x20')
    magic_bytes = bytes.fromhex(magic_key_hex.replace(' ', ''))

    # MD5 e CRC32
    md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes
    md5_digest = hashlib.md5(md5_input).digest()

    crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + (b'\x00' * 9)
    crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF
    crc32_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]

    # --- RECALCULO DE CHECKSUMS PADRÃO SFF ---
    # Importante: Faça isso ANTES de retornar os dados finais

    if family == "SFP Family":
        #SFF-8472
        # CC_BASE: Soma dos bytes 0 a 62, armazena no 63
        data[63] = calculate_sff_checksum(data[0:62])
        #CC_EXT: Soma dos bytes 64 a 94, armazena no 95
        data[95] = calculate_sff_checksum(data[64:94])

    elif family == "QSFP Family":
        # SFF-8636 (Upper Page 00h começa no offset 128)
        # CC_BASE: Soma dos bytes 128 a 190, armazena no 191
        data[191] = calculate_sff_checksum(data[128:190])
        # CC_EXT: Soma dos bytes 192 a 222, armazena no 223
        data[223] = calculate_sff_checksum(data[192:222])


    # 8. Injeção Binária - Codificação.

    if family == "SFP Family":
        data[96:97] = (b'\x00' * 2)     #60h - 62h
        data[98] = manu_id_bytes[0]     #62h
        data[99:114] = md5_digest       #63h - 72h
        data[115:123] = (b'\x00' * 9)   #73h a 7Bh
        data[124:127] = crc32_reversed  #7Ch a 7Fh
        print("Transceiver SFP Crackeado com sucesso!")
    elif family == "QSFP Family":
        data[224:225] = (b'\x00' * 2)  # E0h - E1h
        data[226] = manu_id_bytes[0]   # E2h
        data[227:242] = md5_digest     # E3h a F2h
        data[243:251] = (b'\x00' * 9)  # F3h a FBh
        data[252:256] = crc32_reversed # FCh a FFh
        print("Transceiver QSFP Crackeado com sucesso!")
    else :
        print("Error - Family not supported")



    return (
        data, vendor_name, part_number, serial_number,
        transceiver_type, media_type, distance_str,
        revision_name, status_msg,
        md5_digest.hex().upper(), crc32_reversed.hex().upper()
    )