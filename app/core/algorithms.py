import hashlib
import zlib
from app.core.constants import TRANSCEIVER_IDENTIFIERS, REVISION_COMPLIANCE, ETH_100G_COMPLIANCE, EXTENDED_COMPLIANCE

def apply_cisco_patch(binary_data, magic_key_hex, manu_id_hex):
    data = bytearray(binary_data)

    # 1. Identification of Media Type (Byte 131)
    compliance_byte = data[131]
    media_type = "Unknown/Custom"

    # Check each bit to find the compliance
    for bit_mask, description in ETH_100G_COMPLIANCE.items():
        if compliance_byte & bit_mask:
            media_type = description
            break

    # 1. Hardware Identification (Byte 0)
    id_byte = data[0]
    transceiver_type = TRANSCEIVER_IDENTIFIERS.get(id_byte, f"Unknown ({hex(id_byte)})")

    # 2. Revision Compliance Algorithm (Byte 1)
    rev_byte = data[1]
    revision_name = REVISION_COMPLIANCE.get(rev_byte, f"Unknown Revision ({hex(rev_byte)})")

    # 1. Distance Check (The most reliable source for reach)
    distance_km = data[146]  # Byte 146 (92h)

    # 2. Compliance Logic
    compliance_131 = data[131]  # Byte 131 (83h)
    extended_192 = data[192]  # Byte 192 (C0h)

    media_type = "Unknown"

    # SMART LOGIC: If it's 20km, prioritize that regardless of Byte 131
    if distance_km == 20:
        if extended_192 == 0x41:
            media_type = "100G-4WDM-20"
        else:
            media_type = "100G-LR4 (20km Variant)"

    # If not 20km, follow the standard bitmask
    elif compliance_131 != 0:
        if compliance_131 & 0x02:
            media_type = "100GBASE-LR4"
        elif compliance_131 & 0x01:
            media_type = "100GBASE-ER4"
        elif compliance_131 & 0x80:
            # If distance is > 0, it's likely NOT an AOC despite the 0x80 bit
            media_type = "100G-AOC" if distance_km == 0 else "100G-Custom Optical"

    # Final fallback to Extended Codes
    if media_type == "Unknown" and extended_192 != 0:
        media_type = EXTENDED_COMPLIANCE.get(extended_192, f"Extended ({hex(extended_192)})")

    # 3. Basic Hardware Status (Byte 2)
    # Bit 0: 0 = Adressable/Ready, 1 = Not Ready
    status_byte = data[2]
    is_ready = (status_byte & 0x01) == 0
    status_msg = "Module Ready" if is_ready else "Data Not Ready"

    # --- MEMORY EXPANSION & DATA EXTRACTION (Keep your existing logic) ---
    if len(data) < 512:
        data.extend(b'\x00' * (512 - len(data)))

    try:
        vendor_name = data[148:164].decode('ascii', errors='ignore').strip()
        serial_number = data[196:212].decode('ascii', errors='ignore').strip()
        part_number = data[168:184].decode('ascii', errors='ignore').strip()

    except Exception:
        vendor_name = "Unknown"
        part_number = "Unknown"
        serial_number = "Unknown"

    # 4. Prepare inputs for MD5 Calculation
    manu_id_bytes = bytes.fromhex(manu_id_hex.zfill(2))
    vendor_padded = vendor_name.encode('ascii').ljust(16, b'\x20')
    serial_padded = serial_number.encode('ascii').ljust(16, b'\x20')
    magic_bytes = bytes.fromhex(magic_key_hex.replace(' ', ''))

    # 5. Generate MD5 Hash
    md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes
    md5_digest = hashlib.md5(md5_input).digest()

    # 6. Generate Reversed CRC32
    # Input format: 00 00 + ManuID + MD5 + 9 bytes of 0x00
    crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + (b'\x00' * 9)
    crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF
    crc32_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]

    # 7. Binary Injection
    data[226] = manu_id_bytes[0]      # Manu_ID at byte 226 (0xE2)
    data[227:243] = md5_digest        # MD5 starting at 227 (0xE3)
    data[252:256] = crc32_reversed    # CRC32 at the end of the block (0xFC)

    return (
        data,
        vendor_name,
        serial_number,
        part_number,
        transceiver_type,
        media_type,
        f"{distance_km} km",
        revision_name,  # New
        status_msg,  # New
        md5_digest.hex().upper(),
        crc32_reversed.hex().upper()
    )

