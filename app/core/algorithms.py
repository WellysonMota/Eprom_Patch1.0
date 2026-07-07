import hashlib
import zlib
import struct

from app.core.constants import (
    SFP_MAP, QSFP_MAP, CMIS_MAP, TRANSCEIVER_IDENTIFIERS,
    REVISION_COMPLIANCE, MAGIC_KEYS
)


def calculate_sff_checksum(data_block):
    """Soma mod 256 para conformidade SFF/CMIS."""
    return sum(data_block) & 0xFF


def format_sff_string(text, length=16):
    """Garante N bytes com preenchimento de espaços (0x20)."""
    clean_text = str(text).encode('ascii', errors='ignore').strip()
    return clean_text.ljust(length, b'\x20')[:length]


def detect_identifier(data):
    """
    Detects the transceiver identifier correctly.
    Some files (e.g. 512-byte AOC) have a blank lower page (all 0xFF)
    and the real identifier lives at byte 0x80 (start of upper page).
    """
    byte0 = data[0]
    # Lower page blank → read real identifier from upper page byte 0 (offset 0x80)
    if byte0 == 0xFF and len(data) >= 129:
        return data[0x80]
    return byte0


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
    if len(data) < 512:
        data.extend(b'\x00' * (512 - len(data)))

    # ── Detect module family ──────────────────────────────────────────────────
    identifier = detect_identifier(data)

    if identifier == 0x18:
        offsets, family = CMIS_MAP, "400G Family"
    elif identifier == 0x03:
        offsets, family = SFP_MAP, "SFP Family"
    else:
        # QSFP28 (0x0C), QSFP+ (0x0D), QSFP-DD (0x11), and any unknown
        offsets, family = QSFP_MAP, "QSFP Family"

    # ── STEP 1: Optional rebranding ───────────────────────────────────────────
    if new_vendor:
        start, end = offsets["vendor_name"]
        data[start:end] = format_sff_string(new_vendor)
    if new_pn:
        start, end = offsets["part_number"]
        data[start:end] = format_sff_string(new_pn)
    if new_sn:
        start, end = offsets["serial_number"]
        data[start:end] = format_sff_string(new_sn)

    # ── STEP 2: Extract final fields for display and MD5 ─────────────────────
    v_start, v_end = offsets["vendor_name"]
    s_start, s_end = offsets["serial_number"]
    p_start, p_end = offsets["part_number"]

    vendor_final = data[v_start:v_end].decode('ascii', errors='ignore').strip()
    sn_final     = data[s_start:s_end].decode('ascii', errors='ignore').strip()
    pn_final     = data[p_start:p_end].decode('ascii', errors='ignore').strip()

    # ── STEP 3: Compute Cisco signatures ─────────────────────────────────────
    manu_id_byte  = bytes.fromhex(manu_id_hex.zfill(2))
    magic_bytes   = bytes.fromhex(magic_key_hex.replace(' ', ''))

    # MD5 payload: use the vendor name that is ACTUALLY in the EEPROM
    # (either the original or the rebranded one from Step 1)
    vendor_padded = data[v_start:v_end]          # 16 bytes, already in EEPROM
    serial_padded = data[s_start:s_end]          # 16 bytes, already in EEPROM

    md5_input  = manu_id_byte + vendor_padded + serial_padded + magic_bytes
    md5_digest = hashlib.md5(md5_input).digest()

    # ── STEP 4: Recalculate standard SFF checksums (BEFORE patch injection) ───
    if family == "SFP Family":
        data[63]  = calculate_sff_checksum(data[0:63])
        data[95]  = calculate_sff_checksum(data[64:95])
    elif family == "QSFP Family":
        data[191] = calculate_sff_checksum(data[128:191])  # CC_BASE
        data[223] = calculate_sff_checksum(data[192:223])  # CC_EXT
    elif family == "400G Family":
        data[255] = calculate_sff_checksum(data[128:255])  # CMIS CC

    # ── STEP 5: Inject Cisco patch bytes ─────────────────────────────────────
    if family == "SFP Family":
        # SFP patch area: 0x60-0x7F
        data[96:98]   = b'\x00\x00'         # 0x60-0x61
        data[98]      = manu_id_byte[0]     # 0x62  Manu_ID
        data[99:115]  = md5_digest          # 0x63-0x72  MD5 (16 bytes)
        data[115:124] = b'\x00' * 9         # 0x73-0x7B  padding
        # CRC32 over the full patch window (28 bytes)
        crc_window    = bytes(data[96:124])
        crc32_val     = zlib.crc32(crc_window) & 0xFFFFFFFF
        data[124:128] = struct.pack('<I', crc32_val)  # 0x7C-0x7F  CRC32 LE
    else:
        # QSFP / QSFP-DD / AOC patch area: 0xE0-0xFF
        data[224:226] = b'\x00\x00'         # 0xE0-0xE1
        data[226]     = manu_id_byte[0]     # 0xE2  Manu_ID
        data[227:243] = md5_digest          # 0xE3-0xF2  MD5 (16 bytes)
        data[243:252] = b'\x00' * 9         # 0xF3-0xFB  padding
        # CRC32 over bytes 0xE0-0xFB (28 bytes) — confirmed correct
        crc_window    = bytes(data[224:252])
        crc32_val     = zlib.crc32(crc_window) & 0xFFFFFFFF
        data[252:256] = struct.pack('<I', crc32_val)  # 0xFC-0xFF  CRC32 LE

    crc32_str     = data[252:256].hex().upper() if family != "SFP Family" else data[124:128].hex().upper()
    distance_str, _ = calculate_reach(data, family)
    t_type        = TRANSCEIVER_IDENTIFIERS.get(identifier, f"QSFP (0x{identifier:02X})")

    # ── Fix: ensure byte 0 carries the real identifier ────────────────────────
    # Files with a blank lower page (byte 0 = 0xFF) cause download issues in
    # browsers because the file appears to start with hundreds of 0xFF bytes.
    # Writing the real identifier (from byte 0x80) to byte 0 fixes this.
    if data[0] == 0xFF and len(data) >= 129:
        data[0] = data[0x80]

    return (data, vendor_final, pn_final, sn_final, t_type, "Optical",
            distance_str, "Rev 1.0", "Ready",
            md5_digest.hex().upper(), crc32_str)


def apply_juniper_patch(binary_data, magic_key_hex, manu_id_hex,
                        new_vendor=None, new_pn=None, new_sn=None):
    """
    Juniper patch: writes Juniper PN at offset 0x60-0x71 (A0h),
    recalculates CC_EXT. No MD5/CRC32 — Juniper only validates the PN string.
    Stub — full implementation pending.
    """
    data = bytearray(binary_data)

    identifier   = detect_identifier(data)
    offsets      = SFP_MAP if identifier == 0x03 else QSFP_MAP
    family       = "SFP Family" if identifier == 0x03 else "QSFP Family"

    if new_vendor:
        start, end = offsets["vendor_name"]
        data[start:end] = format_sff_string(new_vendor)
    if new_pn:
        start, end = offsets["part_number"]
        data[start:end] = format_sff_string(new_pn)
    if new_sn:
        start, end = offsets["serial_number"]
        data[start:end] = format_sff_string(new_sn)

    v_start, v_end = offsets["vendor_name"]
    s_start, s_end = offsets["serial_number"]
    p_start, p_end = offsets["part_number"]

    vendor_final = data[v_start:v_end].decode('ascii', errors='ignore').strip()
    sn_final     = data[s_start:s_end].decode('ascii', errors='ignore').strip()
    pn_final     = data[p_start:p_end].decode('ascii', errors='ignore').strip()

    # Recalculate checksums
    if family == "SFP Family":
        data[63] = calculate_sff_checksum(data[0:63])
        data[95] = calculate_sff_checksum(data[64:95])
    else:
        data[191] = calculate_sff_checksum(data[128:191])
        data[223] = calculate_sff_checksum(data[192:223])

    distance_str, _ = calculate_reach(data, family)
    t_type = TRANSCEIVER_IDENTIFIERS.get(identifier, f"Unknown (0x{identifier:02X})")

    return (data, vendor_final, pn_final, sn_final, t_type, "Optical",
            distance_str, "Rev 1.0", "Ready",
            "N/A (Juniper)", "N/A (Juniper)")