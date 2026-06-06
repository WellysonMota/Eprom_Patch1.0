#!/usr/bin/env python3
"""
Cisco SFP Binary Validator
==========================
Simulates the Cisco switch validation logic for SFP transceivers.
Checks if a patched .bin would pass the switch's authentication check.

Algorithm:
  1. Read Manu ID (0x62), Vendor PN (0x14-0x23), Serial Number (0x44-0x53)
  2. Select Magic Key based on Manu ID
  3. Compute MD5(Manu ID + Vendor PN + SN + Magic Key)
  4. Verify MD5 is stored at 0x63-0x72
  5. Verify 9 zero bytes at 0x73-0x7B
  6. Compute CRC32 of bytes 0x60-0x7B
  7. Verify CRC32 (reversed) is stored at 0x7C-0x7F
"""

import sys
import hashlib
import binascii
import struct

# ── Magic Keys per Manufacturer ID ──────────────────────────────────────────
MAGIC_KEYS = {
    0x02: bytes.fromhex("8DDAE6A46EC9DEF6100BF185059C3DAB"),  # Manu ID 02 (Cisco)
    0x08: bytes.fromhex("30DB1EE9C7913AE5A3C8161B574A9FF6"),  # Manu ID 08 (Cisco)
    0x11: bytes.fromhex("E14869FDA81B1C212D715E3BC1371D75"),  # Manu ID 08 (Cisco)
}

# ── Offsets (SFF/SFP standard + Cisco extension) ────────────────────────────
OFF_VENDOR_PN   = (0x14, 0x24)   # 16 bytes
OFF_SN          = (0x44, 0x54)   # 16 bytes
OFF_MANU_ID     = 0x62           # 1 byte
OFF_MD5_START   = 0x63           # 16 bytes  -> 0x63-0x72
OFF_ZERO_START  = 0x73           # 9 bytes   -> 0x73-0x7B
OFF_CRC_START   = 0x7C           # 4 bytes   -> 0x7C-0x7F
CRC_REGION      = (0x60, 0x7C)   # bytes used for CRC32 calculation


def validate(filepath: str) -> bool:
    print(f"\n{'='*55}")
    print(f"  Cisco SFP Validator")
    print(f"{'='*55}")
    print(f"  File: {filepath}\n")

    # ── Read file ────────────────────────────────────────────────────────────
    try:
        with open(filepath, "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"  [ERROR] File not found: {filepath}")
        return False

    if len(data) < 0x80:
        print(f"  [ERROR] File too small ({len(data)} bytes). Expected at least 128 bytes.")
        return False

    # ── Extract fields ───────────────────────────────────────────────────────
    manu_id = data[OFF_MANU_ID]
    vendor  = bytes(data[OFF_VENDOR_PN[0]:OFF_VENDOR_PN[1]])
    sn      = bytes(data[OFF_SN[0]:OFF_SN[1]])

    print(f"  Manufacturer ID : 0x{manu_id:02X}")
    print(f"  Vendor PN       : {vendor.decode('ascii', errors='replace').strip()}")
    print(f"  Serial Number   : {sn.decode('ascii', errors='replace').strip()}")
    print()

    all_pass = True

    # ── Check 1: Manu ID has a known Magic Key ───────────────────────────────
    if manu_id not in MAGIC_KEYS:
        print(f"  [FAIL] ❌  Manu ID 0x{manu_id:02X} has no Magic Key defined.")
        return False

    key = MAGIC_KEYS[manu_id]

    # ── Check 2: MD5 ─────────────────────────────────────────────────────────
    payload        = bytes([manu_id]) + vendor + sn + key
    calc_md5       = hashlib.md5(payload).digest()
    stored_md5     = bytes(data[OFF_MD5_START:OFF_MD5_START + 16])

    md5_ok = calc_md5 == stored_md5
    status = "✅  PASS" if md5_ok else "❌  FAIL"
    print(f"  [MD5]  {status}")
    print(f"         Calculated : {calc_md5.hex()}")
    print(f"         Stored     : {stored_md5.hex()}")
    if not md5_ok:
        all_pass = False
    print()

    # ── Check 3: Zero padding (0x73-0x7B) ────────────────────────────────────
    zero_region  = bytes(data[OFF_ZERO_START:OFF_ZERO_START + 9])
    zeros_ok     = zero_region == b'\x00' * 9
    status = "✅  PASS" if zeros_ok else "❌  FAIL"
    print(f"  [ZERO] {status}  (0x73-0x7B)")
    if not zeros_ok:
        print(f"         Expected : 00 * 9")
        print(f"         Found    : {zero_region.hex(' ').upper()}")
        all_pass = False
    print()

    # ── Check 4: CRC32 ───────────────────────────────────────────────────────
    crc_input   = bytes(data[CRC_REGION[0]:CRC_REGION[1]])
    calc_crc    = binascii.crc32(crc_input) & 0xFFFFFFFF
    calc_crc_b  = struct.pack(">I", calc_crc)[::-1]   # reversed big-endian
    stored_crc  = bytes(data[OFF_CRC_START:OFF_CRC_START + 4])

    crc_ok = calc_crc_b == stored_crc
    status = "✅  PASS" if crc_ok else "❌  FAIL"
    print(f"  [CRC32] {status}")
    print(f"          Calculated : {' '.join(f'{b:02X}' for b in calc_crc_b)}")
    print(f"          Stored     : {' '.join(f'{b:02X}' for b in stored_crc)}")
    if not crc_ok:
        all_pass = False
    print()

    # ── Final result ─────────────────────────────────────────────────────────
    print(f"{'='*55}")
    if all_pass:
        print("  RESULT: ✅  PASS — Binary would be accepted by the switch")
    else:
        print("  RESULT: ❌  FAIL — Binary would be REJECTED by the switch")
    print(f"{'='*55}\n")

    return all_pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cisco_sfp_validator.py <path_to_bin>")
        print("Example: python3 cisco_sfp_validator.py patched_AHM013M_cisco.bin")
        sys.exit(1)

    result = validate(sys.argv[1])
    sys.exit(0 if result else 1)
