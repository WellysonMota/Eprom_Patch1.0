# Magic Keys for Cisco's MD5 validation algorithm
MAGIC_KEYS = {
    "02 (Cisco)": "8DDAE6A4 6EC9DEF6 100BF185 059C3DAB",
    "08 (Cisco)": "30DB1EE9 C7913AE5 A3C8161B 574A9FF6",
    "06 (Cisco)": "175258fe e9b4f0d9 eab6006f 7c65a8cb",
    "0E (Cisco)": "4AF86716 ED1E2F34 7CA13C99 78AD8CA0",
    "11 (Cisco)": "E14869FD A81B1C21 2D715E3B C1371D75",
    "JUNIPER": "",
    "INTEL": "",
    "HUAWEI": "",
}

# Standard Transceiver Form Factor Identifiers (SFF-8024 / CMIS)
TRANSCEIVER_IDENTIFIERS = {
    0x03: "SFP / SFP+ / SFP28",
    0x0D: "QSFP+",
    0x11: "QSFP28",
    0x18: "QSFP-DD (400G)",
    0x1E: "OSFP"
}

# Memory Map Offsets (Decimal)
SFP_MAP = {
    "vendor_name": (20, 36),   # 14h
    "part_number": (40, 56),   # 28h
    "serial_number": (68, 84), # 44h
}

QSFP_MAP = {
    "vendor_name": (148, 164), # 94h
    "part_number": (168, 184), # A8h
    "serial_number": (196, 212),# C4h
}

CMIS_MAP = {
    "vendor_name": (129, 145),   # 81h
    "part_number": (148, 164),   # 94h
    "serial_number": (166, 182), # A6h
}

# Compliance Tables
REVISION_COMPLIANCE = {
    0x00: "Unspecified",
    0x03: "SFF-8636 Rev 1.3",
    0x04: "SFF-8636 Rev 1.4",
    0x08: "SFF-8636 Rev 2.8/CMIS",
}

ETH_100G_COMPLIANCE = {0x02: "100GBASE-LR4", 0x01: "100GBASE-ER4", 0x80: "100G-AOC"}
EXTENDED_COMPLIANCE = {0x41: "100G-4WDM-20 (20km)", 0x42: "100G-4WDM-40 (40km)"}

# constants.py

# Dicionário consolidado de perfis Cisco para Rebranding
# Inclui 1G, 10G, 25G, 40G, 100G e 400G (incluindo Coerentes)
CISCO_PROFILES = {
    # --- 1G SFP (Memory Page A2h - Offset 180h) ---
    "GLC-SX-MM": {
        "tan": "10-2130-01V01",
        "clei": "COUIAJCBAA",
        "description": "1000BASE-SX (850nm MM)",
        "form_factor": "SFP"
    },
    "GLC-LH-SM": {
        "tan": "10-2131-01V01",
        "clei": "COUIAJDBAA",
        "description": "1000BASE-LX/LH (1310nm SM)",
        "form_factor": "SFP"
    },
    "GLC-ZX-SM": {
        "tan": "10-2132-01V01",
        "clei": "COUIAJ7BAA",
        "description": "1000BASE-ZX (1550nm SM 80km)",
        "form_factor": "SFP"
    },

    # --- 10G SFP+ (Memory Page A2h - Offset 180h) ---
    "SFP-10G-SR": {
        "tan": "10-2415-03V03",
        "clei": "COUIA8NCAA",
        "description": "10GBASE-SR (850nm MM)",
        "form_factor": "SFP",
        "media_code": "C6"  # Valor encontrado no byte 19Fh
    },
    "SFP-10G-LR": {
        "tan": "10-2457-02V01",
        "clei": "COUIAY8CAA",
        "description": "10GBASE-LR (1310nm SM 10km)",
        "form_factor": "SFP"
    },
    "SFP-10G-ER": {
        "tan": "10-2624-01V01",
        "clei": "COUIAZCCAA",
        "description": "10GBASE-ER (1550nm SM 40km)",
        "form_factor": "SFP"
    },
    "SFP-10G-ZR": {
        "tan": "10-2625-01V01",
        "clei": "COUIBALCAA",
        "description": "10GBASE-ZR (1550nm SM 80km)",
        "form_factor": "SFP"
    },

    # --- 25G SFP28 (Memory Page A2h - Offset 180h) ---
    "SFP-25G-SR-S": {
        "tan": "10-3120-01V01",
        "clei": "COUIBA3CAA",
        "description": "25GBASE-SR (100m MM)",
        "form_factor": "SFP"
    },
    "SFP-25G-LR-S": {
        "tan": "10-3121-01V01",
        "clei": "COUIBA4CAA",
        "description": "25GBASE-LR (10km SM)",
        "form_factor": "SFP"
    },

    # --- 40G QSFP+ (Upper Page 00h - Offset 202) ---
    "QSFP-40G-SR4": {
        "tan": "10-2651-01V01",
        "clei": "COUIAZ0CAA",
        "description": "40GBASE-SR4 (MPO MM)",
        "form_factor": "QSFP"
    },
    "QSFP-40G-LR4": {
        "tan": "10-2652-01V01",
        "clei": "COUIAZ1CAA",
        "description": "40GBASE-LR4 (LC SM 10km)",
        "form_factor": "QSFP"
    },

    # --- 100G QSFP28 (Upper Page 00h - Offset 202) ---
    "QSFP-100G-SR4": {
        "tan": "10-3115-01V01",
        "clei": "COUIATKCAA",
        "description": "100GBASE-SR4 (100m MM)",
        "form_factor": "QSFP"
    },
    "QSFP-100G-LR4": {
        "tan": "10-3116-01V01",
        "clei": "COUIATMCAF",
        "description": "100GBASE-LR4 (10km SM)",
        "form_factor": "QSFP"
    },
    "QSFP-100G-CWDM4": {
        "tan": "10-3142-01V01",
        "clei": "COUIASPCAA",
        "description": "100G-CWDM4 (2km SM)",
        "form_factor": "QSFP"
    },
    "QSFP28-100G-DCO": {
        "tan": "10-3250-01V01",
        "clei": "COUIATXCAA",
        "description": "100G Coherent DCO (DWDM)",
        "form_factor": "QSFP"
    },

    # --- 400G QSFP-DD (Upper Page 00h - Offset 202) ---
    "QSFP-DD-400G-FR4": {
        "tan": "10-3332-01V01",
        "clei": "COUIBCCCAA",
        "description": "400GBASE-FR4 (2km SM)",
        "form_factor": "QSFP-DD"
    },
    "QSFP-DD-400G-ZR-S": {
        "tan": "10-3480-01V01",
        "clei": "COUIBTCCAA",
        "description": "400G-ZR Coherent (120km DWDM)",
        "form_factor": "QSFP-DD"
    },
    "QSFP-DD-400G-ZRP-S": {
        "tan": "10-3481-01V01",
        "clei": "COUIBTECAA",
        "description": "400G-ZR+ Coherent (Multi-haul)",
        "form_factor": "QSFP-DD"
    }
}


JUNIPER_PROFILES = {
    # --- 1G SFP (Memory Page A2h - Offset 180h) ---
    "GLC-SX-MM": {
        "tan": "10-2130-01V01",
        "clei": "COUIAJCBAA",
        "description": "1000BASE-SX (850nm MM)",
        "form_factor": "SFP"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 02h PROFILES (Cisco) — fixed per SKU, NOT per unit.
# Each entry is the full 128-byte Page 02h block, validated against a real
# Apticom/vendor dump. Do NOT add a SKU here without a real reference dump —
# CLEI/checksums on this page are not derivable by formula.
# ─────────────────────────────────────────────────────────────────────────────
PAGE2_PROFILES = {
    "QSFP-100G-ZR-S": {
        "hex": "494E5549414B4445414131302D333234382D3031563031200100000000000000007800000000000000000000000000000000000000000000000000000000AAAA515346502D313030472D5A522D532020202020200000000000000000000000583634313334343131009800000000000000000000000000000000000000000000",
        "clei": "INUIAKDEAA",
        "pn": "10-3248-01",
        "product": "QSFP-100G-ZR-S",
        "status": "Validated",
        "note": "Confirmed byte-for-byte identical across all Apticom FTLC3351R3PL1-C units (fixed string, no per-unit calculation).",
    },
    "QSFP-100G-LR-S": {
        "hex": "494E5549414B4445414231302D333400312D3031563031200100000000000000009100000000000000000000000000000000000000000000000000000000AA00515346502D313030472D4C522D532000202020200000000000000000000000003634313334343131009800000000000000000000000000000000000000000000",
        "clei": "INUIAKDEAB",
        "pn": "10-344x-01",
        "product": "QSFP-100G-LR-S",
        "status": "Pending validation",
        "note": "Source: Smartoptics-encoded unit dump (SN 2611W38QX). Not yet confirmed whether 'LR-S' product string affects Nexus classification (zr-optics vs lr-optics) — validate before production use.",
    },

    # --- SFP family (checksum1 at offset 0x1F = sum(0x00-0x1E), NOT 0x21) ---
    "DS-SFP-FC16G-SW": {
        "hex": "434F5549414E5A43414131302D323431382D30315630312001004600000000E7000000000000000000000000000000000000000000000000000000000000AAAA44532D5346502D46433136472D535720202020203131000000000000000000EA000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF",
        "clei": "COUIANZCAA",
        "pn": "10-2418-01V01",
        "product": "DS-SFP-FC16G-SW",
        "status": "Validated",
        "note": "16G Fibre Channel SW. A duplicate dump (same CLEI/PN, labeled 'FC8G-SW') was discarded as mislabeled — confirm if an 8G variant exists separately before re-adding.",
    },
    "DS-SFP-FC32G-LW": {
        "hex": "434D554941503243414131302D333230372D30315630312001004600000000BC000000000000000000005D006400750091000000166740562E47004F0000AAAA44532D5346502D46433332472D4C5720202020203032000000000000000000E1000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF",
        "clei": "CMUIAP2CAA",
        "pn": "10-3207-01V01",
        "product": "DS-SFP-FC32G-LW",
        "status": "Validated",
        "note": "32G Fibre Channel LW.",
    },
    "DS-SFP-FC32G-SW": {
        "hex": "434D554941503343414131302D333230362D30315630312001004600000000BC000000000000000000000000000000000000000000000000000000000000AAAA44532D5346502D46433332472D535720202020203032000000000000000000E8000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF",
        "clei": "CMUIAP3CAA",
        "pn": "10-3206-01V01",
        "product": "DS-SFP-FC32G-SW",
        "status": "Validated",
        "note": "32G Fibre Channel SW.",
    },
    "SFP-10G-SR": {
        "hex": "434F554941384E43414131302D323431352D30335630332001004600000000C6000000000000000000000000000000000000000000000000000000000000AAAA5346502D3130472D535220202020202020202020323300000000000000000035151A20242A302030000000000000000000000000001D00000000000000000000",
        "clei": "COUIA8NCAA",
        "pn": "10-2415-03V03",
        "product": "SFP-10G-SR",
        "status": "Validated",
        "note": "10GBASE-SR. Confirmed identical across 3 field dumps (SPS-series SN). Checksums 0x1F and 0x5F verified; the 0x60-0x68 region here holds non-zero binary data (likely wavelength/calibration bytes, not an ASCII serial) and byte 0x69 does not match sum(0x60-0x68) — unlike QSFP dumps, this 'checksum3' rule has never been confirmed on a non-trivial SFP sample, so this may simply not apply to the SFP format.",
    },
    "SFP-25G-SR-S": {
        "hex": "434D554941524143414131302D333232372D30315630312001004600000000CF00000000000000000000000000000000000000000000000000000000000000005346502D3235472D53522D53202020202020202030370000000000000000007D000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF",
        "clei": "CMUIARACAA",
        "pn": "10-3227-01V01",
        "product": "SFP-25G-SR-S",
        "status": "Validated",
        "note": "25GBASE-SR. Checksums 0x1F and 0x5F verified, 0x60-0x68 region blank (chk3 trivially OK). Note: bytes 0x3E-0x3F are 00 00 here, not the AA AA marker seen on other CLEI dumps — appears to be a format difference for this CLEI generation, not corruption.",
    },
    "SFP-10/25G-CSR-S": {
        "hex": "494E554941435345414131302D333338382D30315630312001004600000000E300000000000000000000000000000000000000000000000000000000000000005346502D31302F3235472D4353522D53202020203038000000000000000000D11E202A2A3134293600000000000000000000000000560000FFFFFFFFFFFFFFFF",
        "clei": "INUIACSEAA",
        "pn": "10-3388-01V01",
        "product": "SFP-10/25G-CSR-S",
        "status": "Validated",
        "note": "10/25G dual-rate SR. Checksums 0x1F and 0x5F verified; 0x60-0x68 holds non-zero binary data and byte 0x69 doesn't match sum(0x60-0x68) — same open 'checksum3' question as SFP-10G-SR. Bytes 0x3E-0x3F are 00 00, not AA AA (same format note as SFP-25G-SR-S).",
    },

    # --- QSFP family (checksum1 at offset 0x21 = sum(0x00-0x20)) ---
    "QSFP-100G-SL4": {
        "hex": "434D554941584A43414131302D333531322D3031563031200100000000000000009500000000000000000000000000000000000000000000000000000000AAAA515346502D313030472D534C342020202020202000000000000000000000001F313333393937303831D900000000000000000000000000000000000000000000",
        "clei": "CMUIAXJCAA",
        "pn": "10-3512-01V01",
        "product": "QSFP-100G-SL4",
        "status": "Validated",
        "note": "Source file was named '...100G-SR4...' but the product string inside the EEPROM reads 'QSFP-100G-SL4' — named per actual EEPROM content, not the filename.",
    },
    "ONS-QSFP28-LR4": {
        "hex": "574F545244345742414131302D333230342D3031563031200100003520202020207100000000000000000000000000000000000000000000000000000000AAAA4F4E532D5153465032382D4C5234202020202020000000000000000000000080313333393937313331D500000000000000000000000000000000000000000000",
        "clei": "WOTRD4WBAA",
        "pn": "10-3204-01V01",
        "product": "ONS-QSFP28-LR4",
        "status": "Validated",
        "note": "Source file was named '...100G-SR4-L...' but the product string inside the EEPROM reads 'ONS-QSFP28-LR4' — named per actual EEPROM content, not the filename.",
    },
    "QSFP-40G-SR4": {
        "hex": "434F554941394A43414331302D323637322D3033563033200100000000000000008400000000000000000000000000000000000000000000000000000000AAAA515346502D3430472D53523420202020202020200000000000000000000000183634313334343230009800000000000000000000000000000000000000000000",
        "clei": "COUIA9JCAC",
        "pn": "10-2672-03V03",
        "product": "QSFP-40G-SR4",
        "status": "Validated",
        "note": "40GBASE-SR4.",
    },
    "QSFP-100G-LR4-S": {
        "hex": "434D5549414D4143414131302D333134362D3031563031200100003420202020205800000000000000000000000000000000000000000000000000000000AAAA515346502D313030472D4C52342D53202020202000000000000000000000005E313333393937313131D300000000000000000000000000000000000000000000",
        "clei": "CMUIAMACAA",
        "pn": "10-3146-01V01",
        "product": "QSFP-100G-LR4-S",
        "status": "Validated",
        "note": "100GBASE-LR4.",
    },
    "QSFP-H40G-AOC3M": {
        "hex": "434D505141425243414131302D323932372D3031563031200100000000000000009300000000000000000000000000000000000000000000000000000000AAAA515346502D483430472D414F43334D202020202000000000000000000000007A3634313334343230009800000000000000000000000000000000000000000000",
        "clei": "CMPQABRCAA",
        "pn": "10-2927-01V01",
        "product": "QSFP-H40G-AOC3M",
        "status": "Validated",
        "note": "40G Active Optical Cable, 3m.",
    },
    "QSFP-100G-AOC2M": {
        "hex": "434D505141435043414131302D333137342D3031563031200100000100000000008E00000000000000000000000000000000000000000000000000000000AAAA515346502D313030472D414F43324D202020202000000000000000000000005E313333393937303731D800000000000000000000000000000000000000000000",
        "clei": "CMPQACPCAA",
        "pn": "10-3174-01V01",
        "product": "QSFP-100G-AOC2M",
        "status": "Validated",
        "note": "100G Active Optical Cable, 2m.",
    },

    # --- Excluded pending a clean re-dump ---
    # "QSFP-100G-CWDM4-S": bytes 0x22-0x3D contained non-zero, calibration-like
    #   data where every other confirmed dump is blank, and the checksum at
    #   0x69 was overwritten by serial-field overflow. Likely a corrupted or
    #   misaligned page read — do not use until a clean dump is provided.
    # "SFP28-25G-SR": source file was 256 bytes of 0x00 (no Page 02h present)
    #   — awaiting a valid dump.
}