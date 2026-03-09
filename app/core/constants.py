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