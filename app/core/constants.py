# Magic Keys for Cisco's MD5 validation algorithm
MAGIC_KEYS = {
    "02 (Cisco)": "8DDAE6A4 6EC9DEF6 100BF185 059C3DAB",
    "08 (Cisco)": "30DB1EE9 C7913AE5 A3C8161B 574A9FF6",
    "0E (Cisco)": "4AF86716 ED1E2F34 7CA13C99 78AD8CA0",
    "11 (Cisco)": "E14869FD A81B1C21 2D715E3B C1371D75",
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