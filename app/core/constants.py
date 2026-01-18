# Magic Keys for Cisco's MD5 validation algorithm
MAGIC_KEYS = {
    "02 (Cisco 1)": "8DDAE6A4 6EC9DEF6 100BF185 059C3DAB",
    "0E (Cisco 2)": "4AF86716 ED1E2F34 7CA13C99 78AD8CA0",
    "11 (Cisco 3)": "E14869FD A81B1C21 2D715E3B C1371D75",
}

# Standard Transceiver Form Factor Identifiers (SFF-8024)
TRANSCEIVER_IDENTIFIERS = {
    0x03: "SFP / SFP+ / SFP28",
    0x0D: "QSFP+",
    0x11: "QSFP28",
    0x18: "QSFP-DD",
    0x1E: "OSFP"
}

# SFF-8636 Revision Compliance Codes (Byte 01h)
REVISION_COMPLIANCE = {
    0x00: "Unspecified",
    0x01: "SFF-8436 Rev 4.8",
    0x02: "SFF-8436 Rev 4.8 or later",
    0x03: "SFF-8636 Rev 1.3",
    0x04: "SFF-8636 Rev 1.4",
    0x05: "SFF-8636 Rev 1.5",
    0x06: "SFF-8636 Rev 2.0",
    0x07: "SFF-8636 Rev 2.5, 2.6 and 2.7",
    0x08: "SFF-8636 Rev 2.8, 2.9, 2.10 and 2.11"
}

# Status Indicators (Byte 02h)
# Bit 0 is 'Data Not Ready'
HARDWARE_STATUS = {
    "READY": "Module Ready",
    "NOT_READY": "Data Not Ready (Initializing)",
}

# 100G Ethernet Compliance Codes (Byte 131 / 83h)
ETH_100G_COMPLIANCE = {
    0x80: "100G AOC (Active Optical Cable)",
    0x40: "100G ACC (Active Copper Cable)",
    0x20: "100GBASE-SR10",
    0x10: "100G-CWDM4 MSA",
    0x08: "100GBASE-CR4",
    0x04: "100GBASE-SR4",
    0x02: "100GBASE-LR4",
    0x01: "100GBASE-ER4"
}

# Extended Specification Compliance Codes (Byte 192 / C0h)
EXTENDED_COMPLIANCE = {
    0x02: "100GBASE-LR4 (10km)",
    0x0B: "100G-CWDM4 MSA (2km)",
    0x41: "100G-4WDM-20 (20km)",
    0x42: "100G-4WDM-40 (40km)",
    0x43: "100G-LR4-P (Standard)",
}