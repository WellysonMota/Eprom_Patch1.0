import hashlib
import zlib
import binascii
import struct

# ==============================================================================
# --- CONFIGURAÇÃO ---
# ==============================================================================

# 1. Inputs (Usando os Hex que você forneceu antes)
# Nota: O código original usa .encode('ascii'), mas como já temos em Hex, vamos usar bytes diretos.
MANU_ID_HEX = "02"  # Key 08
VENDOR_HEX = "46494e4953415220434f52502e202020"  # CISCO-FINISAR (16 bytes)
SERIAL_HEX = "4134364134524b202020202020202020"  # A0XCDCGB7 (16 bytes)

# 2. O CRC32 Alvo (Resultado Final Esperado)
TARGET_CRC_HEX = "29c2a9b8"

# 3. LISTA DE MAGIC BYTES CANDIDATOS (Sua lista de Hashes Cisco)
CANDIDATE_MAGIC_BYTES = [
    "BE3BBAC5280BBDB2925AB42B046AB35C",
    "A7FFD7C231CFD0B58B9ED92C1DAEDE5B",
    "B0C2649B26F263EC9CA36A750A936D02",
    "A906099C3F360EEB8567077213570005",
    "824ABF95147AB8E2AE2BB17B381BB60C",
    "9B8ED2920DBED5E5B7EFDC7C21DFDB0B",
    "D4D2D38642E2D4F1F8B3DD686E83DA1F",
    "CD16BE815B26B9F6E177B06F7747B718",
    "E65A0888706A0FFFCA3B06665C0B0111",
    "FF9E658F69AE62F8D3FF6B6145CF6C16",
    "78E20AA0EED20DD75483044EC2B30339",
    "612667A7F71660D04D476949DB776E3E",
    "4A6AD1AEDC5AD6D9660BDF40F03BD837",
    "53AEBCA9C59EBBD77FCFB247E9FFB530",
    "1CF2BDBD8AC2BACA3093B353A6A3B424",
    "0536D0BA9306D7CD2957DE54BF67D923",
    "2E7A66B3B84A61C4021B685D942B6F2A",
    "37BE0BB4A18E0CC31BDF055A8DEF022D",
    "1BBB2B46DFCC171F1E62F77679A8C9A6",
    "3B2518C45F7E5BA298C3A6EF99FFF6E3",
    "8DDAE6A46EC9DEF6100BF185059C3DAB",  # Key 02
    "89232D6FA52638921EC281C26516F769",
    "D6A8458C7C1BD1EF0971BF3D10D5DDB3",
    "DEEFE6846A1331847BA0013F90723501",
    "17525XFEE9B4F0D9EAB6006F7C65A8CB",  # Cuidado com o X
    "0B79423280567577C04B34263C359EAA",
    "30DB1EE9C7913AE5A3C8161B574A9FF6",
    "20D1527B25EFD68C0DB41CB7473D2346",
    "5111887F14D5B0F35498CF61A375B222",
    "3C06164D2ACD619321FBA6C1C28BD403",
    "5A26A68DC15E5203FC353B305DE60160",
    "31F98E999FE119BB3DFFE555BD1FC1C2",
    "4AF86716ED1E2F347CA13C9978AD8CA0",  # Key 0E
    "1DBAA98E645B0CE531D1C7830708D993",
    "12A7DD487A322967F4EAF08CF2A92202",
    "E14869FDA81B1C212D715E3BC1371D75",  # Key 11
    "E115E6F5769D4EAC54E15809FC0BF465",
    "AC94DCE66C21576FF1DF977DFBAC7D59",
    "9950B24AE24DAEF2ABB5640F56A3F1DA",
    "4FCEF279707CBDBEBC1B75388577095F",
    "3869230ABE442B4BDB58239F20902B51",
    "DAB6CD86032D50106F14069D9F87D057",
    "BF3F4764F98FC3A5F1C896B959D480D9",
    "5D7C3B2CF7041E830AEB4C7B08EEB350",
    "3ED40F47A421A71100F5AD5C025D0164",
    "C8FF5D5C5A4008F79C8034E4E19AD27B",
    "94468BB4BF08A79E06F1689A1B3CBE00",
    "2A4022062CD21D7E06E2D1E62A9B1D98",
    "E286ABBA3A36D31EF5CAD751944086BD",
    "646F9C596FAA6F0669121162D2D383C7",
    "18837E4B24A83ABFCA62F9928CBB9A6D",
    "965BC91601C8DC90A2100578FA602507",
    "465FF5558E61CD4288C6BF7CD47BCA2E",
    "B0169A7D132C754CE4EC9D178243F34A",
    "5BF810F9487F7CF63DF929D19C7026F1",
    "B19E0F6E95E549F90D85E9408A7BECAD",
    "596FEE2682D456BDDBF946CFC4CCBED6",
    "AAE437D987E43AB91EEDD8F3E1EA0203",
    "3DA46AEE2B8D6C755FC717466B6D61BD",
    "8B0703DDD839567A17127B30B9AE536B",
    "1AA6972F247D9E4FCC538C58624440A5",
    "53F8836B99C3AE5CF714C207F0B8D0E4",
    "DF7661FAADB2FC1A20BDA5E3D9715AAF",
    "14A7B773CAB32131C0D5BD679618786F",
    "8B04EE5E864E86086DE47208B0F491BB"
]


# ==============================================================================
# --- LÓGICA DO ALGORITMO (Baseada no seu snippet) ---
# ==============================================================================

def brute_force():
    # Prepara os dados fixos
    try:
        # manu_id_bytes = bytes.fromhex(manu_id_hex.zfill(2))
        manu_id_bytes = bytes.fromhex(MANU_ID_HEX)

        # vendor_padded = vendor_name.encode('ascii').ljust(16, b'\x20')
        vendor_padded = bytes.fromhex(VENDOR_HEX)  # Já está com padding e hex

        # serial_padded = serial_number.encode('ascii').ljust(16, b'\x20')
        serial_padded = bytes.fromhex(SERIAL_HEX)  # Já está com padding e hex

        target_crc_int = int(TARGET_CRC_HEX, 16)

    except ValueError as e:
        print(f"❌ Erro nos dados de entrada: {e}")
        return

    print(f"🔧 Iniciando Brute-Force Complexo (MD5 -> CRC32)...")
    print(f"🎯 Alvo CRC32: {hex(target_crc_int).upper()}")

    found = False

    for index, hex_string in enumerate(CANDIDATE_MAGIC_BYTES):
        clean_hex = hex_string.strip().replace(" ", "")

        try:
            # magic_bytes = bytes.fromhex(magic_key_hex.replace(' ', ''))
            magic_bytes = bytes.fromhex(clean_hex)
        except ValueError:
            continue

        if len(magic_bytes) != 16:
            continue

        # --- ETAPA 1: MD5 Calculation ---
        # md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes
        md5_input = manu_id_bytes + vendor_padded + serial_padded + magic_bytes

        # md5_digest = hashlib.md5(md5_input).digest()
        md5_digest = hashlib.md5(md5_input).digest()

        # --- ETAPA 2: CRC32 Input Construction ---
        # crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + (b'\x00' * 9)
        padding_nine = b'\x00' * 9
        crc_input = b'\x00\x00' + manu_id_bytes + md5_digest + padding_nine

        # --- ETAPA 3: CRC32 Calculation ---
        # crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF
        crc32_val = zlib.crc32(crc_input) & 0xFFFFFFFF

        # crc32_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]
        # Isso inverte os BYTES (ex: 0xAABBCCDD vira 0xDDCCBBAA)
        # Convertendo isso de volta para int para comparar
        crc32_bytes_reversed = crc32_val.to_bytes(4, byteorder='big')[::-1]
        crc32_reversed_int = int.from_bytes(crc32_bytes_reversed, byteorder='big')

        # Debug Opcional (se quiser ver o que está calculando)
        # print(f"Testando {clean_hex[:4]}... CRC Calc: {hex(crc32_val)} | Rev: {hex(crc32_reversed_int)}")

        if crc32_val == target_crc_int or crc32_reversed_int == target_crc_int:
            print(f"\n✅ SUCESSO! MAGIC KEY ENCONTRADA!")
            print(f"📍 Índice na Lista: {index}")
            print(f"🔑 Magic Key (Hex): {clean_hex.upper()}")
            print(f"📝 MD5 Gerado: {md5_digest.hex()}")

            if crc32_val == target_crc_int:
                print(f"⚙️ Match: CRC32 Direto")
            else:
                print(f"⚙️ Match: CRC32 Reverso (Bytes Invertidos)")

            found = True
            break

    if not found:
        print("\n❌ Nenhuma chave da lista funcionou com esse algoritmo.")


if __name__ == "__main__":
    brute_force()