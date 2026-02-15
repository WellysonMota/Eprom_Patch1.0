import hashlib

# ==============================================================================
# --- CONFIGURAÇÃO ---
# ==============================================================================

# 1. Inputs (Usando os Hex que você forneceu antes)
# Nota: O código original usa .encode('ascii'), mas como já temos em Hex, vamos usar bytes diretos.
MANU_ID_HEX = "08"  # Key 08
VENDOR_HEX = "434953434f2d46494e49534152202020"  # CISCO-FINISAR (16 bytes)
SERIAL_HEX = "41305843444347423720202020202020"  # A0XCDCGB7 (16 bytes)

# 2. (OPCIONAL) MD5 ALVO
# Se você souber qual MD5 o firmware está gerando, cole aqui.
# Se deixar vazio "", o script vai apenas LISTAR todos os MD5 gerados para você ver.
TARGET_MD5_HEX = "b25aa822d45d278fbfd2c2930d775456"
# Exemplo: "a1b2c3d4e5f6..."

# 3. LISTA DE CANDIDATOS (Sua lista limpa)
CANDIDATE_HASHES = [
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
    "8DDAE6A46EC9DEF6100BF185059C3DAB",
    "89232D6FA52638921EC281C26516F769",
    "D6A8458C7C1BD1EF0971BF3D10D5DDB3",
    "DEEFE6846A1331847BA0013F90723501",
    "17525XFEE9B4F0D9EAB6006F7C65A8CB",
    "0B79423280567577C04B34263C359EAA",
    "30DB1EE9C7913AE5A3C8161B574A9FF6",
    "20D1527B25EFD68C0DB41CB7473D2346",
    "5111887F14D5B0F35498CF61A375B222",
    "3C06164D2ACD619321FBA6C1C28BD403",
    "5A26A68DC15E5203FC353B305DE60160",
    "31F98E999FE119BB3DFFE555BD1FC1C2",
    "4AF86716ED1E2F347CA13C9978AD8CA0",
    "1DBAA98E645B0CE531D1C7830708D993",
    "12A7DD487A322967F4EAF08CF2A92202",
    "E14869FDA81B1C212D715E3BC1371D75",
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
# --- LÓGICA ---
# ==============================================================================

def generate_md5_table():
    try:
        manu_id_bytes = bytes.fromhex(MANU_ID_HEX)
        vendor_bytes = bytes.fromhex(VENDOR_HEX)
        serial_bytes = bytes.fromhex(SERIAL_HEX)

        target_md5 = None
        if TARGET_MD5_HEX:
            target_md5 = TARGET_MD5_HEX.strip().lower().replace(" ", "")
            print(f"🎯 Buscando por MD5 Alvo: {target_md5}")
        else:
            print(f"📋 Listando todos os MD5 gerados...")

    except ValueError as e:
        print(f"❌ Erro nos dados fixos: {e}")
        return

    found = False

    for index, hex_string in enumerate(CANDIDATE_HASHES):
        clean_hex = hex_string.strip().replace(" ", "")

        try:
            magic_bytes = bytes.fromhex(clean_hex)
        except ValueError:
            continue  # Pula inválidos (ex: o que tem 'X')

        if len(magic_bytes) != 16:
            continue

        # INPUT = [08] + [Vendor Padded] + [Serial Padded] + [Candidate Hash]
        md5_input = manu_id_bytes + vendor_bytes + serial_bytes + magic_bytes

        # CALCULA MD5
        md5_digest = hashlib.md5(md5_input).hexdigest()

        # SE TIVER ALVO, COMPARA. SE NÃO, MOSTRA TUDO.
        if target_md5:
            if md5_digest == target_md5:
                print(f"\n✅ SUCESSO! CANDIDATO ENCONTRADO!")
                print(f"📍 Índice: {index}")
                print(f"🔑 Chave de Entrada (Hex): {clean_hex.upper()}")
                print(f"📝 MD5 Gerado: {md5_digest}")
                found = True
                break
        else:
            # Mostra linha a linha
            print(f"[{index:02}] Entrada: {clean_hex[:8]}... -> MD5: {md5_digest}")

    if target_md5 and not found:
        print("\n❌ Nenhuma chave gerou o MD5 alvo.")


if __name__ == "__main__":
    generate_md5_table()