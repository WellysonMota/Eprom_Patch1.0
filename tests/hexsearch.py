# Defina o caminho do seu arquivo e a sequência hex
file_path = "c3560-ipbasek9-mz.122-55.SE12.bin"
hex_sequence = "4AF86716ED1E2F347CA13C9978AD8CA0"

# Converte a string hex para bytes reais
search_bytes = bytes.fromhex(hex_sequence)

with open(file_path, "rb") as f:
    content = f.read()
    offset = content.find(search_bytes)

    if offset != -1:
        print(f"✅ Sequência encontrada!")
        print(f"📍 Offset Decimal: {offset}")
        print(f"📍 Offset Hexadecimal: {hex(offset).upper()}")
    else:
        print("❌ Sequência não encontrada no arquivo.")