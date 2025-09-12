from AES_utils import *

def main():
    print("=== Sistema de Cifragem e Decifragem AES - 128 bits ===")
    print("1 - Cifrar")
    print("2 - Decifrar")
    opcao = input("Escolha uma opção: ")

    if opcao == "1":
        print("\n--- CIFRAGEM ---")
        chave = input("Digite a chave em string ou hexadecimal: ")
        
        if chave.startswith("0x") or chave.startswith("0X"):
            chave = [int(chave[i:i+2], 16) for i in range(2, 34, 2)]
        else:
            chave = list(chave.encode())
            while len(chave) < 16:
                chave.append(0)
            chave = chave[:16]

        mensagem = input("Digite a mensagem a ser cifrada (string): ")
        
        bytes_do_texto = list(mensagem.encode())
        while len(bytes_do_texto) % 16 != 0:
            bytes_do_texto.append(0)
        blocos = [bytes_do_texto[i:i+16] for i in range(0, len(bytes_do_texto), 16)]
        
        chaves_por_rodada = expande_chave(chave)
        blocos_cifrados = []
        
        for bloco in blocos:
            estado = [bloco[i:i+4] for i in range(0, 16, 4)]
            estado = xor_com_chave(estado, chaves_por_rodada[0])
            for rodada in range(1,10):
                estado = substitui_bytes(estado)
                estado = desloca_linhas(estado)
                estado = embaralha_colunas(estado)
                estado = xor_com_chave(estado, chaves_por_rodada[rodada])
            estado = substitui_bytes(estado)
            estado = desloca_linhas(estado)
            estado = xor_com_chave(estado, chaves_por_rodada[10])
            
        blocos_cifrados.append([estado[i][j] for i in range(4) for j in range(4)])

        print("\nFormato de saída:")
        print("1 - Hexadecimal")
        print("2 - Decimal")
        saida_opcao = input("Escolha o formato da saída: ")

        if saida_opcao == "1":
            for bloco in blocos_cifrados:
                print(" ".join(f"{byte:02X}" for byte in bloco))
        else:
            for bloco in blocos_cifrados:
                print(" ".join(str(byte) for byte in bloco))

    elif opcao == "2":
        print("\n--- DECIFRAGEM ---")
        chave = input("Digite a chave (string ou hexadecimal): ")
        
        if chave.startswith("0x"):
            chave = [int(chave[i:i+2], 16) for i in range(2, 34, 2)]
        else:
            chave = list(chave.encode())
            while len(chave) < 16:
                chave.append(0)
            chave = chave[:16]
        
        mensagem_cifrada = input("Digite a mensagem cifrada decimal ou hexadecimal (espaço entre bytes -> 0x01 0x02 ...): ")
        
        bytes_cifrados = []

        for byte in mensagem_cifrada.split():
            if byte.startswith("0x") or byte.startswith("0X"):
                valor = int(byte, 16)
            else:
                valor = int(byte)
            bytes_cifrados.append(valor)
        
        
        blocos = [bytes_cifrados[i:i+16] for i in range(0, len(bytes_cifrados), 16)]
        chaves_por_rodada = expande_chave(chave)
        blocos_decifrados = []
        
        for bloco in blocos:
            estado = [bloco[i:i+4] for i in range(0, 16, 4)]
            estado = xor_com_chave(estado, chaves_por_rodada[10])
            for rodada in range(9, 0, -1):
                estado = reverte_bytes(estado)
                estado = arruma_linhas(estado)
                estado = desembaralha_colunas(estado)
                estado = xor_com_chave(estado, chaves_por_rodada[rodada])
            estado = reverte_bytes(estado)
            estado = arruma_linhas(estado)
            estado = xor_com_chave(estado, chaves_por_rodada[0])
            
            blocos_decifrados.append([estado[i][j] for i in range(4) for j in range(4)])
            
        mensagem_bytes = [byte for bloco in blocos_decifrados for byte in bloco]
        
        print("\nFormato de saída:")
        print("1 - String")
        print("2 - Hexadecimal")
        saida_opcao = input("Escolha o formato da saída: ")

        if saida_opcao == "1":
            mensagem = bytes(mensagem_bytes).decode()
            print("Mensagem decifrada (string):", mensagem)
        else:
            mensagem_hex = " ".join(f"0x{byte:02X}" for byte in mensagem_bytes)
            print("Mensagem decifrada (hexadecimal):", mensagem_hex)

    else:
        print("Opção inválida!")

if __name__ == "__main__":
    main()