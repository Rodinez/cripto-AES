from AES_utils import *

def main():
    print("=== Sistema de Cifragem e Decifragem AES - 128 bits ===")
    print("1 - Cifrar")
    print("2 - Decifrar")
    opcao = input("Escolha uma opção: ")

    if opcao == "1":
        print("\n--- CIFRAGEM ---")
        print("Formato da chave:")
        print("1 - String")
        print("2 - Hexadecimal")
        formato_chave = input("Escolha o formato: ")
        print()
        chave_input = input("Digite a chave: ")

        if formato_chave == "1":  
            chave = list(chave_input.encode()) # string -> hex
            while len(chave) < 16: 
                chave.append(0) # padding se necessário
            chave = chave[:16] # 16 bytes para a chave
        else:  
            # 16 bytes para a chave 2 a 2 dígitos no formato hexadecimal
            chave = [int(chave_input[i:i+2], 16) for i in range(0, 32, 2)] 
        
        print()
        mensagem = input("Digite a mensagem a ser cifrada (string): ")
        
        bytes_do_texto = list(mensagem.encode()) # string -> hex
        while len(bytes_do_texto) % 16 != 0: 
            bytes_do_texto.append(0)
        # blocos de 16 bytes
        blocos = [bytes_do_texto[i:i+16] for i in range(0, len(bytes_do_texto), 16)] 
                
        chaves_por_rodada = expande_chave(chave)
        blocos_cifrados = []
        
        for bloco in blocos:
            # transposta do bloco
            estado = [[bloco[linha + 4*coluna] for coluna in range(4)] for linha in range(4)] 
            # 1ª rodada da cifragem
            estado = xor_com_chave(estado, chaves_por_rodada[0]) 
            # rodadas 2 a 10 da cifragem
            for rodada in range(1,10): 
                estado = substitui_bytes(estado)
                estado = desloca_linhas(estado)
                estado = embaralha_colunas(estado)
                estado = xor_com_chave(estado, chaves_por_rodada[rodada])
            # última rodada da cifragem (11ª)
            estado = substitui_bytes(estado)
            estado = desloca_linhas(estado)
            estado = xor_com_chave(estado, chaves_por_rodada[10])
            blocos_cifrados.append([estado[i][j] for j in range(4) for i in range(4)])

        print("\nFormato de saída:")
        print("1 - Hexadecimal")
        print("2 - Decimal")
        saida_opcao = input("Escolha o formato da saída: ")
        print()

        if saida_opcao == "1":
            print("".join(f"{byte:02X}" for bloco in blocos_cifrados for byte in bloco))
        else:
            print(" ".join(str(byte) for bloco in blocos_cifrados for byte in bloco))

    elif opcao == "2":
        print("\n--- DECIFRAGEM ---")
        print("Formato da chave:")
        print("1 - String")
        print("2 - Hexadecimal")
        formato_chave = input("Escolha o formato: ")
        print()

        chave_input = input("Digite a chave: ")
        print()

        if formato_chave == "1":  
            chave = list(chave_input.encode()) # string -> hex
            while len(chave) < 16: 
                chave.append(0)  # padding se necessário
            chave = chave[:16] # 16 bytes para a chave
        else:
            # 16 bytes para a chave 2 a 2 dígitos no formato hexadecimal
            chave = [int(chave_input[i:i+2], 16) for i in range(0, 32, 2)]
        
        print("Formato da mensagem cifrada:")
        print("1 - Hexadecimal")
        print("2 - Decimal")
        formato_msg = input("Escolha o formato: ")
        print()

        mensagem_cifrada = input("Digite a mensagem cifrada: ")
        print()  
              
        bytes_cifrados = []

        if formato_msg == "1": 
            # divisão de 2 em 2 no formato hexadecimal
            bytes_cifrados = [int(mensagem_cifrada[i:i+2], 16) for i in range(0, len(mensagem_cifrada), 2)] 
        else:  
            for byte in mensagem_cifrada.split(): # formato 117 119 10 2 32 ..
                bytes_cifrados.append(int(byte))
        
        
        # blocos de 16 bytes
        blocos = [bytes_cifrados[i:i+16] for i in range(0, len(bytes_cifrados), 16)]
        chaves_por_rodada = expande_chave(chave)
        blocos_decifrados = []
        
        for bloco in blocos:
            # transposta do bloco
            estado = [[bloco[linha + 4*coluna] for coluna in range(4)] for linha in range(4)]
            # 1ª rodada da descifragem
            estado = xor_com_chave(estado, chaves_por_rodada[10])
            # rodadas 2 a 10 da descifragem
            for rodada in range(9, 0, -1):
                estado = arruma_linhas(estado)
                estado = reverte_bytes(estado)
                estado = xor_com_chave(estado, chaves_por_rodada[rodada])
                estado = desembaralha_colunas(estado)
            # última rodada da descifragem (11ª)
            estado = arruma_linhas(estado)
            estado = reverte_bytes(estado)
            estado = xor_com_chave(estado, chaves_por_rodada[0])
            
            blocos_decifrados.append([estado[i][j] for j in range(4) for i in range(4)])
            
        mensagem_bytes = [byte for bloco in blocos_decifrados for byte in bloco]
        
        print("\nFormato de saída:")
        print("1 - String")
        print("2 - Hexadecimal")
        saida_opcao = input("Escolha o formato da saída: ")
        print()

        if saida_opcao == "1":
            try:
                mensagem = bytes(mensagem_bytes).decode() # hex -> string
                print("Mensagem decifrada (string):", mensagem)
            except UnicodeDecodeError:
                print("utf-8 não conseguiu decodificar algum byte")
                mensagem_hex = "".join(f"{byte:02X}" for byte in mensagem_bytes)
                print("\nSaída em hexadecimal em compensação:", mensagem_hex)
        else:
            mensagem_hex = "".join(f"{byte:02X}" for byte in mensagem_bytes)
            print("Mensagem decifrada (hexadecimal):", mensagem_hex)

    else:
        print("Opção inválida!")

if __name__ == "__main__":
    main()