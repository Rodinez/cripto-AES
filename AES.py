from AES_utils import *

def main():
    print("=== Sistema de Cifragem e Decifragem AES - 128 bits ===")
    print("1 - Cifrar")
    print("2 - Decifrar")
    opcao = input("Escolha uma opção: ")

    if opcao == "1":
        print("\n--- CIFRAGEM ---")
        chave = input("Digite a chave em string ou hexadecimal (começando com 0x): ")
        
        if chave.startswith("0x"):
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
                print(" ".join(f"{b:02X}" for b in bloco))
        else:
            for bloco in blocos_cifrados:
                print(" ".join(str(b) for b in bloco))

    elif opcao == "2":
        print("\n--- DECIFRAGEM ---")
        chave = input("Digite a chave (string ou hexadecimal): ")
        mensagem_cifrada = input("Digite a mensagem cifrada (decimal ou hexadecimal): ")

        print("\nFormato de saída:")
        print("1 - String")
        print("2 - Hexadecimal")
        saida_opcao = input("Escolha o formato da saída: ")

        if saida_opcao == "1":
            print("Mensagem decifrada (string): result")
        else:
            print("Mensagem decifrada (hexadecimal): result")

    else:
        print("Opção inválida!")

if __name__ == "__main__":
    main()