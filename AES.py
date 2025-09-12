from AES_utils import *

def main():
    print("=== Sistema de Cifragem e Decifragem AES - 128 bits ===")
    print("1 - Cifrar")
    print("2 - Decifrar")
    opcao = input("Escolha uma opção: ")

    if opcao == "1":
        print("\n--- CIFRAGEM ---")
        chave = input("Digite a chave (string ou hexadecimal): ")
        
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
        
        

        print("\nFormato de saída:")
        print("1 - Hexadecimal")
        print("2 - Decimal")
        saida_opcao = input("Escolha o formato da saída: ")

        if saida_opcao == "1":
            print("Mensagem cifrada (hexadecimal): result")
        else:
            print("Mensagem cifrada (decimal): result")

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