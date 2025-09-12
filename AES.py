from AES_utils import *

def main():
    print("=== Sistema de Cifragem e Decifragem AES - 128 bits ===")
    print("1 - Cifrar")
    print("2 - Decifrar")
    opcao = input("Escolha uma opção: ")

    if opcao == "1":
        print("\n--- CIFRAGEM ---")
        chave = input("Digite a chave (string ou hexadecimal): ")
        if not chave.startswith("0x"):
            chave = "0x" + chave.encode().hex()

        mensagem = input("Digite a mensagem a ser cifrada (string): ")

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