"""
Módulo: cli.py
Interface interativa e por argumentos para gerenciamento de chaves, cifragem OAEP,
assinatura digital PSS de arquivos e testes automatizados de segurança.
"""
import sys
import os
import base64
from rsa_math import generate_keypair, export_key, load_key
from rsa_oaep import oaep_encrypt, oaep_decrypt
from rsa_pss import pss_sign, pss_verify

def menu_gerar_chaves():
    prefixo = input("Digite o prefixo para os arquivos de chave (padrão: 'minha_chave'): ").strip()
    if not prefixo:
        prefixo = "minha_chave"
    print(f"\n[*] Gerando primos e par RSA-2048 via Miller-Rabin (aguarde)...")
    pub, priv = generate_keypair(2048)
    pub_file = f"{prefixo}_public.json"
    priv_file = f"{prefixo}_private.json"
    export_key(pub, pub_file, "RSA-PUBLIC-KEY")
    export_key(priv, priv_file, "RSA-PRIVATE-KEY")
    print(f"[✓] Chave pública salva em: {pub_file}")
    print(f"[✓] Chave privada salva em: {priv_file}")

def menu_cifrar_oaep():
    chave_path = input("Caminho da chave pública (.json): ").strip()
    if not os.path.exists(chave_path):
        print("[!] Arquivo de chave não encontrado.")
        return
    pub = load_key(chave_path)
    mensagem = input("Digite a mensagem para cifrar: ").encode("utf-8")
    try:
        criptograma = oaep_encrypt(mensagem, pub)
        print(f"\n[✓] Mensagem cifrada com sucesso (RSA-OAEP)!")
        print(f"    Hexadecimal: {criptograma.hex()[:80]}... ({len(criptograma)} bytes)")
        print(f"    Base64: {base64.b64encode(criptograma).decode('ascii')}")
    except Exception as e:
        print(f"[!] Erro ao cifrar: {e}")

def menu_decifrar_oaep():
    chave_path = input("Caminho da chave privada (.json): ").strip()
    if not os.path.exists(chave_path):
        print("[!] Arquivo de chave não encontrado.")
        return
    priv = load_key(chave_path)
    ct_b64 = input("Cole o criptograma em Base64: ").strip()
    try:
        ct_bytes = base64.b64decode(ct_b64)
        decifrado = oaep_decrypt(ct_bytes, priv)
        print(f"\n[✓] Mensagem recuperada: {decifrado.decode('utf-8')}")
    except Exception as e:
        print(f"[!] Falha na decifragem (integridade violada ou chave incorreta): {e}")

def menu_assinar_arquivo():
    chave_path = input("Caminho da chave privada (.json): ").strip()
    if not os.path.exists(chave_path):
        print("[!] Arquivo de chave não encontrado.")
        return
    arq_path = input("Caminho do arquivo a ser assinado: ").strip()
    if not os.path.exists(arq_path):
        print("[!] Arquivo não encontrado.")
        return

    priv = load_key(chave_path)
    with open(arq_path, "rb") as f:
        dados = f.read()

    assinatura_b64 = pss_sign(dados, priv)
    sig_path = f"{arq_path}.sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(assinatura_b64)

    print(f"\n[✓] Assinatura RSA-PSS gerada com sucesso!")
    print(f"    Assinatura salva em: {sig_path}")
    print(f"    Digest SHA3-256 e Salt aplicados.")

def menu_verificar_arquivo():
    chave_path = input("Caminho da chave pública (.json): ").strip()
    arq_path = input("Caminho do arquivo original: ").strip()
    sig_path = input("Caminho do arquivo de assinatura (.sig): ").strip()

    if not (os.path.exists(chave_path) and os.path.exists(arq_path) and os.path.exists(sig_path)):
        print("[!] Um ou mais arquivos informados não existem.")
        return

    pub = load_key(chave_path)
    with open(arq_path, "rb") as f:
        dados = f.read()
    with open(sig_path, "r", encoding="utf-8") as f:
        sig_b64 = f.read().strip()

    valido = pss_verify(dados, sig_b64, pub)
    print("\n" + "=" * 50)
    if valido:
        print("[✓] RESULTADO: O ARQUIVO É ÍNTEGRO E A ASSINATURA É VÁLIDA!")
    else:
        print("[X] RESULTADO: ASSINATURA INVÁLIDA OU ARQUIVO ADULTERADO!")
    print("=" * 50)

def executar_testes_automaticos():
    print("\n" + "=" * 65)
    print("EXECUTANDO TESTES DE INTEGRIDADE AUTOMATIZADOS (PARTE IV)")
    print("=" * 65)

    pub, priv = generate_keypair(2048)
    msg = b"Arquivo de teste CIC0201"
    sig = pss_sign(msg, priv)

    print("\n1. Verificando arquivo e assinatura originais:")
    assert pss_verify(msg, sig, pub) is True
    print("   [✓] Válido (OK)")

    print("\n2. Teste (a): Alteração de 1 byte no arquivo:")
    msg_adulterada = bytearray(msg)
    msg_adulterada[0] ^= 0x01
    val_a = pss_verify(bytes(msg_adulterada), sig, pub)
    print(f"   Resultado: {'VÁLIDO' if val_a else 'REJEITADO (Sucesso - integridade mantida)'}")
    assert val_a is False

    print("\n3. Teste (b): Alteração de 1 byte na assinatura:")
    sig_bytes = bytearray(base64.b64decode(sig))
    sig_bytes[10] ^= 0xFF
    sig_adulterada = base64.b64encode(sig_bytes).decode("ascii")
    val_b = pss_verify(msg, sig_adulterada, pub)
    print(f"   Resultado: {'VÁLIDO' if val_b else 'REJEITADO (Sucesso - assinatura rejeitada)'}")
    assert val_b is False

    print("\n4. Teste (c): Verificação com outra chave pública:")
    outra_pub, _ = generate_keypair(2048)
    val_c = pss_verify(msg, sig, outra_pub)
    print(f"   Resultado: {'VÁLIDO' if val_c else 'REJEITADO (Sucesso - chave incompatível)'}")
    assert val_c is False

    print("\n[✓] Todos os testes passaram com sucesso!\n")

def main():
    while True:
        print("\n" + "=" * 55)
        print("SISTEMA DE CRIPTOGRAFIA E ASSINATURA DIGITAL (RSA)")
        print("=" * 55)
        print("1. Gerar novo par de chaves RSA (2048 bits)")
        print("2. Cifrar mensagem curta (RSA-OAEP)")
        print("3. Decifrar mensagem (RSA-OAEP)")
        print("4. Assinar arquivo (RSA-PSS + SHA3-256)")
        print("5. Verificar assinatura de arquivo (RSA-PSS)")
        print("6. Executar bateria de testes automatizados (Parte IV)")
        print("0. Sair")
        print("=" * 55)

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            menu_gerar_chaves()
        elif opcao == "2":
            menu_cifrar_oaep()
        elif opcao == "3":
            menu_decifrar_oaep()
        elif opcao == "4":
            menu_assinar_arquivo()
        elif opcao == "5":
            menu_verificar_arquivo()
        elif opcao == "6":
            executar_testes_automaticos()
        elif opcao == "0":
            print("Encerrando.")
            sys.exit(0)
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main()