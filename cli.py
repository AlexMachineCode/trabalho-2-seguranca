"""
Módulo: cli.py
Interface interativa e por argumentos para gerenciamento de chaves, cifragem OAEP,
assinatura digital PSS de arquivos e testes automatizados de segurança.
"""
import sys
import os
import base64
import json
import tempfile
from rsa_math import generate_keypair, export_key, load_key
from rsa_oaep import oaep_encrypt, oaep_decrypt
from rsa_pss import pss_sign, pss_verify
from signed_envelope import create_envelope, export_envelope, load_envelope, parse_envelope

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
    envelope = create_envelope(os.path.basename(arq_path), assinatura_b64)
    export_envelope(envelope, sig_path)

    print(f"\n[✓] Assinatura RSA-PSS gerada com sucesso!")
    print(f"    Assinatura salva em: {sig_path}")
    print(f"    Digest SHA3-256 e Salt aplicados.")

def menu_verificar_arquivo():
    chave_path = input("Caminho da chave pública (.json): ").strip()
    arq_path = input("Caminho do arquivo original: ").strip()
    sig_path = input("Caminho do envelope JSON de assinatura (.sig): ").strip()

    if not (os.path.exists(chave_path) and os.path.exists(arq_path) and os.path.exists(sig_path)):
        print("[!] Um ou mais arquivos informados não existem.")
        return

    pub = load_key(chave_path)
    with open(arq_path, "rb") as f:
        dados = f.read()
    try:
        envelope = load_envelope(sig_path)
    except ValueError as e:
        print(f"[!] Envelope inválido: {e}")
        return
    sig_b64 = envelope["signature"]

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
    print("\nVerificando módulo RSA com pelo menos 2048 bits:")
    assert pub["n"].bit_length() >= 2048
    assert priv["n"] == pub["n"]
    print(f"   [✓] {pub['n'].bit_length()} bits (OK)")

    msg = b"Arquivo de teste CIC0201"
    print("\nVerificando cifragem e decifragem OAEP:")
    ciphertext = oaep_encrypt(msg, pub)
    assert oaep_decrypt(ciphertext, priv) == msg
    print("   [✓] Mensagem recuperada (OK)")

    print("\nVerificando OAEP com exatamente 1 byte adulterado:")
    adulterado = bytearray(ciphertext)
    adulterado[-1] ^= 0x01
    assert sum(a != b for a, b in zip(ciphertext, adulterado)) == 1
    try:
        oaep_decrypt(bytes(adulterado), priv)
    except ValueError:
        print("   [✓] Criptograma adulterado rejeitado (OK)")
    else:
        raise AssertionError("OAEP aceitou criptograma adulterado.")

    print("\nVerificando rejeição OAEP para c_int >= n:")
    k = (pub["n"].bit_length() + 7) // 8
    for c_int in (pub["n"], pub["n"] + 1):
        try:
            oaep_decrypt(c_int.to_bytes(k, "big"), priv)
        except ValueError:
            pass
        else:
            raise AssertionError("OAEP aceitou criptograma fora do intervalo.")
    print("   [✓] Criptogramas fora do intervalo rejeitados (OK)")

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

    print("\n4. Teste (c): Alteração de 1 caractere hexadecimal do n da chave pública:")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "public.json")
        export_key(pub, key_path, "RSA-PUBLIC-KEY")
        with open(key_path, "r", encoding="utf-8") as f:
            original_json = f.read()
        data = json.loads(original_json)
        n_original = data["n"]
        data["n"] = n_original[:-1] + format(int(n_original[-1], 16) ^ 0x02, "x")
        adulterado_json = json.dumps(data, indent=4)
        assert len(original_json) == len(adulterado_json)
        assert sum(a != b for a, b in zip(original_json, adulterado_json)) == 1
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(adulterado_json)
        adulterada_pub = load_key(key_path)
    val_c = pss_verify(msg, sig, adulterada_pub)
    print(f"   Resultado: {'VÁLIDO' if val_c else 'REJEITADO (Sucesso - chave incompatível)'}")
    assert val_c is False

    print("\n5. Verificando criação, exportação e carregamento de envelope válido:")
    envelope = create_envelope("documento.txt", sig)
    with tempfile.TemporaryDirectory() as tmp:
        envelope_path = os.path.join(tmp, "documento.txt.sig")
        export_envelope(envelope, envelope_path)
        carregado = load_envelope(envelope_path)
    assert carregado == envelope
    assert pss_verify(msg, carregado["signature"], pub) is True
    print("   [✓] Envelope válido (OK)")

    print("\n6. Verificando rejeição de envelopes inválidos:")
    invalidos = ["{", "[]", "null"]
    for campo in envelope:
        invalidos.append(json.dumps({k: v for k, v in envelope.items() if k != campo}))
    for campo, valor in (
        ("version", 2), ("version", True), ("version", "1"),
        ("algorithm", "RSA-OAEP"), ("algorithm", None),
        ("filename", ""), ("filename", "   "), ("filename", 123),
        ("filename", "\x00"), ("signature", ""), ("signature", 123),
        ("signature", "%%%"), ("signature", "YQ"), ("signature", "é"),
    ):
        invalidos.append(json.dumps({**envelope, campo: valor}))
    with tempfile.TemporaryDirectory() as tmp:
        envelope_path = os.path.join(tmp, "invalido.sig")
        for invalido in invalidos:
            with open(envelope_path, "w", encoding="utf-8") as f:
                f.write(invalido)
            for carregar in (lambda: parse_envelope(invalido),
                             lambda: load_envelope(envelope_path)):
                try:
                    carregar()
                except ValueError:
                    pass
                else:
                    raise AssertionError("Envelope inválido foi aceito.")
    print(f"   [✓] {len(invalidos)} formatos inválidos rejeitados no parser e carregador (OK)")

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