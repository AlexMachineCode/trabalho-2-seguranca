"""
Módulo: rsa_oaep.py
Esquema de cifragem assimétrica probabilística RSA-OAEP (RSAES-OAEP)
com SHA3-256 e MGF1 conforme a norma RFC 8017.
"""
import secrets
from mgf1 import sha3_256, mgf1, xor

def oaep_encrypt(message: bytes, public_key: dict, label: bytes = b"") -> bytes:
    """Cifra mensagens curtas usando RSA-OAEP."""
    n, e = public_key["n"], public_key["e"]
    k = (n.bit_length() + 7) // 8
    h_len = 32

    max_msg_len = k - 2 * h_len - 2
    if len(message) > max_msg_len:
        raise ValueError(f"Mensagem excede o tamanho máximo suportado ({max_msg_len} bytes).")

    l_hash = sha3_256(label)
    ps_len = k - len(message) - 2 * h_len - 2
    db = l_hash + (b"\x00" * ps_len) + b"\x01" + message

    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = xor(db, db_mask)

    seed_mask = mgf1(masked_db, h_len)
    masked_seed = xor(seed, seed_mask)

    em = b"\x00" + masked_seed + masked_db
    m_int = int.from_bytes(em, byteorder="big")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(k, byteorder="big")

def oaep_decrypt(ciphertext: bytes, private_key: dict, label: bytes = b"") -> bytes:
    """Decifra o criptograma e valida rigorosamente o padding e integridade."""
    n, d = private_key["n"], private_key["d"]
    k = (n.bit_length() + 7) // 8
    h_len = 32

    if len(ciphertext) != k or k < 2 * h_len + 2:
        raise ValueError("Criptograma com tamanho incompatível.")

    c_int = int.from_bytes(ciphertext, byteorder="big")
    m_int = pow(c_int, d, n)
    em = m_int.to_bytes(k, byteorder="big")

    y = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    seed_mask = mgf1(masked_db, h_len)
    seed = xor(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - h_len - 1)
    db = xor(masked_db, db_mask)

    l_hash = sha3_256(label)
    l_hash_prime = db[:h_len]
    padding_and_msg = db[h_len:]

    sep_index = -1
    for i, byte in enumerate(padding_and_msg):
        if byte == 0x01:
            sep_index = i
            break
        elif byte != 0x00:
            raise ValueError("Falha de integridade: padding corrupto detectado.")

    if sep_index == -1 or y != 0x00 or l_hash != l_hash_prime:
        raise ValueError("Falha na decifragem RSA-OAEP: cabeçalho ou label inválidos.")

    return padding_and_msg[sep_index + 1 :]