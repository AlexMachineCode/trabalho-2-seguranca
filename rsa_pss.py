"""
Módulo: rsa_pss.py
Esquema de Assinatura Probabilística RSA-PSS (RSASSA-PSS) com SHA3-256,
salt dinâmico e representação em Base64.
"""
import base64
import secrets
from mgf1 import sha3_256, mgf1, xor

def pss_sign(message: bytes, private_key: dict, s_len: int = 32) -> str:
    """Assina um conjunto de bytes com RSA-PSS e codifica em Base64."""
    n, d = private_key["n"], private_key["d"]
    mod_bits = n.bit_length()
    embits = mod_bits - 1
    em_len = (embits + 7) // 8
    h_len = 32

    m_hash = sha3_256(message)
    if em_len < h_len + s_len + 2:
        raise ValueError("Tamanho de módulo insuficiente para a assinatura PSS.")

    salt = secrets.token_bytes(s_len)
    m_prime = (b"\x00" * 8) + m_hash + salt
    h = sha3_256(m_prime)

    ps_len = em_len - s_len - h_len - 2
    db = (b"\x00" * ps_len) + b"\x01" + salt

    db_mask = mgf1(h, em_len - h_len - 1)
    masked_db = bytearray(xor(db, db_mask))

    zero_bits = 8 * em_len - embits
    if zero_bits > 0:
        masked_db[0] &= (0xFF >> zero_bits)

    em = bytes(masked_db) + h + b"\xbc"
    m_int = int.from_bytes(em, byteorder="big")
    s_int = pow(m_int, d, n)
    
    k = (mod_bits + 7) // 8
    signature_bytes = s_int.to_bytes(k, byteorder="big")
    return base64.b64encode(signature_bytes).decode("ascii")

def pss_verify(message: bytes, signature_b64: str, public_key: dict, s_len: int = 32) -> bool:
    """Verifica a integridade e autenticidade da assinatura digital RSA-PSS."""
    try:
        signature_bytes = base64.b64decode(signature_b64)
        n, e = public_key["n"], public_key["e"]
        mod_bits = n.bit_length()
        embits = mod_bits - 1
        em_len = (embits + 7) // 8
        h_len = 32
        k = (mod_bits + 7) // 8

        if len(signature_bytes) != k:
            return False

        s_int = int.from_bytes(signature_bytes, byteorder="big")
        if s_int >= n:
            return False

        m_int = pow(s_int, e, n)
        em = m_int.to_bytes(em_len, byteorder="big")

        if em[-1] != 0xBC:
            return False

        masked_db = em[: em_len - h_len - 1]
        h = em[em_len - h_len - 1 : -1]

        zero_bits = 8 * em_len - embits
        if zero_bits > 0 and (masked_db[0] & (0xFF << (8 - zero_bits))) != 0:
            return False

        db_mask = mgf1(h, em_len - h_len - 1)
        db = bytearray(xor(masked_db, db_mask))
        if zero_bits > 0:
            db[0] &= (0xFF >> zero_bits)

        ps_len = em_len - h_len - s_len - 2
        for b in db[:ps_len]:
            if b != 0x00:
                return False
        if db[ps_len] != 0x01:
            return False

        salt = bytes(db[-s_len:])
        m_hash = sha3_256(message)
        m_prime = (b"\x00" * 8) + m_hash + salt
        h_prime = sha3_256(m_prime)

        return h == h_prime
    except Exception:
        return False