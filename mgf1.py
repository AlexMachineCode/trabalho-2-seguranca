"""
Módulo: mgf1.py
Implementação da Mask Generation Function 1 (MGF1) em conformidade com
o standard RFC 8017 / PKCS #1 v2.2, baseada na primitiva SHA3-256.
"""
import hashlib

def sha3_256(data: bytes) -> bytes:
    """Calcula o resumo criptográfico SHA3-256."""
    return hashlib.sha3_256(data).digest()

def mgf1(seed: bytes, mask_len: int) -> bytes:
    """Gera uma máscara de comprimento 'mask_len' a partir da semente via SHA3-256."""
    h_len = 32
    if mask_len > (1 << 32) * h_len:
        raise ValueError("Comprimento de máscara excede o limite máximo permitido pela MGF1.")
    
    mask = bytearray()
    counter = 0
    while len(mask) < mask_len:
        c = counter.to_bytes(4, byteorder="big")
        mask.extend(sha3_256(seed + c))
        counter += 1
    return bytes(mask[:mask_len])

def xor(b1: bytes, b2: bytes) -> bytes:
    """Aplica operação bitwise XOR entre duas sequências de bytes."""
    return bytes(x ^ y for x, y in zip(b1, b2))