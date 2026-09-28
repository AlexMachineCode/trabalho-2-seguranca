"""
Módulo: rsa_math.py
Implementa a aritmética fundamental para RSA: Miller-Rabin, Euclides Estendido
e geração/serialização de chaves de 2048 bits sem bibliotecas externas proibidas.
"""
import json
import secrets

def extended_gcd(a: int, b: int):
    """Retorna (gcd, x, y) tal que a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e: int, phi: int) -> int:
    """Calcula o inverso modular d * e ≡ 1 mod phi."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Inverso modular inexistente.")
    return (x % phi + phi) % phi

def is_prime_miller_rabin(n: int, rounds: int = 40) -> bool:
    """Teste de primalidade probabilístico de Miller-Rabin (40 iterações)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Gera um primo ímpar com a dimensão em bits especificada."""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate, rounds=40):
            return candidate

def generate_keypair(bits: int = 2048):
    """Gera par de chaves RSA pública e privada (módulo >= 2048 bits)."""
    if bits < 2048:
        raise ValueError("O módulo RSA deve ter pelo menos 2048 bits.")
    half_bits = bits // 2
    e = 65537
    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p != q:
            n = p * q
            if n.bit_length() < 2048:
                continue
            phi = (p - 1) * (q - 1)
            gcd, _, _ = extended_gcd(e, phi)
            if gcd == 1:
                break
    d = mod_inverse(e, phi)
    public_key = {"n": n, "e": e}
    private_key = {"n": n, "e": e, "d": d, "p": p, "q": q}
    return public_key, private_key

def export_key(key: dict, filename: str, key_type: str):
    """Grava chaves estruturadas em JSON com valores em hexadecimal."""
    data = {"type": key_type}
    for k, v in key.items():
        data[k] = hex(v)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_key(filename: str) -> dict:
    """Carrega chave pública ou privada a partir de JSON."""
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: int(v, 16) for k, v in data.items() if k != "type"}