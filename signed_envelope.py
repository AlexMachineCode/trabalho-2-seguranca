"""Envelope JSON para assinatura RSA-PSS de um arquivo externo."""
import base64
import binascii
import json


def validate_envelope(envelope: dict) -> dict:
    """Valida os campos obrigatórios e retorna o envelope ou lança ValueError."""
    required = {"version", "algorithm", "filename", "signature"}
    if not isinstance(envelope, dict) or not required.issubset(envelope):
        raise ValueError("Envelope deve ser um objeto com todos os campos obrigatórios.")
    if type(envelope["version"]) is not int or envelope["version"] != 1:
        raise ValueError("Versão de envelope inválida.")
    if envelope["algorithm"] != "RSA-PSS-SHA3-256":
        raise ValueError("Algoritmo de envelope inválido.")
    filename = envelope["filename"]
    if not isinstance(filename, str) or not filename.strip() or "\x00" in filename:
        raise ValueError("Nome de arquivo inválido.")
    signature = envelope["signature"]
    if not isinstance(signature, str) or not signature:
        raise ValueError("Assinatura deve ser uma string Base64 não vazia.")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Assinatura Base64 inválida.") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != signature:
        raise ValueError("Assinatura Base64 inválida.")
    return envelope


def create_envelope(filename: str, signature: str) -> dict:
    """Cria um envelope validado sem incluir o conteúdo do arquivo."""
    return validate_envelope({
        "version": 1,
        "algorithm": "RSA-PSS-SHA3-256",
        "filename": filename,
        "signature": signature,
    })


def export_envelope(envelope: dict, filename: str):
    """Valida e grava o envelope em JSON UTF-8."""
    validate_envelope(envelope)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=4, ensure_ascii=False)


def parse_envelope(data: str) -> dict:
    """Interpreta JSON e rejeita envelopes com formato inválido."""
    try:
        envelope = json.loads(data)
    except (TypeError, ValueError) as exc:
        raise ValueError("JSON de envelope inválido.") from exc
    return validate_envelope(envelope)


def load_envelope(filename: str) -> dict:
    """Carrega e valida um envelope JSON UTF-8."""
    with open(filename, "r", encoding="utf-8") as f:
        return parse_envelope(f.read())
