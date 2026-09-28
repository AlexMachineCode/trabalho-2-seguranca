# Sistema de Criptografia Assimétrica e Assinatura Digital RSA

Projeto desenvolvido para a disciplina de **Segurança Computacional (CIC0201)** — Universidade de Brasília (UnB).

O sistema implementa, do zero e utilizando apenas a biblioteca padrão do Python 3 (sem uso de pacotes criptográficos externos), um ecossistema completo de criptografia assimétrica e assinatura digital baseado na especificação **PKCS#1 v2.2 (RFC 8017)** com a função hash **SHA3-256**.

---

## Integrantes do Grupo

* **Alex Batista Resende** - Matrícula: `231025261`
* **Marco Aurelio Gonçalves Fonseca** - Matrícula: `221021509`
* **Thomas Jefferson** - Matrícula: `202033561`
* **Luis Henrique Bessa de Melo** - Matrícula: `232009567`

---


Para manter o código limpo, coeso e fácil de auditar, o sistema foi dividido em módulos independentes onde cada arquivo possui uma responsabilidade criptográfica bem definida:

```text
trabalho_2/
├── rsa_math.py        # Módulo 1: Matemática do RSA e Geração de Chaves
├── mgf1.py            # Módulo 2: Função Geradora de Máscara (MGF1)
├── rsa_oaep.py        # Módulo 3: Cifragem e Decifragem (RSA-OAEP)
├── rsa_pss.py         # Módulo 4: Assinatura e Verificação (RSA-PSS)
├── cli.py             # Módulo 5: Interface de Linha de Comando e Testes
├── documento.txt      # Arquivo de teste para assinatura
└── README.md          # Documentação técnica e respostas teóricas
```

## Formato das chaves

As chaves são arquivos JSON com `type` e inteiros representados por strings
hexadecimais com prefixo `0x`:

- Pública: `type="RSA-PUBLIC-KEY"`, `n` e `e`.
- Privada: `type="RSA-PRIVATE-KEY"`, `n`, `e`, `d`, `p` e `q`.

O módulo `n` gerado tem pelo menos 2048 bits e `e` é 65537 (`0x10001`).

## Formato do envelope

A opção 4 grava a assinatura em `<arquivo>.sig`, agora como JSON UTF-8 com
os quatro campos obrigatórios abaixo. A opção 5 carrega e valida esse envelope.
O conteúdo do arquivo assinado continua externo e é informado separadamente
na verificação.

```json
{
    "version": 1,
    "algorithm": "RSA-PSS-SHA3-256",
    "filename": "documento.txt",
    "signature": "<assinatura RSA-PSS codificada em Base64>"
}
```

`version` deve ser o inteiro `1`; `algorithm` deve ser exatamente
`RSA-PSS-SHA3-256`; `filename` deve ser uma string não vazia, sem caractere
nulo; `signature` deve ser uma string Base64 válida e não vazia. O texto entre
`<...>` no exemplo é um marcador e deve ser substituído pela assinatura real.
JSON inválido, campos ausentes e valores inválidos são rejeitados com
`ValueError`. O nome é informativo; a assinatura autentica os bytes do arquivo
externo, não os metadados do envelope. Arquivos `.sig` antigos contendo apenas
Base64 não são envelopes válidos.

## Execução dos testes

Na pasta do projeto, execute:

```bash
python3 -c "from cli import executar_testes_automaticos; executar_testes_automaticos()"
```

Também é possível executar `python3 cli.py` e selecionar a opção **6**.
A bateria verifica módulo `n` com pelo menos 2048 bits, OAEP normal, OAEP com
um byte adulterado, rejeição de criptogramas com inteiro maior ou igual a `n`,
PSS válido, arquivo adulterado, assinatura adulterada, chave pública com um
caractere hexadecimal de `n` adulterado, envelope válido e envelopes inválidos.
Uma falha interrompe a execução com erro; o sucesso é indicado ao final.
