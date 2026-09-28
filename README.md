cat << 'EOF' > README.md
# Sistema de Criptografia Assimétrica e Assinatura Digital RSA

Projeto desenvolvido para a disciplina de **Segurança Computacional (CIC0201)** — Universidade de Brasília (UnB).

O sistema implementa, do zero e utilizando apenas a biblioteca padrão do Python 3 (sem uso de pacotes criptográficos externos), um ecossistema completo de criptografia assimétrica e assinatura digital baseado na especificação **PKCS#1 v2.2 (RFC 8017)** com a função hash **SHA3-256**.

---

## Integrantes do Grupo

* **Alex Batista Resende** - Matrícula: `231025261`
* **Nome do Integrante 2** - Matrícula: `XX/XXXXXXX`
* **Nome do Integrante 3** - Matrícula: `XX/XXXXXXX`

---

## 🏛 Arquitetura Descentralizada e Explicação dos Arquivos

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
