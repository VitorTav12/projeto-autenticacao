# 🛡️ Sistema de Autenticação Segura (MFA & LGPD)

Este projeto consiste numa aplicação web monolítica desenvolvida para demonstrar a implementação de um fluxo de autenticação altamente seguro, em total conformidade com as diretrizes da norma ISO/IEC 27001 e com a Lei Geral de Proteção de Dados (LGPD).

## 👥 Equipe de Desenvolvimento

* *Vitor Hugo Oliveira Tavares* - RGM: 11251404852
* *Igor Augusto dos Santos Pereira* - RGM: 11251403589
* *Renato Martins Lopes* - RGM: 11251405741

## 🚀 Tecnologias Utilizadas

* *Linguagem:* Python 3
* *Framework Web:* Flask (com Jinja2 para os templates)
* *Banco de Dados:* PostgreSQL (psycopg2)
* *Criptografia:* Argon2 (argon2-cffi)
* *Autenticação 2FA:* TOTP via Google Authenticator (pyotp)

## 🔐 Mecanismos de Segurança Implementados

* *Derivação de Chaves (KDF):* Substituição de algoritmos vulneráveis por *Argon2id*, garantindo resistência contra ataques de dicionário e de força bruta via GPU.
* *Múltiplo Fator de Autenticação (MFA):* Bloqueio de sessão temporária até à validação do token temporal de 6 dígitos (TOTP).
* *Proteção contra Força Bruta:* Sistema de Rate Limiting que impõe um bloqueio de 180 segundos após 3 tentativas de login falhadas.
* *Prevenção de Injeção SQL:* Utilização de queries parametrizadas em todas as transações da camada DAO.

## ⚖️ Conformidade com a LGPD

O sistema atua em conformidade com os direitos do titular, incluindo:
* *Art. 7º (Consentimento):* Registo explícito com rastreabilidade da versão do termo de privacidade no ato do registo.
* *Art. 18 (Direitos do Titular):* Painel do utilizador com funcionalidades de exportação estruturada de dados pessoais (JSON) e exclusão definitiva de conta (anonimização de logs e eliminação de identificadores).

## ⚙️ Como executar o projeto localmente

1. Clone o repositório:
   ```bash
   git clone [https://github.com/VitorTav12/projeto-autenticacao.git](https://github.com/VitorTav12/projeto-autenticacao.git)
