# 🖥️ Chat E2EE — Aplicação Servidor (`servidorRedes`)

[![Python 3](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-E2EE%20%7C%20AES--256%20%7C%20Argon2-green.svg)]()
[![License](https://img.shields.io/badge/License-Academic-orange.svg)]()

> **Componente Servidor do Sistema de Chat Desktop com Criptografia Ponta a Ponta (E2EE)**  
> *Desenvolvido para a disciplina de Segurança da Informação / Redes de Computadores (Engenharia de Computação — UABJ/UFRPE)*  
> *Professor: Ygor Amaral B. L. de Sena*

---

## 📋 Sumário
- [Visão Geral](#-visão-geral)
- [Princípio de Operação Cega](#-princípio-de-operação-cega-zero-knowledge-routing)
- [Funcionalidades Principais](#-funcionalidades-principais)
- [Arquitetura em Camadas](#-arquitetura-em-camadas)
- [Primitivas Criptográficas e Segurança](#-primitivas-criptográficas-e-segurança)
- [Estrutura do Repositório](#-estrutura-do-repositório)
- [Modelo de Dados (Banco SQLite)](#-modelo-de-dados-banco-sqlite)
- [Como Executar](#-como-executar)
- [Autor](#-autor)

---

## 📄 Visão Geral

O **`servidorRedes`** é a aplicação backend responsável por intermediar toda a comunicação do sistema de chat. Ele gerencia as conexões simultâneas de clientes via **Sockets TCP**, autentica usuários, distribui chaves públicas, sinaliza estados de presença (online/offline) e "digitando", e armazena mensagens na fila offline.

A aplicação foi projetada combinando a infraestrutura multithreaded de rede do **Projeto 1** com a especificação rigorosa de segurança do **Projeto 2**, garantindo que o canal de comunicação seja autenticado e cifrado sem violar a privacidade ponta a ponta dos usuários.

---

## 🙈 Princípio de Operação Cega (*Zero-Knowledge Routing*)

A exigência central da arquitetura é a **separação entre a segurança do canal e a privacidade ponta a ponta**:
- O servidor **roteia todas as mensagens**, pois os clientes não se conectam diretamente entre si (a comunicação é sempre através do servidor socket).
- O servidor é **fundamentalmente incapaz de ler o conteúdo das mensagens**, pois o miolo do pacote trafega cifrado com chaves simétricas negociadas diretamente entre o emissor e o receptor (E2EE).
- O servidor abre apenas a **camada externa (do canal)** para identificar o destinatário, substitui essa camada pela chave do canal do destinatário e repassa o pacote fechado.

---

## 🚀 Funcionalidades Principais

* **Autenticação e Registro Seguro**:
  * Hashing de senhas com **Argon2** e *salt* exclusivo por usuário (senhas em texto puro jamais chegam ao banco).
  * Autenticação sem senha por **Desafio Digital (*Nonce* e Assinatura)** para dispositivos já autenticados.
  * Autenticação por senha em **Novos Dispositivos**, com revogação automática da chave pública anterior, notificação aos contatos e descarte de mensagens offline antigas.
* **Canal Cifrado Cliente-Servidor**:
  * Handshake **Diffie-Hellman Efêmero (DHE)** + derivação **HKDF (SHA-256)**.
  * Cifragem simétrica **AES-256** e verificação de integridade/autenticidade via **HMAC-SHA-256** (*Encrypt-then-MAC*).
  * Expiração e renovação periódica de chaves a cada **60 minutos** ou **100 mensagens** (com handshakes de renovação cifrados).
* **Distribuição de Chaves Públicas**:
  * Endpoint para fornecer a chave pública de um usuário cadastrado mediante solicitação de outro cliente.
* **Roteamento de Mensagens em Tempo Real & Offline**:
  * Encaminhamento transparente de pacotes cifrados em dupla camada.
  * Fila de mensagens offline no SQLite para entrega automática quando o destinatário se conectar.
  * Retransmissão de eventos de presença e sinalizador *"Digitando"* (`TYPING` / `TYPING_STOP`).

---

## 🏗️ Arquitetura em Camadas

Seguindo as diretrizes do projeto, o código do servidor organiza-se em três camadas bem definidas, isolando regras de negócio de primitivas de segurança e sockets:

```
                  +-------------------------------------------------------+
                  |                      DOMÍNIO                          |
                  |  Serviço: Contas, Roteamento, Presença, Fila Offline  |
                  +-------------------------------------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                     SEGURANÇA                         |
                  |  • Política: Sessão, Expiração, Handshake, Chaveiro   |
                  |  • Mecanismo (Primitivas): AES-256, HMAC, HKDF,       |
                  |    Argon2, RSA-PSS / Ed25519                          |
                  +-------------------------------------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                   INFRAESTRUTURA                      |
                  |  • Rede & Protocolo: Sockets TCP Multi-thread         |
                  |  • Persistência: SQLite (database.py / chat_server.db)|
                  +-------------------------------------------------------+
```

---

## 🔒 Primitivas Criptográficas e Segurança

| Garantia / Função | Algoritmo Utilizado | Aplicação no Servidor |
| :--- | :--- | :--- |
| **Proteção de Senhas** | **Argon2** (com *salt* individual) | Guarda o hash e o *salt* no banco SQLite |
| **Confidencialidade do Canal** | **AES-256** | Cifra o envelope externo do canal socket |
| **Acordo de Chaves** | **Diffie-Hellman Efêmero (DHE)** | Negocia o segredo inicial da sessão do canal |
| **Derivação de Chaves** | **HKDF (SHA-256)** | Gera a Chave 1 (AES) e a Chave 2 (HMAC) a partir do DHE |
| **Integridade e Autenticidade** | **HMAC-SHA-256** | Valida pacotes antes da decifragem (*Encrypt-then-MAC*) |
| **Assinatura Digital** | **RSA-PSS** ou **Ed25519** | Valida os desafios (*nonces*) na autenticação de cliente |

---

## 📂 Estrutura do Repositório

```
servidorRedes/
├── server.py              # Script principal do servidor (Sockets TCP, Threading, Handshakes)
├── database.py            # Módulo de persistência (Inicialização do SQLite e Queries)
├── chat_server.db         # Arquivo do banco de dados SQLite (gerado automaticamente)
├── README.md              # Documentação oficial da aplicação
└── requirements.txt       # Dependências de bibliotecas Python
```

---

## 🗄️ Modelo de Dados (Banco SQLite)

O banco de dados `chat_server.db` é gerenciado pelo `database.py` e contém a estrutura necessária para autenticação e fila offline:

```sql
-- Tabela de Usuários e Chaves Públicas
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    public_key TEXT NOT NULL
);

-- Tabela de Mensagens Offline (Cifradas E2EE)
CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## ⚡ Como Executar

### **Pré-requisitos**
* Python **3.10+** instalado.
* Dependências criptográficas (`argon2-cffi`, `cryptography` ou `pycryptodome`).

### **Passos:**

1. **Clonar o repositório:**
   ```bash
   git clone https://github.com/oVictorTorres/servidorRedes.git
   cd servidorRedes
   ```

2. **Instalar as dependências:**
   ```bash
   pip install argon2-cffi cryptography
   ```

3. **Inicializar o Banco de Dados (Executar apenas na primeira vez):**
   ```bash
   python database.py
   ```
   *Este comando cria a estrutura do `chat_server.db` com o schema atualizado para Argon2 e chaves públicas.*

4. **Iniciar o Servidor:**
   ```bash
   python server.py
   ```
   *O servidor ficará escutando na porta configurada (padrão: `127.0.0.1:5000`) aguardando conexões dos clientes.*

---

## 👤 Autor
* **Victor Torres** (Desenvolvimento & Arquitetura)  
* **Disciplina**: Segurança da Informação / Redes de Computadores — UABJ/UFRPE
