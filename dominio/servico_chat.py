import os
import base64
from seguranca.primitivas import PrimitivasServidor
import threading
from infraestrutura.persistencia import PersistenciaDB


class ServicoChat:
    def __init__(self):
        self.db = PersistenciaDB()
        self.online_users = {}   # {username: socket_conn}
        self.sessoes = {}        # {username: SessaoCanalServidor}
        self.lock_online = threading.Lock()
        self.pending_challenges = {}

    def processar_requisicao(
        self, conn, current_username, mensagem_bruta, sessao=None
    ):
        """Processa o protocolo de mensagens e direciona as ações."""
        partes = mensagem_bruta.split("|")
        comando = partes[0]

        # 0a. LOGIN_INIT — inicia o fluxo de desafio/assinatura
        if comando == "LOGIN_INIT" and len(partes) >= 2:
            username = partes[1]
            if username not in self.db.listar_todos_usuarios():
                return "ERROR|Usuario nao encontrado.", current_username

            ed25519_pub = self.db.obter_ed25519_publica(username)
            if not ed25519_pub:
                return "FALLBACK_PASSWORD|", current_username

            nonce = os.urandom(32)
            self.pending_challenges[username] = {
                "nonce": nonce,
                "conn": conn,
            }
            nonce_b64 = base64.b64encode(nonce).decode("utf-8")
            return f"CHALLENGE|{nonce_b64}", current_username

        # 0b. LOGIN_PROOF — recebe a assinatura e valida
        elif comando == "LOGIN_PROOF" and len(partes) >= 3:
            username = partes[1]
            sig_b64 = partes[2]

            pending = self.pending_challenges.pop(username, None)
            if not pending or pending["conn"] is not conn:
                return "ERROR|Nenhum desafio pendente.", current_username

            ed25519_pub = self.db.obter_ed25519_publica(username)
            if not ed25519_pub:
                return (
                    "ERROR|Sem chave Ed25519 registrada.",
                    current_username,
                )

            if not PrimitivasServidor.verificar_ed25519_b64(
                ed25519_pub, pending["nonce"], sig_b64
            ):
                return "ERROR|Assinatura invalida.", current_username

            with self.lock_online:
                self.online_users[username] = conn
                if sessao is not None:
                    self.sessoes[username] = sessao

            self.notificar_mudanca_status(except_conn=conn)
            self._entregar_mensagens_offline(conn, username)
            return "LOGIN_OK|Autenticado por assinatura.", username

        # 1. LOGIN
        if comando == "LOGIN" and len(partes) >= 3:
            username, senha = partes[1], partes[2]
            if self.db.verificar_credenciais(username, senha):
                with self.lock_online:
                    self.online_users[username] = conn
                    if sessao is not None:
                        self.sessoes[username] = sessao
                self.notificar_mudanca_status(except_conn=conn)
                self._entregar_mensagens_offline(conn, username)
                return "LOGIN_OK|Autenticado com sucesso", username
            return "ERROR|Usuario ou senha incorretos", current_username

        # 2. REGISTER
        elif comando == "REGISTER" and len(partes) >= 3:
            username, senha = partes[1], partes[2]
            if self.db.cadastrar_usuario(username, senha):
                return (
                    "REGISTER_OK|Usuario cadastrado com sucesso",
                    current_username,
                )
            return "ERROR|Nome de usuario ja esta em uso", current_username

        # 3. GET_CONTACTS
        elif comando == "GET_CONTACTS":
            contatos = self.obter_lista_contatos_formatada()
            return f"CONTACTS_LIST|{'|'.join(contatos)}", current_username

        # 4. MESSAGE — roteamento cifrado por destinatário
        elif comando in ("MESSAGE", "MESSAGE_E2EE") and len(partes) >= 3:
            destinatario = partes[1]
            conteudo = partes[2]
            pacote = f"{comando}|{current_username}|{conteudo}"

            with self.lock_online:
                conn_dest = self.online_users.get(destinatario)
                sessao_dest = self.sessoes.get(destinatario)

            if conn_dest and sessao_dest:
                try:
                    cifrado = sessao_dest.cifrar_saida(pacote)
                    conn_dest.sendall(cifrado.encode("utf-8"))
                except Exception as e:
                    print(
                        f"[ROTEAMENTO] Falha ao enviar para "
                        f"{destinatario}: {e}"
                    )
                    self.db.salvar_mensagem_offline(
                        current_username, destinatario, conteudo
                    )
            else:
                self.db.salvar_mensagem_offline(
                    current_username, destinatario, conteudo
                )
            return None, current_username

        # 5. TYPING / TYPING_STOP
        elif comando in ("TYPING", "TYPING_STOP") and len(partes) >= 2:
            destinatario = partes[1]
            with self.lock_online:
                conn_dest = self.online_users.get(destinatario)
                sessao_dest = self.sessoes.get(destinatario)
            if conn_dest and sessao_dest:
                try:
                    pacote = f"{comando}|{current_username}"
                    cifrado = sessao_dest.cifrar_saida(pacote)
                    conn_dest.sendall(cifrado.encode("utf-8"))
                except Exception:
                    pass
            return None, current_username

        # 6. SET_PUBKEY
        elif comando == "SET_PUBKEY" and len(partes) >= 2:
            if not current_username:
                return "ERROR|Autenticacao necessaria.", current_username
            self.db.atualizar_chave_publica(current_username, partes[1])
            return None, current_username

        # 7. GET_PUBKEY
        elif comando == "GET_PUBKEY" and len(partes) >= 2:
            alvo = partes[1]
            chave_b64 = self.db.obter_chave_publica(alvo)
            if chave_b64:
                return f"PUBKEY|{alvo}|{chave_b64}", current_username
            return (
                f"ERROR|{alvo} ainda nao publicou chave publica.",
                current_username,
            )

        # 7b. SET_ED25519_PUBKEY — armazena a chave pública Ed25519
        elif comando == "SET_ED25519_PUBKEY" and len(partes) >= 2:
            if not current_username:
                return "ERROR|Autenticacao necessaria.", current_username
            self.db.atualizar_ed25519_publica(
                current_username, partes[1]
            )
            return None, current_username

        # 8. LOGOUT
        elif comando == "LOGOUT":
            if current_username:
                self.desconectar_usuario(current_username)
            return "LOGOUT_OK", None

        return "ERROR|Comando nao reconhecido", current_username

    def obter_lista_contatos_formatada(self):
        todos = self.db.listar_todos_usuarios()
        with self.lock_online:
            onlines = set(self.online_users.keys())
        return [
            f"{u}:{'online' if u in onlines else 'offline'}"
            for u in todos
        ]

    def notificar_mudanca_status(self, except_conn=None):
        """Notifica todos os clientes (cifrando por sessão)."""
        contatos = self.obter_lista_contatos_formatada()
        msg = f"CONTACTS_LIST|{'|'.join(contatos)}"

        with self.lock_online:
            itens = list(self.online_users.items())

        for user, conn in itens:
            if conn is except_conn:
                continue
            sessao = self.sessoes.get(user)
            if not sessao:
                continue
            try:
                cifrado = sessao.cifrar_saida(msg)
                conn.sendall(cifrado.encode("utf-8"))
            except Exception:
                pass

    def _entregar_mensagens_offline(self, conn, username):
        mensagens = self.db.buscar_e_limpar_mensagens_offline(username)
        sessao = self.sessoes.get(username)
        for remetente, conteudo, timestamp in mensagens:
            msg = f"MESSAGE|{remetente}|{conteudo}|{timestamp}"
            try:
                if sessao:
                    cifrado = sessao.cifrar_saida(msg)
                    conn.sendall(cifrado.encode("utf-8"))
                else:
                    conn.sendall(msg.encode("utf-8"))
            except Exception:
                pass

    def desconectar_usuario(self, username):
        with self.lock_online:
            self.online_users.pop(username, None)
            self.sessoes.pop(username, None)
        self.pending_challenges.pop(username, None)
        self.notificar_mudanca_status()