import threading
from infraestrutura.persistencia import PersistenciaDB


class ServicoChat:
    def __init__(self):
        self.db = PersistenciaDB()
        self.online_users = {}  # {username: socket_conn}
        self.lock_online = threading.Lock()

    def processar_requisicao(self, conn, current_username, mensagem_bruta):
        """Processa o protocolo de mensagens e direciona as ações."""
        partes = mensagem_bruta.split("|")
        comando = partes[0]

        # 1. LOGIN
        if comando == "LOGIN" and len(partes) >= 3:
            username, senha = partes[1], partes[2]
            if self.db.verificar_credenciais(username, senha):
                with self.lock_online:
                    self.online_users[username] = conn
                # Notifica os OUTROS clientes (não este). O recém-logado
                # vai pedir a lista por conta própria via GET_CONTACTS.
                self.notificar_mudanca_status(except_conn=conn)
                # Entrega fila offline
                self._entregar_mensagens_offline(conn, username)
                return "LOGIN_OK|Autenticado com sucesso", username
            return "ERROR|Usuário ou senha incorretos", current_username

        # 2. REGISTER
        elif comando == "REGISTER" and len(partes) >= 3:
            username, senha = partes[1], partes[2]
            if self.db.cadastrar_usuario(username, senha):
                return (
                    "REGISTER_OK|Usuário cadastrado com sucesso",
                    current_username,
                )
            return "ERROR|Nome de usuário já está em uso", current_username

        # 3. GET_CONTACTS
        elif comando == "GET_CONTACTS":
            contatos = self.obter_lista_contatos_formatada()
            return f"CONTACTS_LIST|{'|'.join(contatos)}", current_username

        # 4. MESSAGE (Roteamento entre clientes)
        elif comando in ("MESSAGE", "MESSAGE_E2EE") and len(partes) >= 3:
            destinatario = partes[1]
            conteudo = partes[2]
            pacote_encaminhar = f"{comando}|{current_username}|{conteudo}"

            with self.lock_online:
                conn_destinatario = self.online_users.get(destinatario)

            if conn_destinatario:
                # Destinatário online: envia diretamente
                try:
                    conn_destinatario.sendall(
                        pacote_encaminhar.encode("utf-8")
                    )
                except Exception:
                    self.db.salvar_mensagem_offline(
                        current_username, destinatario, conteudo
                    )
            else:
                # Destinatário offline: salva na fila de persistência
                self.db.salvar_mensagem_offline(
                    current_username, destinatario, conteudo
                )

            return None, current_username

        # 5. TYPING / TYPING_STOP
        elif comando in ("TYPING", "TYPING_STOP") and len(partes) >= 2:
            destinatario = partes[1]
            with self.lock_online:
                conn_destinatario = self.online_users.get(destinatario)
            if conn_destinatario:
                try:
                    conn_destinatario.sendall(
                        f"{comando}|{current_username}".encode("utf-8")
                    )
                except Exception:
                    pass
            return None, current_username

        # 6. SET_PUBKEY — armazena a chave pública X25519 do usuário logado
        elif comando == "SET_PUBKEY" and len(partes) >= 2:
            if not current_username:
                return (
                    "ERROR|É necessário estar autenticado.",
                    current_username,
                )
            chave_b64 = partes[1]
            self.db.atualizar_chave_publica(current_username, chave_b64)
            return None, current_username

        # 7. GET_PUBKEY — devolve a chave pública X25519 de um usuário
        elif comando == "GET_PUBKEY" and len(partes) >= 2:
            alvo = partes[1]
            print(f"[DEBUG SERV] GET_PUBKEY de {current_username} para {alvo}")
            chave_b64 = self.db.obter_chave_publica(alvo)
            print(f"[DEBUG SERV] Chave achada? {bool(chave_b64)}")
            if chave_b64:
                return f"PUBKEY|{alvo}|{chave_b64}", current_username

        # 8. LOGOUT
        elif comando == "LOGOUT":
            if current_username:
                self.desconectar_usuario(current_username)
            return "LOGOUT_OK", None

        return "ERROR|Comando não reconhecido", current_username

    def obter_lista_contatos_formatada(self):
        todos_usuarios = self.db.listar_todos_usuarios()
        with self.lock_online:
            onlines = set(self.online_users.keys())

        lista = []
        for user in todos_usuarios:
            status = "online" if user in onlines else "offline"
            lista.append(f"{user}:{status}")
        return lista

    def notificar_mudanca_status(self, except_conn=None):
        """Notifica todos os clientes sobre atualização da lista de contatos.

        O parâmetro except_conn permite excluir uma conexão específica do
        broadcast (ex.: o cliente que acabou de logar, que receberá a lista
        por resposta direta ao seu próprio GET_CONTACTS).
        """
        contatos = self.obter_lista_contatos_formatada()
        msg = f"CONTACTS_LIST|{'|'.join(contatos)}".encode("utf-8")

        with self.lock_online:
            for conn in list(self.online_users.values()):
                if conn is except_conn:
                    continue
                try:
                    conn.sendall(msg)
                except Exception:
                    pass

    def _entregar_mensagens_offline(self, conn, username):
        mensagens = self.db.buscar_e_limpar_mensagens_offline(username)
        for remetente, conteudo, timestamp in mensagens:
            msg = f"MESSAGE|{remetente}|{conteudo}|{timestamp}".encode("utf-8")
            try:
                conn.sendall(msg)
            except Exception:
                pass

    def desconectar_usuario(self, username):
        with self.lock_online:
            if username in self.online_users:
                del self.online_users[username]
        self.notificar_mudanca_status()