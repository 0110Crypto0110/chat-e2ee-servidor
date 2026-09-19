import sqlite3
import threading
from datetime import datetime

from seguranca.primitivas import PrimitivasServidor

DB_NAME = "chat_server.db"


class PersistenciaDB:
    def __init__(self, db_name=DB_NAME):
        self.db_name = db_name
        self.lock = threading.Lock()
        self._criar_tabelas_iniciais()

    def _get_connection(self):
        return sqlite3.connect(self.db_name)

    def _criar_tabelas_iniciais(self):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Tabela de usuários
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    salt TEXT,
                    public_key TEXT
                )
                """
            )

            # Tabela de mensagens offline
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.commit()
            conn.close()

    # ------------------------------------------------------------------
    # 👤 USUÁRIOS (com Argon2)
    # ------------------------------------------------------------------
    def cadastrar_usuario(
        self, username, password, salt=None, public_key=None
    ) -> bool:
        """Cadastra um usuário aplicando hash Argon2 na senha.

        O parâmetro `salt` é aceito por compatibilidade com a assinatura
        antiga, mas é ignorado — o salt é gerado internamente junto com o
        hash Argon2 e persistido na coluna `salt`.
        """
        # Gera hash + salt Argon2
        hash_str, salt_b64 = PrimitivasServidor.gerar_hash_senha(password)

        with self.lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users "
                    "(username, password, salt, public_key) "
                    "VALUES (?, ?, ?, ?)",
                    (username, hash_str, salt_b64, public_key),
                )
                conn.commit()
                conn.close()
                return True
            except sqlite3.IntegrityError:
                return False

    def verificar_credenciais(self, username, password) -> bool:
        """Verifica a senha contra o hash Argon2 armazenado no banco."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password, salt FROM users WHERE username=?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()

        if not row:
            return False

        hash_salvo, salt_b64 = row[0], row[1]
        if not hash_salvo:
            return False

        return PrimitivasServidor.verificar_senha(
            password, hash_salvo, salt_b64
        )

    def listar_todos_usuarios(self) -> list:
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users")
            usuarios = [r[0] for r in cursor.fetchall()]
            conn.close()
            return usuarios

    # ------------------------------------------------------------------
    # 💾 MENSAGENS OFFLINE
    # ------------------------------------------------------------------
    def salvar_mensagem_offline(self, sender, receiver, message):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO offline_messages "
                "(sender, receiver, message, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (sender, receiver, message, timestamp),
            )
            conn.commit()
            conn.close()

    def buscar_e_limpar_mensagens_offline(self, receiver) -> list:
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sender, message, timestamp FROM offline_messages "
                "WHERE receiver=?",
                (receiver,),
            )
            mensagens = cursor.fetchall()
            cursor.execute(
                "DELETE FROM offline_messages WHERE receiver=?",
                (receiver,),
            )
            conn.commit()
            conn.close()
            return mensagens

    # ------------------------------------------------------------------
    # 🔑 CHAVES PÚBLICAS (E2EE)
    # ------------------------------------------------------------------
    def atualizar_chave_publica(self, username, public_key):
        """Armazena a chave pública X25519 (base64) do usuário."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET public_key=? WHERE username=?",
                (public_key, username),
            )
            conn.commit()
            conn.close()

    def obter_chave_publica(self, username):
        """Devolve a chave pública X25519 (base64) do usuário, ou None."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT public_key FROM users WHERE username=?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()
            return row[0] if row and row[0] else None