import socket
import threading

from seguranca.sessao_canal import SessaoCanalServidor

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 5000


class RedeServidor:
    def __init__(self, servico_chat, host=HOST_PADRAO, port=PORTA_PADRAO):
        self.host = host
        self.port = port
        self.servico = servico_chat
        self.server_socket = None
        self.executando = False

    def iniciar(self):
        """Inicializa o socket TCP e entra no loop de aceite."""
        self.server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self.server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.executando = True
        print(f"[SERVIDOR] Escutando em {self.host}:{self.port}")

        while self.executando:
            try:
                conn, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self._tratar_cliente,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
            except socket.error:
                break

    def _tratar_cliente(self, conn, addr):
        """Thread individual para tratar a comunicação de um cliente."""
        print(f"[NOVA CONEXÃO] Cliente {addr} conectado.")
        current_username = None
        sessao = SessaoCanalServidor()

        try:
            while self.executando:
                dados = conn.recv(65536)
                if not dados:
                    break

                mensagem_bruta = dados.decode("utf-8", errors="ignore")

                # ---------- FASE 1: HANDSHAKE (texto claro) ----------
                if not sessao.canal_ativo:
                    if mensagem_bruta.startswith("HANDSHAKE_INIT"):
                        resposta = sessao.processar_handshake_inicial(
                            mensagem_bruta
                        )
                        conn.sendall(resposta.encode("utf-8"))
                        print(f"[HANDSHAKE] Canal ativo com {addr}")
                    else:
                        conn.sendall(
                            b"ERROR|Handshake obrigatorio antes de "
                            b"qualquer comando."
                        )
                    continue

                # ---------- FASE 2: CANAL ATIVO (tudo cifrado) ----------
                texto_claro = sessao.decifrar_entrada(mensagem_bruta)
                if not texto_claro:
                    print(f"[AVISO] Pacote invalido de {addr}")
                    continue

                print(f"[RECV] {addr}: {texto_claro[:80]!r}")

                resposta, current_username = (
                    self.servico.processar_requisicao(
                        conn, current_username, texto_claro, sessao
                    )
                )

                if resposta:
                    print(f"[SEND] {addr}: {resposta[:80]!r}")
                    cifrado = sessao.cifrar_saida(resposta)
                    conn.sendall(cifrado.encode("utf-8"))

        except socket.error as e:
            print(f"[ERRO SOCKET] {addr}: {e}")
        finally:
            if current_username:
                self.servico.desconectar_usuario(current_username)
            conn.close()
            print(f"[DESCONEXÃO] Cliente {addr} encerrado.")