import socket
import threading

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
        """Inicializa o socket TCP e entra no loop de aceite de conexões."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

        try:
            while self.executando:
                dados = conn.recv(4096)
                if not dados:
                    break

                # Encaminha os bytes/texto bruto para a camada de
                # serviço/segurança tratar
                mensagem_bruta = dados.decode("utf-8", errors="ignore")
                resposta, current_username = self.servico.processar_requisicao(
                    conn, current_username, mensagem_bruta
                )

                if resposta:
                    conn.sendall(
                        resposta.encode("utf-8")
                        if isinstance(resposta, str)
                        else resposta
                    )

        except socket.error as e:
            print(f"[ERRO SOCKET] {addr}: {e}")
        finally:
            if current_username:
                self.servico.desconectar_usuario(current_username)
            conn.close()
            print(f"[DESCONEXÃO] Cliente {addr} encerrado.")