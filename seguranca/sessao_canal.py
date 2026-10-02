import base64
from seguranca.primitivas import PrimitivasServidor


class SessaoCanalServidor:
    """Estado criptográfico do canal de uma conexão cliente↔servidor.

    Não guarda o socket — o `rede.py` é quem mantém a `conn`. Aqui só
    vivem as chaves derivadas e o flag de ativação.
    """

    def __init__(self):
        self.chave_1_aes = None
        self.chave_2_hmac = None
        self.canal_ativo = False

    def processar_handshake_inicial(self, mensagem: str) -> str:
        partes = mensagem.split("|")
        if len(partes) < 3 or partes[0] != "HANDSHAKE_INIT":
            return "ERROR|Formato de Handshake invalido"

        pub_cli_b64 = partes[1]
        salt_b64 = partes[2]
        pub_cli_bytes = base64.b64decode(pub_cli_b64)
        salt_bytes = base64.b64decode(salt_b64)
        print(f"[SRV] pub_cli = {pub_cli_bytes.hex()}")
        print(f"[SRV] salt    = {salt_bytes.hex()}")

        priv_srv, pub_srv_b64 = PrimitivasServidor.gerar_par_dhe()
        pub_srv_bytes = base64.b64decode(pub_srv_b64)
        print(f"[SRV] pub_srv = {pub_srv_bytes.hex()}")

        segredo = PrimitivasServidor.calcular_segredo_compartilhado(
            priv_srv, pub_cli_b64
        )
        print(f"[SRV] segredo = {segredo.hex()}")

        self.chave_1_aes, self.chave_2_hmac = (
            PrimitivasServidor.derivar_chaves_hkdf(segredo, salt_b64)
        )
        print(f"[SRV] aes_key = {self.chave_1_aes.hex()}")
        print(f"[SRV] mac_key = {self.chave_2_hmac.hex()}")

        self.canal_ativo = True
        return f"HANDSHAKE_RESP|{pub_srv_b64}"

    def cifrar_saida(self, texto_plano: str) -> str:
        if not self.canal_ativo:
            return texto_plano
        return PrimitivasServidor.cifrar_canal(
            self.chave_1_aes, self.chave_2_hmac, texto_plano
        )

    def decifrar_entrada(self, pacote_b64: str) -> str:
        if not self.canal_ativo:
            return pacote_b64
        return PrimitivasServidor.decifrar_canal(
            self.chave_1_aes, self.chave_2_hmac, pacote_b64
        )