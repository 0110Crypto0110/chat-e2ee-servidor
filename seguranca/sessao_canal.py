#import os
import base64

import primitivas_rust as prim


class SessaoCanalCliente:
    """Handshake DHE + derivação HKDF + cifragem do canal cliente↔servidor.

    Deriva duas chaves de 32 bytes a partir do segredo X25519:
      - Chave 1 (AES-256-GCM)  → primeira metade do HKDF
      - Chave 2 (HMAC-SHA-256) → segunda metade do HKDF
    """

    def __init__(self):
        self.chave_1_aes = None
        self.chave_2_hmac = None
        self.canal_ativo = False
        self._priv_dhe = None
        self._salt = None

    # ------------------------------------------------------------------
    # HANDSHAKE
    # ------------------------------------------------------------------
    def gerar_handshake_init(self) -> str:
        """Gera 'HANDSHAKE_INIT|pub_dhe_b64|salt_b64'."""
        self._priv_dhe = os.urandom(32)
        pub = bytes(prim.x25519_public_from_private(self._priv_dhe))
        self._salt = os.urandom(16)
        pub_b64 = base64.b64encode(pub).decode("utf-8")
        salt_b64 = base64.b64encode(self._salt).decode("utf-8")
        return f"HANDSHAKE_INIT|{pub_b64}|{salt_b64}"

    def processar_handshake_resp(self, mensagem: str) -> bool:
        """Recebe 'HANDSHAKE_RESP|pub_dhe_srv_b64' e deriva as chaves."""
        partes = mensagem.split("|")
        if len(partes) < 2 or partes[0] != "HANDSHAKE_RESP":
            return False
        try:
            pub_srv = base64.b64decode(partes[1])
            segredo = bytes(prim.x25519_shared(self._priv_dhe, pub_srv))
            okm = bytes(
                prim.hkdf_sha256(
                    segredo,
                    self._salt,
                    b"canal-cliente-servidor",
                    64,
                )
            )
        except Exception as e:
            print(f"[HANDSHAKE] Erro ao derivar chaves: {e}")
            return False

        self.chave_1_aes = okm[:32]
        self.chave_2_hmac = okm[32:]
        self.canal_ativo = True
        return True

    # ------------------------------------------------------------------
    # CIFRAGEM DO CANAL (Encrypt-then-MAC)
    # ------------------------------------------------------------------
    def cifrar_saida(self, texto_plano: str) -> str:
        """Cifra com AES-256-GCM e adiciona HMAC. Retorna base64."""
        if not self.canal_ativo:
            return texto_plano

        dados = texto_plano.encode("utf-8")
        nonce = os.urandom(12)
        ct = bytes(prim.aes256_encrypt(self.chave_1_aes, dados, nonce))
        tag = bytes(prim.hmac_sha256(self.chave_2_hmac, nonce + ct))
        pacote = nonce + ct + tag
        return base64.b64encode(pacote).decode("utf-8")

    def decifrar_entrada(self, pacote_b64: str) -> str:
        """Valida HMAC e decifra o pacote. Retorna texto claro ou ''."""
        if not self.canal_ativo:
            return pacote_b64

        try:
            pacote = base64.b64decode(pacote_b64.strip())
        except Exception:
            return ""

        if len(pacote) < 12 + 16 + 32:
            return ""

        nonce = pacote[:12]
        tag = pacote[-32:]
        ct = pacote[12:-32]

        if not prim.hmac_sha256_verify(self.chave_2_hmac, nonce + ct, tag):
            print("[CANAL] HMAC inválido — pacote rejeitado.")
            return ""

        try:
            pt = bytes(prim.aes256_decrypt(self.chave_1_aes, ct, nonce))
            return pt.decode("utf-8")
        except Exception as e:
            print(f"[CANAL] Falha ao decifrar: {e}")
            return ""