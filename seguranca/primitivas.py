import os
import hmac
import hashlib
import base64

# ---------------------------------------------------------------------
# Primitivas nativas (Rust) — TODAS as operações criptográficas
# ---------------------------------------------------------------------
try:
    import primitivas_rust as pr

    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

# ---------------------------------------------------------------------
# Fallback Python — apenas para hash de senha
# ---------------------------------------------------------------------
try:
    import argon2

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class PrimitivasServidor:
    """Funções criptográficas de baixo nível do servidor.

    Ordem de preferência:
      1. primitivas_rust (Rust / PyO3) — TODAS as operações
      2. argon2-cffi (Python) — fallback só para senhas
      3. PBKDF2 (Python) — último recurso para senhas

    Sem cryptography. Sem fallbacks simulados. Se o Rust não estiver
    disponível, X25519 / HKDF / AES / HMAC levantam RuntimeError.
    """

    # ------------------------------------------------------------------
    # 🔑 HASHING DE SENHAS (Argon2)
    # ------------------------------------------------------------------
    @staticmethod
    def gerar_hash_senha(senha: str) -> tuple[str, str]:
        salt_bytes = os.urandom(16)
        salt_b64 = base64.b64encode(salt_bytes).decode("utf-8")

        if RUST_AVAILABLE:
            hash_str = pr.argon2_hash_password(senha, salt_bytes)
            return hash_str, salt_b64

        if ARGON2_AVAILABLE:
            ph = argon2.PasswordHasher()
            return ph.hash(senha), salt_b64

        # Fallback PBKDF2 — único fallback aceitável para senhas
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), salt_bytes, 100_000
        )
        hash_b64 = base64.b64encode(hash_bytes).decode("utf-8")
        return f"$pbkdf2${hash_b64}", salt_b64

    @staticmethod
    def verificar_senha(senha: str, hash_salvo: str, salt_b64: str) -> bool:
        if RUST_AVAILABLE and hash_salvo.startswith("$argon2"):
            return pr.argon2_verify_password(senha, hash_salvo)

        if ARGON2_AVAILABLE and hash_salvo.startswith("$argon2"):
            ph = argon2.PasswordHasher()
            try:
                return ph.verify(hash_salvo, senha)
            except Exception:
                return False

        salt_bytes = base64.b64decode(salt_b64)
        if hash_salvo.startswith("$pbkdf2$"):
            hash_esperado = hash_salvo.replace("$pbkdf2$", "")
            hash_bytes = hashlib.pbkdf2_hmac(
                "sha256", senha.encode("utf-8"), salt_bytes, 100_000
            )
            return hmac.compare_digest(
                base64.b64encode(hash_bytes).decode("utf-8"),
                hash_esperado,
            )
        return False

    # ------------------------------------------------------------------
    # 🤝 DHE X25519 (via Rust)
    # ------------------------------------------------------------------
    @staticmethod
    def gerar_par_dhe():
        """Gera um par de chaves efêmeras X25519 via Rust.

        Retorna (priv_bytes, pub_b64).
        """
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - X25519 indisponivel."
            )
        priv = os.urandom(32)
        pub = bytes(pr.x25519_public_from_private(priv))
        return priv, base64.b64encode(pub).decode("utf-8")

    @staticmethod
    def calcular_segredo_compartilhado(
        chave_privada_srv: bytes, pub_key_cliente_b64: str
    ) -> bytes:
        """Calcula o segredo compartilhado X25519 via Rust."""
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - X25519 indisponivel."
            )
        pub_cli = base64.b64decode(pub_key_cliente_b64)
        return bytes(pr.x25519_shared(chave_privada_srv, pub_cli))

    # ------------------------------------------------------------------
    # 🌱 HKDF-SHA-256 (via Rust)
    # ------------------------------------------------------------------
    @staticmethod
    def derivar_chaves_hkdf(
        segredo_compartilhado: bytes, salt_b64: str
    ) -> tuple[bytes, bytes]:
        """HKDF-SHA-256 → 32B AES + 32B HMAC, via Rust.

        A string `info` precisa ser IDÊNTICA nos dois lados:
        b"canal-cliente-servidor".
        """
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - HKDF indisponivel."
            )
        salt_bytes = base64.b64decode(salt_b64)
        okm = bytes(
            pr.hkdf_sha256(
                segredo_compartilhado,
                salt_bytes,
                b"canal-cliente-servidor",
                64,
            )
        )
        return okm[:32], okm[32:]

    # ------------------------------------------------------------------
    # 🔐 HMAC-SHA-256 (via Rust)
    # ------------------------------------------------------------------
    @staticmethod
    def calcular_hmac(chave_2: bytes, mensagem_bytes: bytes) -> str:
        if RUST_AVAILABLE:
            digest = bytes(pr.hmac_sha256_digest(chave_2, mensagem_bytes))
            return base64.b64encode(digest).decode("utf-8")

        mac = hmac.new(chave_2, mensagem_bytes, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("utf-8")

    @staticmethod
    def _verificar_hmac(
        chave_2: bytes, mensagem_bytes: bytes, mac_recebido_b64: str
    ) -> bool:
        if RUST_AVAILABLE:
            try:
                mac_bytes = base64.b64decode(mac_recebido_b64)
            except Exception:
                return False
            return pr.hmac_sha256_verify(chave_2, mensagem_bytes, mac_bytes)

        mac_calc = PrimitivasServidor.calcular_hmac(chave_2, mensagem_bytes)
        return hmac.compare_digest(mac_recebido_b64, mac_calc)

    # ------------------------------------------------------------------
    # 🔐 CANAL — AES-256-GCM + HMAC-SHA-256 (via Rust)
    # Envelope: base64(nonce[12] || ct || tag[32])
    # ------------------------------------------------------------------
    @staticmethod
    def cifrar_canal(chave_1: bytes, chave_2: bytes, texto_plano: str) -> str:
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - AES indisponivel."
            )
        dados = texto_plano.encode("utf-8")
        nonce = os.urandom(12)
        ct = bytes(pr.aes256_encrypt(chave_1, dados, nonce))
        tag = bytes(pr.hmac_sha256_digest(chave_2, nonce + ct))
        pacote = nonce + ct + tag
        return base64.b64encode(pacote).decode("utf-8")

    @staticmethod
    def decifrar_canal(
        chave_1: bytes, chave_2: bytes, pacote_b64: str
    ) -> str:
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - AES indisponivel."
            )
        try:
            pacote = base64.b64decode(pacote_b64.strip())
        except Exception:
            return ""

        # 12 (nonce) + 16 (tag GCM mínimo) + 32 (HMAC)
        if len(pacote) < 12 + 16 + 32:
            return ""

        nonce = pacote[:12]
        tag = pacote[-32:]
        ct = pacote[12:-32]

        if not pr.hmac_sha256_verify(chave_2, nonce + ct, tag):
            print("[SEGURANCA SERVIDOR] HMAC do canal invalido.")
            return ""

        try:
            pt = bytes(pr.aes256_decrypt(chave_1, ct, nonce))
            return pt.decode("utf-8")
        except Exception as e:
            print(f"[ERRO DECIFRAGEM CANAL] {e}")
            return ""

    @staticmethod
    def verificar_ed25519_b64(
        public_b64: str, message: bytes, signature_b64: str
    ) -> bool:
        """Verifica assinatura Ed25519 a partir de base64."""
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "primitivas_rust nao instalado - Ed25519 indisponivel."
            )
        pub = base64.b64decode(public_b64)
        sig = base64.b64decode(signature_b64)
        return pr.ed25519_verify(pub, message, sig)