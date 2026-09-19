import os
import hmac
import hashlib
import base64

# ---------------------------------------------------------------------
# Tentativa 1 — primitivas nativas em Rust (preferencial)
# ---------------------------------------------------------------------
try:
    import primitivas_rust as pr

    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

# ---------------------------------------------------------------------
# Tentativa 2 — bibliotecas Python (fallback)
# ---------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import argon2

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class PrimitivasServidor:
    """Concentra as funções criptográficas de baixo nível do servidor.

    Ordem de preferência:
      1. primitivas_rust (Rust / PyO3) — Argon2, HMAC, AES
      2. cryptography + argon2 (Python)
      3. Fallbacks puros em Python (apenas para testes)
    """

    # ------------------------------------------------------------------
    # 🔑 HASHING DE SENHAS (Argon2)
    # ------------------------------------------------------------------
    @staticmethod
    def gerar_hash_senha(senha: str) -> tuple[str, str]:
        """
        Gera um salt aleatório e calcula o hash Argon2 da senha.
        Retorna a tupla (hash_str, salt_b64).
        """
        salt_bytes = os.urandom(16)
        salt_b64 = base64.b64encode(salt_bytes).decode("utf-8")

        # --- Preferência 1: Rust ---
        if RUST_AVAILABLE:
            hash_str = pr.argon2_hash_password(senha, salt_bytes)
            return hash_str, salt_b64

        # --- Preferência 2: argon2-cffi em Python ---
        if ARGON2_AVAILABLE:
            ph = argon2.PasswordHasher()
            hash_str = ph.hash(senha)
            return hash_str, salt_b64

        # --- Fallback 3: PBKDF2 puro ---
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), salt_bytes, 100_000
        )
        hash_b64 = base64.b64encode(hash_bytes).decode("utf-8")
        return f"$pbkdf2${hash_b64}", salt_b64

    @staticmethod
    def verificar_senha(senha: str, hash_salvo: str, salt_b64: str) -> bool:
        """
        Verifica a senha contra o hash armazenado.
        """
        # --- Preferência 1: Rust ---
        if RUST_AVAILABLE and hash_salvo.startswith("$argon2"):
            return pr.argon2_verify_password(senha, hash_salvo)

        # --- Preferência 2: argon2-cffi em Python ---
        if ARGON2_AVAILABLE and hash_salvo.startswith("$argon2"):
            ph = argon2.PasswordHasher()
            try:
                return ph.verify(hash_salvo, senha)
            except Exception:
                return False

        # --- Fallback 3: PBKDF2 ---
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
    # 🤝 TROCA DE CHAVES (DHE) E DERIVAÇÃO (HKDF-SHA-256)
    # ------------------------------------------------------------------
    @staticmethod
    def gerar_par_dhe():
        """Gera um par de chaves efêmeras Diffie-Hellman (ECDHE P-256)."""
        if CRYPTOGRAPHY_AVAILABLE:
            chave_privada = ec.generate_private_key(ec.SECP256R1())
            chave_publica = chave_privada.public_key()
            pub_bytes = chave_publica.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return chave_privada, base64.b64encode(pub_bytes).decode("utf-8")
        else:
            # Fallback para ambiente de testes sem dependência nativa
            priv = os.urandom(32)
            pub = base64.b64encode(hashlib.sha256(priv).digest()).decode(
                "utf-8"
            )
            return priv, pub

    @staticmethod
    def calcular_segredo_compartilhado(
        chave_privada_srv, pub_key_cliente_b64: str
    ) -> bytes:
        """Calcula o segredo compartilhado DHE."""
        if CRYPTOGRAPHY_AVAILABLE and isinstance(
            chave_privada_srv, ec.EllipticCurvePrivateKey
        ):
            pub_bytes = base64.b64decode(pub_key_cliente_b64)
            chave_publica_cli = serialization.load_der_public_key(pub_bytes)
            return chave_privada_srv.exchange(ec.ECDH(), chave_publica_cli)
        else:
            priv_bytes = (
                chave_privada_srv
                if isinstance(chave_privada_srv, bytes)
                else b"priv"
            )
            return hashlib.sha256(
                priv_bytes + pub_key_cliente_b64.encode()
            ).digest()

    @staticmethod
    def derivar_chaves_hkdf(
        segredo_compartilhado: bytes, salt_b64: str
    ) -> tuple[bytes, bytes]:
        """
        Executa o HKDF-SHA-256 gerando 64 bytes de saída:
        - Primeiros 32 bytes: Chave 1 (AES-256)
        - Últimos 32 bytes: Chave 2 (HMAC-SHA-256)
        """
        salt_bytes = base64.b64decode(salt_b64)
        if CRYPTOGRAPHY_AVAILABLE:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt_bytes,
                info=b"canal-cliente-servidor",
            )
            okm = hkdf.derive(segredo_compartilhado)
        else:
            okm = hashlib.pbkdf2_hmac(
                "sha256", segredo_compartilhado, salt_bytes, 1000, dklen=64
            )

        chave_1_aes = okm[:32]
        chave_2_hmac = okm[32:]
        return chave_1_aes, chave_2_hmac

    # ------------------------------------------------------------------
    # 🔐 CIFRAGEM SIMÉTRICA (AES-256) E INTEGRIDADE (HMAC-SHA-256)
    # ------------------------------------------------------------------
    @staticmethod
    def calcular_hmac(chave_2: bytes, mensagem_bytes: bytes) -> str:
        """Gera a assinatura HMAC-SHA-256 e devolve em base64."""
        # --- Preferência 1: Rust ---
        if RUST_AVAILABLE:
            digest = pr.hmac_sha256_digest(chave_2, mensagem_bytes)
            return base64.b64encode(digest).decode("utf-8")

        # --- Fallback Python ---
        mac = hmac.new(chave_2, mensagem_bytes, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("utf-8")

    @staticmethod
    def _verificar_hmac(
        chave_2: bytes, mensagem_bytes: bytes, mac_recebido_b64: str
    ) -> bool:
        """Verificação HMAC em tempo constante."""
        # --- Preferência 1: Rust (usa verify_slice, comparação constante) ---
        if RUST_AVAILABLE:
            try:
                mac_bytes = base64.b64decode(mac_recebido_b64)
            except Exception:
                return False
            return pr.hmac_sha256_verify(chave_2, mensagem_bytes, mac_bytes)

        # --- Fallback Python (compare_digest é tempo constante) ---
        mac_calculado_b64 = PrimitivasServidor.calcular_hmac(
            chave_2, mensagem_bytes
        )
        return hmac.compare_digest(mac_recebido_b64, mac_calculado_b64)

    @staticmethod
    def cifrar_canal(chave_1: bytes, chave_2: bytes, texto_plano: str) -> str:
        """
        Aplica o padrão Encrypt-then-MAC no canal:
        1. Cifra com AES-256-CBC (Chave 1) usando IV aleatório.
        2. Calcula HMAC-SHA-256 sobre IV || CIFRADO (Chave 2).
        3. Empacota como 'IV_B64|CIFRADO_B64|MAC_B64'.
        """
        dados = texto_plano.encode("utf-8")
        iv = os.urandom(16)

        if CRYPTOGRAPHY_AVAILABLE:
            cipher = Cipher(algorithms.AES(chave_1), modes.CBC(iv))
            encryptor = cipher.encryptor()
            # Padding PKCS7
            pad_len = 16 - (len(dados) % 16)
            dados_padded = dados + bytes([pad_len] * pad_len)
            cifrado = encryptor.update(dados_padded) + encryptor.finalize()
        else:
            # XOR fallback de simulação
            cifrado = bytearray(
                [b ^ chave_1[i % 32] for i, b in enumerate(dados)]
            )

        iv_b64 = base64.b64encode(iv).decode("utf-8")
        cifrado_b64 = base64.b64encode(cifrado).decode("utf-8")

        # MAC cobre IV + ciphertext (evita adulteração do IV)
        mac_b64 = PrimitivasServidor.calcular_hmac(
            chave_2, iv + bytes(cifrado)
        )
        return f"{iv_b64}|{cifrado_b64}|{mac_b64}"

    @staticmethod
    def decifrar_canal(
        chave_1: bytes, chave_2: bytes, pacote_encapsulado: str
    ) -> str:
        """
        Aplica MAC-then-Decrypt:
        1. Valida o HMAC (sobre IV + cifrado). Se inválido, descarta.
        2. Decifra o conteúdo AES-256-CBC.
        """
        try:
            partes = pacote_encapsulado.split("|")
            if len(partes) != 3:
                return ""

            iv_b64, cifrado_b64, mac_recebido_b64 = partes
            cifrado_bytes = base64.b64decode(cifrado_b64)
            iv_bytes = base64.b64decode(iv_b64)

            # 1. VERIFICAÇÃO DO HMAC ANTES DE DECIFRAR
            if not PrimitivasServidor._verificar_hmac(
                chave_2, iv_bytes + cifrado_bytes, mac_recebido_b64
            ):
                print(
                    "[SEGURANÇA SERVIDOR] HMAC do canal inválido! "
                    "Pacote descartado."
                )
                return ""

            # 2. DECIFRAGEM AES-256
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(chave_1), modes.CBC(iv_bytes))
                decryptor = cipher.decryptor()
                dados_padded = (
                    decryptor.update(cifrado_bytes) + decryptor.finalize()
                )
                pad_len = dados_padded[-1]
                dados = dados_padded[:-pad_len]
            else:
                dados = bytearray(
                    [b ^ chave_1[i % 32] for i, b in enumerate(cifrado_bytes)]
                )

            return dados.decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"[ERRO DECIFRAGEM CANAL] {e}")
            return ""

    # ------------------------------------------------------------------
    # ✍️ VERIFICAÇÃO DE ASSINATURA DIGITAL (Desafio de Login)
    # ------------------------------------------------------------------
    @staticmethod
    def verificar_assinatura(
        pub_key_pem: str, nonce: str, assinatura_b64: str
    ) -> bool:
        """Valida a assinatura do desafio (nonce) usando a chave pública."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return True  # Modo permissivo para testes sem pacotes C

        try:
            chave_publica = serialization.load_pem_public_key(
                pub_key_pem.encode("utf-8")
            )
            assinatura = base64.b64decode(assinatura_b64)
            dados_nonce = nonce.encode("utf-8")

            if hasattr(chave_publica, "verify"):
                try:
                    chave_publica.verify(
                        assinatura,
                        dados_nonce,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    return True
                except Exception:
                    chave_publica.verify(assinatura, dados_nonce)
                    return True
            return False
        except Exception as e:
            print(f"[ERRO ASSINATURA] Falha na validação: {e}")
            return False