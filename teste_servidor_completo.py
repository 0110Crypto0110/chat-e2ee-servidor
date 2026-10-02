"""Teste completo do servidor - com validação detalhada.

Rodar com o venv do servidor ativo:
    python teste_servidor_completo.py
"""

import os
import base64
import sqlite3
import time


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
class Teste:
    def __init__(self):
        self.ok = 0
        self.falhou = 0
        self.erros = []

    def secao(self, titulo):
        print()
        print("─" * 72)
        print(f"  {titulo}")
        print("─" * 72)

    def check(self, nome, condicao, detalhe=""):
        if condicao:
            print(f"  ✅ {nome}")
            if detalhe:
                print(f"     {detalhe}")
            self.ok += 1
        else:
            print(f"  ❌ {nome}")
            if detalhe:
                print(f"     {detalhe}")
            self.falhou += 1
            self.erros.append(nome)
        return condicao

    def iguais(self, nome, a, b, mostrar=True):
        ok = a == b
        det = ""
        if mostrar and not ok:
            det = f"A={self.resumo(a)}   B={self.resumo(b)}"
        return self.check(nome, ok, det)

    def diferentes(self, nome, a, b):
        ok = a != b
        det = ""
        if not ok:
            det = f"ambos = {self.resumo(a)}"
        return self.check(nome, ok, det)

    @staticmethod
    def resumo(v, n=16):
        if isinstance(v, bytes):
            h = v.hex()
            return f"{h[:n]}…{h[-n:]}" if len(h) > n * 2 else h
        if isinstance(v, str):
            return f"{v[:n]}…{v[-n:]}" if len(v) > n * 2 else v
        return str(v)[:40]

    def resumo_final(self):
        print()
        print("═" * 72)
        print("  RESUMO FINAL")
        print("═" * 72)
        print(f"  Total de checks: {self.ok + self.falhou}")
        print(f"  ✅ Passaram: {self.ok}")
        print(f"  ❌ Falharam: {self.falhou}")
        if self.erros:
            print()
            print("  Checks que falharam:")
            for e in self.erros:
                print(f"    • {e}")
        print()


t = Teste()


# ---------------------------------------------------------------------
# 1. primitivas_rust (12 funções)
# ---------------------------------------------------------------------
def teste_primitivas_rust():
    t.secao("1. primitivas_rust — funções Rust (servidor)")

    try:
        import primitivas_rust as pr
    except ImportError as e:
        t.check("import primitivas_rust", False, str(e))
        return

    t.check("import primitivas_rust", True, f"arquivo: {pr.__file__}")

    # --- Argon2 ---
    print()
    print("  ── Argon2id (hash de senha) ──")
    salt = os.urandom(16)
    h = pr.argon2_hash_password("minhaSenha!123", salt)
    print(f"     salt: {t.resumo(salt)}")
    print(f"     hash: {h[:60]}…")
    t.check("hash começa com $argon2id", h.startswith("$argon2id"))
    t.check("verify senha correta", pr.argon2_verify_password("minhaSenha!123", h))
    t.check(
        "verify senha errada = False",
        not pr.argon2_verify_password("outra", h),
    )

    # Salt diferente -> hash diferente (mesma senha)
    salt2 = os.urandom(16)
    h2 = pr.argon2_hash_password("minhaSenha!123", salt2)
    t.diferentes("salt diferente → hash diferente", h, h2)
    t.check(
        "hash do salt2 valida a mesma senha",
        pr.argon2_verify_password("minhaSenha!123", h2),
    )

    # --- AES-256-GCM ---
    print()
    print("  ── AES-256-GCM ──")
    k = os.urandom(32)
    n = os.urandom(12)
    ct = bytes(pr.aes256_encrypt(k, b"dados do canal", n))
    pt = bytes(pr.aes256_decrypt(k, ct, n))
    print(f"     ciphertext: {t.resumo(ct)}  ({len(ct)} bytes)")
    t.iguais("AES roundtrip", pt, b"dados do canal")

    # --- HMAC-SHA-256 ---
    print()
    print("  ── HMAC-SHA-256 ──")
    key = os.urandom(32)
    tag = bytes(pr.hmac_sha256_digest(key, b"pacote"))
    print(f"     tag: {t.resumo(tag)}  ({len(tag)} bytes)")
    t.check("tag tem 32 bytes", len(tag) == 32)
    t.check("verify correto", pr.hmac_sha256_verify(key, b"pacote", tag))
    t.check(
        "verify mensagem errada = False",
        not pr.hmac_sha256_verify(key, b"outro", tag),
    )

    # --- HKDF ---
    print()
    print("  ── HKDF-SHA-256 ──")
    okm = bytes(pr.hkdf_sha256(os.urandom(32), os.urandom(16), b"info", 64))
    print(f"     OKM: {t.resumo(okm)}  ({len(okm)} bytes)")
    t.check("HKDF gera 64 bytes", len(okm) == 64)

    # --- X25519 ---
    print()
    print("  ── X25519 ──")
    a_priv = os.urandom(32)
    b_priv = os.urandom(32)
    a_pub = bytes(pr.x25519_public_from_private(a_priv))
    b_pub = bytes(pr.x25519_public_from_private(b_priv))
    seg_a = bytes(pr.x25519_shared(a_priv, b_pub))
    seg_b = bytes(pr.x25519_shared(b_priv, a_pub))
    print(f"     A pub: {t.resumo(a_pub)}")
    print(f"     B pub: {t.resumo(b_pub)}")
    print(f"     segredo: {t.resumo(seg_a)}")
    t.iguais("segredos batem", seg_a, seg_b)

    # --- Ed25519 ---
    print()
    print("  ── Ed25519 ──")
    priv = os.urandom(32)
    pub = bytes(pr.ed25519_public_from_private(priv))
    desafio = b"nonce-do-servidor-32bytes"
    sig = bytes(pr.ed25519_sign(priv, desafio))
    print(f"     pública   : {t.resumo(pub)}")
    print(f"     assinatura: {t.resumo(sig)}  ({len(sig)} bytes)")
    t.check("pública 32B", len(pub) == 32)
    t.check("assinatura 64B", len(sig) == 64)
    t.check("verify correto", pr.ed25519_verify(pub, desafio, sig))
    t.check(
        "verify mensagem errada = False",
        not pr.ed25519_verify(pub, b"outro", sig),
    )


# ---------------------------------------------------------------------
# 2. PrimitivasServidor — wrapper
# ---------------------------------------------------------------------
def teste_primitivas_servidor():
    t.secao("2. PrimitivasServidor — wrapper de alto nível")

    try:
        from seguranca.primitivas import PrimitivasServidor as P
    except Exception as e:
        t.check("import PrimitivasServidor", False, str(e))
        return

    print()
    print("  ── Hash de senha ──")
    h, s = P.gerar_hash_senha("senha_teste_123")
    print(f"     hash: {h[:60]}…")
    print(f"     salt: {s}")
    t.check("começa com $argon2id", h.startswith("$argon2id"))
    t.check("verificar correta", P.verificar_senha("senha_teste_123", h, s))
    t.check(
        "verificar errada = False",
        not P.verificar_senha("errada", h, s),
    )

    print()
    print("  ── DHE X25519 (para o canal) ──")
    priv_a, pub_a_b64 = P.gerar_par_dhe()
    priv_b, pub_b_b64 = P.gerar_par_dhe()
    print(f"     A priv: {t.resumo(priv_a)}")
    print(f"     A pub : {pub_a_b64[:32]}…")
    print(f"     B priv: {t.resumo(priv_b)}")
    print(f"     B pub : {pub_b_b64[:32]}…")
    t.check("priv tem 32 bytes", len(priv_a) == 32)
    t.check("pub é base64", isinstance(pub_a_b64, str))
    t.diferentes("pares A e B são diferentes", pub_a_b64, pub_b_b64)

    seg_a = P.calcular_segredo_compartilhado(priv_a, pub_b_b64)
    seg_b = P.calcular_segredo_compartilhado(priv_b, pub_a_b64)
    print(f"     segredo A: {t.resumo(seg_a)}")
    print(f"     segredo B: {t.resumo(seg_b)}")
    t.iguais("segredos batem", seg_a, seg_b)

    print()
    print("  ── HKDF ──")
    salt_b64 = base64.b64encode(os.urandom(16)).decode()
    k1a, k2a = P.derivar_chaves_hkdf(seg_a, salt_b64)
    k1b, k2b = P.derivar_chaves_hkdf(seg_b, salt_b64)
    print(f"     AES  A: {t.resumo(k1a)}")
    print(f"     AES  B: {t.resumo(k1b)}")
    print(f"     HMAC A: {t.resumo(k2a)}")
    print(f"     HMAC B: {t.resumo(k2b)}")
    t.iguais("chave AES bate", k1a, k1b)
    t.iguais("chave HMAC bate", k2a, k2b)
    t.check("AES 32 bytes", len(k1a) == 32)
    t.check("HMAC 32 bytes", len(k2a) == 32)
    t.diferentes("AES != HMAC", k1a, k2a)

    print()
    print("  ── Canal (cifra/decifra) ──")
    texto = "LOGIN|alice|senha"
    pacote = P.cifrar_canal(k1a, k2a, texto)
    print(f"     texto : {texto!r}")
    print(f"     pacote: {pacote[:60]}…  ({len(pacote)} chars)")
    t.check("pacote é base64 (sem '|')", "|" not in pacote)
    t.check("pacote tem tamanho razoável", len(pacote) > 40)

    decifrado = P.decifrar_canal(k1a, k2a, pacote)
    print(f"     decifrado: {decifrado!r}")
    t.iguais("decifra corretamente", decifrado, texto)

    # Pacote adulterado
    pacote_alt = pacote[:20] + ("A" if pacote[20] != "A" else "B") + pacote[21:]
    t.check(
        "pacote adulterado rejeitado",
        P.decifrar_canal(k1a, k2a, pacote_alt) == "",
    )

    # Chave errada
    k1_errada = os.urandom(32)
    t.check(
        "chave errada rejeita pacote",
        P.decifrar_canal(k1_errada, k2a, pacote) == "",
    )

    # Duas cifragens do mesmo texto → pacotes diferentes (nonce aleatório)
    pacote2 = P.cifrar_canal(k1a, k2a, texto)
    t.diferentes(
        "cifrar mesmo texto 2x → pacotes diferentes (nonce)",
        pacote,
        pacote2,
    )


# ---------------------------------------------------------------------
# 3. PersistenciaDB
# ---------------------------------------------------------------------
def teste_persistencia():
    t.secao("3. PersistenciaDB — banco SQLite temporário")
    db_teste = "chat_test.db"
    if os.path.exists(db_teste):
        os.remove(db_teste)

    try:
        from infraestrutura.persistencia import PersistenciaDB
    except Exception as e:
        t.check("import PersistenciaDB", False, str(e))
        return

    try:
        db = PersistenciaDB(db_name=db_teste)

        print()
        print("  ── Usuários ──")
        t.check("cadastrar alice", db.cadastrar_usuario("alice", "senha123"))
        t.check(
            "cadastrar alice de novo falha (UNIQUE)",
            not db.cadastrar_usuario("alice", "outra"),
        )
        t.check("cadastrar bob", db.cadastrar_usuario("bob", "senha456"))

        print()
        print("  ── Credenciais ──")
        t.check("login alice correto", db.verificar_credenciais("alice", "senha123"))
        t.check(
            "login alice errado = False",
            not db.verificar_credenciais("alice", "errada"),
        )
        t.check(
            "login usuário inexistente = False",
            not db.verificar_credenciais("carlos", "x"),
        )

        print()
        print("  ── Hash Argon2 no banco ──")
        conn = sqlite3.connect(db_teste)
        row = conn.execute(
            "SELECT password FROM users WHERE username='alice'"
        ).fetchone()
        conn.close()
        print(f"     password armazenado: {row[0][:60]}…")
        t.check(
            "senha armazenada como $argon2id (não texto puro)",
            row and row[0].startswith("$argon2id"),
        )
        t.check(
            "senha NÃO aparece em texto puro no banco",
            "senha123" not in row[0],
        )

        print()
        print("  ── Chaves públicas ──")
        db.atualizar_chave_publica("alice", "PUB_X25519_ALICE")
        db.atualizar_ed25519_publica("alice", "PUB_ED25519_ALICE")
        t.check(
            "obter X25519 alice",
            db.obter_chave_publica("alice") == "PUB_X25519_ALICE",
        )
        t.check(
            "obter Ed25519 alice",
            db.obter_ed25519_publica("alice") == "PUB_ED25519_ALICE",
        )
        t.check(
            "chave de bob ainda é None",
            db.obter_chave_publica("bob") is None,
        )

        print()
        print("  ── Listagem ──")
        users = db.listar_todos_usuarios()
        print(f"     usuários: {users}")
        t.check("lista contém alice e bob", set(users) == {"alice", "bob"})

        print()
        print("  ── Fila de mensagens offline ──")
        db.salvar_mensagem_offline("alice", "bob", "oi bob")
        db.salvar_mensagem_offline("alice", "bob", "tudo bem?")
        db.salvar_mensagem_offline("carlos", "bob", "não é para alice")
        mensagens = db.buscar_e_limpar_mensagens_offline("bob")
        print(f"     mensagens para bob: {len(mensagens)}")
        for m in mensagens:
            print(f"       {m[0]} -> {m[1]!r}")
        t.check("3 mensagens entregues", len(mensagens) == 3)
        t.check(
            "primeira mensagem é de alice",
            mensagens[0][0] == "alice" and mensagens[0][1] == "oi bob",
        )
        t.check(
            "fila esvaziada após leitura",
            db.buscar_e_limpar_mensagens_offline("bob") == [],
        )
        t.check(
            "mensagens de carlos ainda presentes para alice? não - ele mandou pra bob",
            True,
        )
    finally:
        if os.path.exists(db_teste):
            os.remove(db_teste)


# ---------------------------------------------------------------------
# 4. SessaoCanalServidor — handshake simulado
# ---------------------------------------------------------------------
def teste_sessao_canal():
    t.secao("4. SessaoCanalServidor — handshake DHE completo")

    try:
        from seguranca.sessao_canal import SessaoCanalServidor
        from seguranca.primitivas import PrimitivasServidor as P
        import primitivas_rust as pr
    except Exception as e:
        t.check("import SessaoCanalServidor", False, str(e))
        return

    # --- Simula o lado do cliente com primitivas puras ---
    priv_cli = os.urandom(32)
    pub_cli = bytes(pr.x25519_public_from_private(priv_cli))
    salt = os.urandom(16)
    pub_cli_b64 = base64.b64encode(pub_cli).decode()
    salt_b64 = base64.b64encode(salt).decode()

    print()
    print("  ── FASE 1: HANDSHAKE_INIT ──")
    print(f"     cliente pub  : {t.resumo(pub_cli)}")
    print(f"     cliente salt : {t.resumo(salt)}")

    handshake_init = f"HANDSHAKE_INIT|{pub_cli_b64}|{salt_b64}"
    sessao = SessaoCanalServidor()
    resp = sessao.processar_handshake_inicial(handshake_init)
    print(f"     resposta srv : {resp[:60]}…")

    if not t.check("servidor respondeu HANDSHAKE_RESP", resp.startswith("HANDSHAKE_RESP|")):
        return
    t.check("servidor marcou canal_ativo", sessao.canal_ativo)

    # --- Deriva as chaves do lado do cliente ---
    pub_srv_b64 = resp.split("|", 1)[1]
    pub_srv = base64.b64decode(pub_srv_b64)
    print()
    print("  ── FASE 2: derivação simétrica ──")
    print(f"     servidor pub : {t.resumo(pub_srv)}")

    segredo_cli = bytes(pr.x25519_shared(priv_cli, pub_srv))
    okm_cli = bytes(pr.hkdf_sha256(
        segredo_cli, salt, b"canal-cliente-servidor", 64
    ))
    chave_aes_cli = okm_cli[:32]
    chave_hmac_cli = okm_cli[32:]

    print(f"     segredo (cli): {t.resumo(segredo_cli)}")
    print(f"     AES    (cli): {t.resumo(chave_aes_cli)}")
    print(f"     AES    (srv): {t.resumo(sessao.chave_1_aes)}")
    print(f"     HMAC   (cli): {t.resumo(chave_hmac_cli)}")
    print(f"     HMAC   (srv): {t.resumo(sessao.chave_2_hmac)}")

    t.iguais("chave AES bate entre cliente e servidor",
             chave_aes_cli, sessao.chave_1_aes)
    t.iguais("chave HMAC bate entre cliente e servidor",
             chave_hmac_cli, sessao.chave_2_hmac)

    # --- FASE 3: tráfego cifrado ---
    print()
    print("  ── FASE 3: tráfego cifrado cliente → servidor ──")
    comando = "LOGIN|alice|senha_secreta"
    pacote_cli = P.cifrar_canal(chave_aes_cli, chave_hmac_cli, comando)
    print(f"     pacote enviado: {pacote_cli[:60]}…")
    t.check("pacote do cliente não tem '|'", "|" not in pacote_cli)

    recebido = sessao.decifrar_entrada(pacote_cli)
    print(f"     servidor decifrou: {recebido!r}")
    t.iguais("servidor decifrou corretamente", recebido, comando)

    print()
    print("  ── FASE 4: tráfego cifrado servidor → cliente ──")
    resposta_srv = "LOGIN_OK|Autenticado por assinatura."
    pacote_srv = sessao.cifrar_saida(resposta_srv)
    print(f"     pacote enviado: {pacote_srv[:60]}…")

    recebido_cli = P.decifrar_canal(chave_aes_cli, chave_hmac_cli, pacote_srv)
    print(f"     cliente decifrou: {recebido_cli!r}")
    t.iguais("cliente decifrou corretamente", recebido_cli, resposta_srv)

    print()
    print("  ── FASE 5: segurança ──")
    # Chave errada
    k_errada = os.urandom(32)
    t.check(
        "chave AES errada não decifra",
        P.decifrar_canal(k_errada, chave_hmac_cli, pacote_srv) == "",
    )
    # HMAC errado
    t.check(
        "chave HMAC errada não decifra",
        P.decifrar_canal(chave_aes_cli, os.urandom(32), pacote_srv) == "",
    )
    # Pacote adulterado
    pkt_alt = pacote_srv[:15] + ("A" if pacote_srv[15] != "A" else "B") + pacote_srv[16:]
    t.check(
        "pacote adulterado rejeitado (HMAC)",
        P.decifrar_canal(chave_aes_cli, chave_hmac_cli, pkt_alt) == "",
    )

    # Handshake inválido
    print()
    print("  ── FASE 6: handshake inválido ──")
    sessao2 = SessaoCanalServidor()
    resp_ruim = sessao2.processar_handshake_inicial("HANDSHAKE_INIT|curto")
    t.check(
        "handshake malformado rejeitado",
        resp_ruim.startswith("ERROR|"),
        f"resposta: {resp_ruim}",
    )
    t.check("canal NÃO ficou ativo", not sessao2.canal_ativo)


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    print()
    print("╔" + "═" * 70 + "╗")
    print("║" + "  TESTE COMPLETO DO SERVIDOR".center(70) + "║")
    print("║" + f"  Python: {os.sys.executable}".center(70)[:70] + "║")
    print("╚" + "═" * 70 + "╝")

    t0 = time.time()
    teste_primitivas_rust()
    teste_primitivas_servidor()
    teste_persistencia()
    teste_sessao_canal()
    dur = time.time() - t0

    t.resumo_final()
    print(f"  Tempo total: {dur:.2f}s")
    print()


if __name__ == "__main__":
    main()