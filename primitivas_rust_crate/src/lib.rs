use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

// =====================================================================
// ARGON2 — hash de senha
// =====================================================================

/// Núcleo de `argon2_hash_password` — lógica pura, testável sem Python.
fn argon2_hash_password_internal(
    password: &str,
    salt_bytes: &[u8],
) -> Result<String, String> {
    if salt_bytes.len() < 8 {
        return Err("O salt Argon2 deve ter ao menos 8 bytes.".into());
    }
    let salt = SaltString::encode_b64(salt_bytes)
        .map_err(|e| format!("Salt invalido: {e}"))?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Falha no Argon2: {e}"))?
        .to_string();
    Ok(hash)
}

/// Núcleo de `argon2_verify_password` — lógica pura.
fn argon2_verify_password_internal(
    password: &str,
    hash_str: &str,
) -> Result<bool, String> {
    let parsed = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Gera o hash Argon2id de uma senha usando um salt fornecido pelo Python.
///
/// Argumentos:
///     password: a senha em texto plano (str)
///     salt_bytes: salt com no mínimo 8 bytes (bytes)
///
/// Retorna:
///     String no formato "$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>"
///
/// Erros:
///     ValueError se o salt tiver menos de 8 bytes ou se o Argon2 falhar.
#[pyfunction]
fn argon2_hash_password(
    password: &str,
    salt_bytes: &[u8],
) -> PyResult<String> {
    argon2_hash_password_internal(password, salt_bytes)
        .map_err(PyValueError::new_err)
}

/// Verifica se `password` corresponde ao hash Argon2 armazenado.
///
/// Argumentos:
///     password: senha em texto plano (str)
///     hash_str: hash no formato "$argon2id$..." (str)
///
/// Retorna:
///     True se a senha confere, False caso contrário.
#[pyfunction]
fn argon2_verify_password(password: &str, hash_str: &str) -> PyResult<bool> {
    argon2_verify_password_internal(password, hash_str)
        .map_err(PyValueError::new_err)
}

// =====================================================================
// AES-256-GCM
// =====================================================================

/// Núcleo de `aes256_encrypt` — lógica pura.
fn aes256_encrypt_internal(
    key: &[u8],
    plaintext: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("A chave AES-256 deve ter exatamente 32 bytes.".into());
    }
    if nonce_bytes.len() != 12 {
        return Err("O nonce deve ter exatamente 12 bytes.".into());
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Falha ao cifrar: {e}"))
}

/// Núcleo de `aes256_decrypt` — lógica pura.
fn aes256_decrypt_internal(
    key: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("A chave AES-256 deve ter exatamente 32 bytes.".into());
    }
    if nonce_bytes.len() != 12 {
        return Err("O nonce deve ter exatamente 12 bytes.".into());
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        format!("Falha ao decifrar (chave errada ou dado corrompido): {e}")
    })
}

/// Cifra `plaintext` com AES-256-GCM.
///
/// Argumentos:
///     key: 32 bytes (256 bits) — chave simétrica
///     plaintext: bytes em claro
///     nonce_bytes: 12 bytes — nonce único por mensagem (NUNCA reutilizar)
///
/// Retorna:
///     bytes do ciphertext com a tag GCM (16 bytes) embutida no final.
///
/// Erros:
///     ValueError se key != 32 bytes ou nonce != 12 bytes.
#[pyfunction]
fn aes256_encrypt(
    py: Python<'_>,
    key: &[u8],
    plaintext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    let ct = aes256_encrypt_internal(key, plaintext, nonce_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &ct).into())
}

/// Decifra `ciphertext` com AES-256-GCM, validando a tag de autenticação.
///
/// Argumentos:
///     key: 32 bytes — mesma chave usada para cifrar
///     ciphertext: bytes do ciphertext + tag GCM
///     nonce_bytes: 12 bytes — mesmo nonce usado para cifrar
///
/// Retorna:
///     bytes do plaintext original.
///
/// Erros:
///     ValueError se key/nonce tiverem tamanho errado, ou se a
///     autenticação falhar (chave errada, dado adulterado, etc.).
#[pyfunction]
fn aes256_decrypt(
    py: Python<'_>,
    key: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    let pt = aes256_decrypt_internal(key, ciphertext, nonce_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &pt).into())
}

// =====================================================================
// HMAC-SHA-256
// =====================================================================

/// Núcleo de `hmac_sha256_digest` — lógica pura.
fn hmac_sha256_digest_internal(
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| format!("Chave HMAC invalida: {e}"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Núcleo de `hmac_sha256_verify` — lógica pura.
fn hmac_sha256_verify_internal(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> Result<bool, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| format!("Chave HMAC invalida: {e}"))?;
    mac.update(message);
    Ok(mac.verify_slice(expected_tag).is_ok())
}

/// Calcula o HMAC-SHA-256 de `message` com `key`.
///
/// Argumentos:
///     key: chave HMAC (qualquer tamanho, recomendado >= 32 bytes)
///     message: bytes a autenticar
///
/// Retorna:
///     bytes de 32 bytes (a tag HMAC).
#[pyfunction]
fn hmac_sha256_digest(
    py: Python<'_>,
    key: &[u8],
    message: &[u8],
) -> PyResult<Py<PyBytes>> {
    let tag = hmac_sha256_digest_internal(key, message)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &tag).into())
}

/// Verifica em tempo constante se a tag HMAC confere.
///
/// Argumentos:
///     key: chave HMAC
///     message: bytes originais
///     expected_tag: tag a comparar
///
/// Retorna:
///     True se a tag confere, False caso contrário.
#[pyfunction]
fn hmac_sha256_verify(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    hmac_sha256_verify_internal(key, message, expected_tag)
        .map_err(PyValueError::new_err)
}

// =====================================================================
// HKDF-SHA-256
// =====================================================================

/// Núcleo de `hkdf_sha256` — lógica pura.
fn hkdf_sha256_internal(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, String> {
    if length == 0 || length > 255 * 32 {
        return Err("Comprimento HKDF invalido (1..=8160 bytes).".into());
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| format!("Falha no HKDF: {e}"))?;
    Ok(okm)
}

/// Deriva `length` bytes determinísticos a partir de `ikm` via HKDF-SHA-256.
///
/// Argumentos:
///     ikm: Input Key Material (ex: segredo X25519)
///     salt: salt do HKDF
///     info: string de contexto (diferencia usos; ex: b"canal-cliente-servidor")
///     length: tamanho da saída em bytes (1..=8160)
///
/// Retorna:
///     bytes do OKM (Output Key Material).
///
/// Erros:
///     ValueError se length for 0 ou maior que 8160.
#[pyfunction]
fn hkdf_sha256(
    py: Python<'_>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Py<PyBytes>> {
    let okm = hkdf_sha256_internal(ikm, salt, info, length)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &okm).into())
}

// =====================================================================
// X25519
// =====================================================================

/// Aplica o clamp RFC 7748 à chave privada X25519.
fn clamp_x25519(mut sk: [u8; 32]) -> [u8; 32] {
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

/// Núcleo de `x25519_public_from_private` — lógica pura.
fn x25519_public_internal(private_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 {
        return Err("Chave privada X25519 deve ter 32 bytes.".into());
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let sk = clamp_x25519(sk);

    let secret = StaticSecret::from(sk);
    let public = PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

/// Núcleo de `x25519_shared` — lógica pura.
fn x25519_shared_internal(
    private_bytes: &[u8],
    peer_public_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 {
        return Err("Chave privada X25519 deve ter 32 bytes.".into());
    }
    if peer_public_bytes.len() != 32 {
        return Err("Chave publica X25519 deve ter 32 bytes.".into());
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let sk = clamp_x25519(sk);

    let mut pk = [0u8; 32];
    pk.copy_from_slice(peer_public_bytes);

    let secret = StaticSecret::from(sk);
    let peer_public = PublicKey::from(pk);
    let shared = secret.diffie_hellman(&peer_public);
    Ok(shared.as_bytes().to_vec())
}

/// Deriva a chave pública X25519 a partir da privada.
///
/// Aplica o clamp RFC 7748 (idempotente) para garantir simetria
/// com implementações que fazem o clamp internamente.
///
/// Argumentos:
///     private_bytes: 32 bytes da chave privada
///
/// Retorna:
///     32 bytes da chave pública.
#[pyfunction]
fn x25519_public_from_private(
    py: Python<'_>,
    private_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    let pub_key = x25519_public_internal(private_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &pub_key).into())
}

/// Calcula o segredo compartilhado X25519 (Diffie-Hellman).
///
/// Argumentos:
///     private_bytes: 32 bytes da chave privada local
///     peer_public_bytes: 32 bytes da chave pública do par
///
/// Retorna:
///     32 bytes do segredo compartilhado.
#[pyfunction]
fn x25519_shared(
    py: Python<'_>,
    private_bytes: &[u8],
    peer_public_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    let shared = x25519_shared_internal(private_bytes, peer_public_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &shared).into())
}

// =====================================================================
// ED25519
// =====================================================================

/// Núcleo de `ed25519_public_from_private` — lógica pura.
fn ed25519_public_internal(private_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 {
        return Err("Chave privada Ed25519 deve ter 32 bytes.".into());
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let signing_key = SigningKey::from_bytes(&sk);
    let verifying_key = signing_key.verifying_key();
    Ok(verifying_key.to_bytes().to_vec())
}

/// Núcleo de `ed25519_sign` — lógica pura.
fn ed25519_sign_internal(
    private_bytes: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 {
        return Err("Chave privada Ed25519 deve ter 32 bytes.".into());
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let signing_key = SigningKey::from_bytes(&sk);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Núcleo de `ed25519_verify` — lógica pura.
fn ed25519_verify_internal(
    public_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    if public_bytes.len() != 32 {
        return Err("Chave publica Ed25519 deve ter 32 bytes.".into());
    }
    if signature_bytes.len() != 64 {
        return Err("Assinatura Ed25519 deve ter 64 bytes.".into());
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_bytes);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Deriva a chave pública Ed25519 a partir da privada.
///
/// Argumentos:
///     private_bytes: 32 bytes da semente privada Ed25519
///
/// Retorna:
///     32 bytes da chave pública.
#[pyfunction]
fn ed25519_public_from_private(
    py: Python<'_>,
    private_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    let pub_key = ed25519_public_internal(private_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &pub_key).into())
}

/// Assina `message` com a chave privada Ed25519.
///
/// Ed25519 é determinístico: mesma entrada → mesma assinatura.
///
/// Argumentos:
///     private_bytes: 32 bytes da chave privada
///     message: bytes a assinar
///
/// Retorna:
///     64 bytes da assinatura.
#[pyfunction]
fn ed25519_sign(
    py: Python<'_>,
    private_bytes: &[u8],
    message: &[u8],
) -> PyResult<Py<PyBytes>> {
    let sig = ed25519_sign_internal(private_bytes, message)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &sig).into())
}

/// Verifica a assinatura Ed25519 de `message` com `public_bytes`.
///
/// Argumentos:
///     public_bytes: 32 bytes da chave pública
///     message: bytes originais
///     signature_bytes: 64 bytes da assinatura
///
/// Retorna:
///     True se a assinatura é válida, False caso contrário.
#[pyfunction]
fn ed25519_verify(
    public_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> PyResult<bool> {
    ed25519_verify_internal(public_bytes, message, signature_bytes)
        .map_err(PyValueError::new_err)
}

// =====================================================================
// TESTES
// =====================================================================

type TestResult = Result<(), String>;

fn expect(cond: bool, msg: &str) -> TestResult {
    if cond { Ok(()) } else { Err(msg.into()) }
}

// --- AES ---
fn t_aes_roundtrip() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let ct = aes256_encrypt_internal(&key, b"mensagem", &nonce)?;
    let pt = aes256_decrypt_internal(&key, &ct, &nonce)?;
    expect(pt == b"mensagem", "roundtrip falhou")
}
fn t_aes_chave_errada() -> TestResult {
    let ct = aes256_encrypt_internal(&[0x42u8; 32], b"dados", &[0x11u8; 12])?;
    expect(
        aes256_decrypt_internal(&[0x99u8; 32], &ct, &[0x11u8; 12]).is_err(),
        "decifrou com chave errada",
    )
}
fn t_aes_nonce_errado() -> TestResult {
    let ct = aes256_encrypt_internal(&[0x42u8; 32], b"dados", &[0x11u8; 12])?;
    expect(
        aes256_decrypt_internal(&[0x42u8; 32], &ct, &[0x22u8; 12]).is_err(),
        "decifrou com nonce errado",
    )
}
fn t_aes_nonce_diferente_ct_diferente() -> TestResult {
    let ct1 = aes256_encrypt_internal(&[0x42u8; 32], b"x", &[0x11u8; 12])?;
    let ct2 = aes256_encrypt_internal(&[0x42u8; 32], b"x", &[0x22u8; 12])?;
    expect(ct1 != ct2, "mesmo texto com nonces diferentes deu mesmo ct")
}
fn t_aes_chave_tamanho_errado() -> TestResult {
    expect(
        aes256_encrypt_internal(&[0x42u8; 16], b"x", &[0x11u8; 12]).is_err(),
        "aceitou chave de 16 bytes",
    )
}

// --- HMAC ---
fn t_hmac_tem_32_bytes() -> TestResult {
    let tag = hmac_sha256_digest_internal(&[0x42u8; 32], b"msg")?;
    expect(tag.len() == 32, "tag nao tem 32 bytes")
}
fn t_hmac_verify_correto() -> TestResult {
    let key = [0x42u8; 32];
    let tag = hmac_sha256_digest_internal(&key, b"msg")?;
    expect(hmac_sha256_verify_internal(&key, b"msg", &tag)?, "verify falhou")
}
fn t_hmac_verify_msg_errada() -> TestResult {
    let key = [0x42u8; 32];
    let tag = hmac_sha256_digest_internal(&key, b"msg")?;
    expect(!hmac_sha256_verify_internal(&key, b"outra", &tag)?, "aceitou msg errada")
}
fn t_hmac_verify_tag_adulterada() -> TestResult {
    let key = [0x42u8; 32];
    let mut tag = hmac_sha256_digest_internal(&key, b"msg")?;
    tag[0] ^= 0xFF;
    expect(!hmac_sha256_verify_internal(&key, b"msg", &tag)?, "aceitou tag adulterada")
}

// --- HKDF ---
fn t_hkdf_deterministico() -> TestResult {
    let a = hkdf_sha256_internal(&[0x01u8; 32], &[0x02u8; 16], b"info", 64)?;
    let b = hkdf_sha256_internal(&[0x01u8; 32], &[0x02u8; 16], b"info", 64)?;
    expect(a == b && a.len() == 64, "HKDF nao e deterministico ou tamanho errado")
}
fn t_hkdf_info_diferente() -> TestResult {
    let a = hkdf_sha256_internal(&[0x01u8; 32], &[0x02u8; 16], b"a", 64)?;
    let b = hkdf_sha256_internal(&[0x01u8; 32], &[0x02u8; 16], b"b", 64)?;
    expect(a != b, "info diferente deu mesmo OKM")
}
fn t_hkdf_length_zero() -> TestResult {
    expect(hkdf_sha256_internal(&[1u8; 32], &[2u8; 16], b"x", 0).is_err(), "aceitou length=0")
}
fn t_hkdf_length_grande() -> TestResult {
    expect(
        hkdf_sha256_internal(&[1u8; 32], &[2u8; 16], b"x", 255 * 32 + 1).is_err(),
        "aceitou length > 8160",
    )
}

// --- X25519 ---
fn t_x25519_pub_32() -> TestResult {
    expect(x25519_public_internal(&[0x01u8; 32])?.len() == 32, "pub != 32")
}
fn t_x25519_segredo_simetrico() -> TestResult {
    let a_priv = [0x01u8; 32];
    let b_priv = [0x02u8; 32];
    let a_pub = x25519_public_internal(&a_priv)?;
    let b_pub = x25519_public_internal(&b_priv)?;
    let seg_a = x25519_shared_internal(&a_priv, &b_pub)?;
    let seg_b = x25519_shared_internal(&b_priv, &a_pub)?;
    expect(seg_a == seg_b, "segredos divergem")
}
fn t_x25519_clamp() -> TestResult {
    let raw1 = [0x42u8; 32];
    let mut raw2 = [0x42u8; 32];
    raw2[0] |= 0x07;
    raw2[31] |= 0x80;
    let p1 = x25519_public_internal(&raw1)?;
    let p2 = x25519_public_internal(&raw2)?;
    expect(p1 == p2, "clamp RFC 7748 nao aplicado")
}
fn t_x25519_tamanho_errado() -> TestResult {
    expect(x25519_public_internal(&[0x01u8; 16]).is_err(), "aceitou 16 bytes")
}

// --- Ed25519 ---
fn t_ed25519_pub_32() -> TestResult {
    expect(ed25519_public_internal(&[0x01u8; 32])?.len() == 32, "pub != 32")
}
fn t_ed25519_sig_64() -> TestResult {
    expect(ed25519_sign_internal(&[0x01u8; 32], b"x")?.len() == 64, "sig != 64")
}
fn t_ed25519_sign_verify() -> TestResult {
    let priv_bytes = [0x01u8; 32];
    let pub_bytes = ed25519_public_internal(&priv_bytes)?;
    let sig = ed25519_sign_internal(&priv_bytes, b"desafio")?;
    expect(ed25519_verify_internal(&pub_bytes, b"desafio", &sig)?, "verify correto falhou")
}
fn t_ed25519_msg_errada() -> TestResult {
    let priv_bytes = [0x01u8; 32];
    let pub_bytes = ed25519_public_internal(&priv_bytes)?;
    let sig = ed25519_sign_internal(&priv_bytes, b"desafio")?;
    expect(!ed25519_verify_internal(&pub_bytes, b"outro", &sig)?, "aceitou msg errada")
}
fn t_ed25519_pub_errada() -> TestResult {
    let pub2 = ed25519_public_internal(&[0x02u8; 32])?;
    let sig = ed25519_sign_internal(&[0x01u8; 32], b"desafio")?;
    expect(!ed25519_verify_internal(&pub2, b"desafio", &sig)?, "aceitou pub errada")
}
fn t_ed25519_deterministico() -> TestResult {
    let priv_bytes = [0x01u8; 32];
    let a = ed25519_sign_internal(&priv_bytes, b"msg")?;
    let b = ed25519_sign_internal(&priv_bytes, b"msg")?;
    expect(a == b, "assinatura nao e deterministica")
}

// --- Argon2 ---
fn t_argon2_hash_verify() -> TestResult {
    let h = argon2_hash_password_internal("senha123", &[0x42u8; 16])?;
    expect(h.starts_with("$argon2id$"), "hash nao comeca com $argon2id")
}
fn t_argon2_verify_correto() -> TestResult {
    let h = argon2_hash_password_internal("senha123", &[0x42u8; 16])?;
    expect(argon2_verify_password_internal("senha123", &h)?, "verify correto falhou")
}
fn t_argon2_senha_errada() -> TestResult {
    let h = argon2_hash_password_internal("senha123", &[0x42u8; 16])?;
    expect(!argon2_verify_password_internal("outra", &h)?, "aceitou senha errada")
}
fn t_argon2_salt_diferente() -> TestResult {
    let h1 = argon2_hash_password_internal("senha", &[0x42u8; 16])?;
    let h2 = argon2_hash_password_internal("senha", &[0x99u8; 16])?;
    expect(h1 != h2, "salt diferente deu hash igual")
}
fn t_argon2_salt_curto() -> TestResult {
    expect(argon2_hash_password_internal("senha", &[0x42u8; 4]).is_err(), "aceitou salt curto")
}

fn todos_testes() -> Vec<(&'static str, TestResult)> {
    vec![
        ("aes_roundtrip", t_aes_roundtrip()),
        ("aes_chave_errada", t_aes_chave_errada()),
        ("aes_nonce_errado", t_aes_nonce_errado()),
        ("aes_nonce_diferente_ct_diferente", t_aes_nonce_diferente_ct_diferente()),
        ("aes_chave_tamanho_errado", t_aes_chave_tamanho_errado()),
        ("hmac_tem_32_bytes", t_hmac_tem_32_bytes()),
        ("hmac_verify_correto", t_hmac_verify_correto()),
        ("hmac_verify_msg_errada", t_hmac_verify_msg_errada()),
        ("hmac_verify_tag_adulterada", t_hmac_verify_tag_adulterada()),
        ("hkdf_deterministico", t_hkdf_deterministico()),
        ("hkdf_info_diferente", t_hkdf_info_diferente()),
        ("hkdf_length_zero", t_hkdf_length_zero()),
        ("hkdf_length_grande", t_hkdf_length_grande()),
        ("x25519_pub_32", t_x25519_pub_32()),
        ("x25519_segredo_simetrico", t_x25519_segredo_simetrico()),
        ("x25519_clamp", t_x25519_clamp()),
        ("x25519_tamanho_errado", t_x25519_tamanho_errado()),
        ("ed25519_pub_32", t_ed25519_pub_32()),
        ("ed25519_sig_64", t_ed25519_sig_64()),
        ("ed25519_sign_verify", t_ed25519_sign_verify()),
        ("ed25519_msg_errada", t_ed25519_msg_errada()),
        ("ed25519_pub_errada", t_ed25519_pub_errada()),
        ("ed25519_deterministico", t_ed25519_deterministico()),
        ("argon2_hash_verify", t_argon2_hash_verify()),
        ("argon2_verify_correto", t_argon2_verify_correto()),
        ("argon2_senha_errada", t_argon2_senha_errada()),
        ("argon2_salt_diferente", t_argon2_salt_diferente()),
        ("argon2_salt_curto", t_argon2_salt_curto()),
    ]
}

/// Roda todos os testes internos do crate.
///
/// Uso no Python:
///     import primitivas_rust as pr
///     for nome, ok, msg in pr.run_tests():
///         print("OK" if ok else f"FALHOU: {msg}", nome)
#[pyfunction]
fn run_tests() -> PyResult<Vec<(String, bool, String)>> {
    Ok(todos_testes()
        .into_iter()
        .map(|(n, r)| match r {
            Ok(()) => (n.to_string(), true, String::new()),
            Err(e) => (n.to_string(), false, e),
        })
        .collect())
}

// =====================================================================
// MÓDULO PYO3
// =====================================================================

#[pymodule]
fn primitivas_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(argon2_hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(argon2_verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_digest, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_public_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_shared, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_public_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(run_tests, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rodar_tudo() {
        let mut falhas = Vec::new();
        for (nome, r) in todos_testes() {
            if let Err(e) = r {
                falhas.push(format!("{nome}: {e}"));
            }
        }
        if !falhas.is_empty() {
            panic!("{} testes falharam:\n{}", falhas.len(), falhas.join("\n"));
        }
    }
}