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
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------
// ARGON2 (hash de senha)
// ---------------------------------------------------------------------

/// Gera o hash Argon2 de uma senha, usando um salt fornecido pelo Python
/// (o Python gera os bytes aleatórios com os.urandom).
#[pyfunction]
fn argon2_hash_password(password: &str, salt_bytes: &[u8]) -> PyResult<String> {
    if salt_bytes.len() < 8 {
        return Err(PyValueError::new_err(
            "O salt Argon2 deve ter ao menos 8 bytes.",
        ));
    }
    let salt = SaltString::encode_b64(salt_bytes)
        .map_err(|e| PyValueError::new_err(format!("Salt inválido: {e}")))?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PyValueError::new_err(format!("Falha no Argon2: {e}")))?
        .to_string();

    Ok(hash)
}

/// Verifica a senha contra um hash Argon2 armazenado.
#[pyfunction]
fn argon2_verify_password(password: &str, hash_str: &str) -> PyResult<bool> {
    let parsed_hash = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    Ok(
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok(),
    )
}

// ---------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------

#[pyfunction]
fn aes256_encrypt(
    py: Python<'_>,
    key: &[u8],
    plaintext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "A chave AES-256 deve ter exatamente 32 bytes.",
        ));
    }
    if nonce_bytes.len() != 12 {
        return Err(PyValueError::new_err(
            "O nonce deve ter exatamente 12 bytes.",
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PyValueError::new_err(format!("Falha ao cifrar: {e}")))?;
    Ok(PyBytes::new(py, &ct).into())
}

#[pyfunction]
fn aes256_decrypt(
    py: Python<'_>,
    key: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "A chave AES-256 deve ter exatamente 32 bytes.",
        ));
    }
    if nonce_bytes.len() != 12 {
        return Err(PyValueError::new_err(
            "O nonce deve ter exatamente 12 bytes.",
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        PyValueError::new_err(format!(
            "Falha ao decifrar (chave errada ou dado corrompido): {e}"
        ))
    })?;
    Ok(PyBytes::new(py, &pt).into())
}

// ---------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------

#[pyfunction]
fn hmac_sha256_digest(
    py: Python<'_>,
    key: &[u8],
    message: &[u8],
) -> PyResult<Py<PyBytes>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("Chave HMAC inválida: {e}")))?;
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    Ok(PyBytes::new(py, &tag).into())
}

#[pyfunction]
fn hmac_sha256_verify(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("Chave HMAC inválida: {e}")))?;
    mac.update(message);
    Ok(mac.verify_slice(expected_tag).is_ok())
}

// ---------------------------------------------------------------------
// Registro do módulo (assinatura PyO3 0.20)
// ---------------------------------------------------------------------

#[pymodule]
fn primitivas_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(argon2_hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(argon2_verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_digest, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_verify, m)?)?;
    Ok(())
}