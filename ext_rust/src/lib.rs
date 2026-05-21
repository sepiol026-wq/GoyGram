// Copyleft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn pad(src: &[u8]) -> Vec<u8> {
    let n = 16 - (src.len() % 16);
    let p = if n == 0 { 16 } else { n };
    let mut out = Vec::with_capacity(src.len() + p);
    out.extend_from_slice(src);
    out.resize(src.len() + p, p as u8);
    out
}

fn unpad(src: &[u8]) -> PyResult<Vec<u8>> {
    if src.is_empty() {
        return Ok(Vec::new());
    }
    let p = *src.last().unwrap() as usize;
    if p == 0 || p > 16 || src.len() < p {
        return Err(PyValueError::new_err("bad pad"));
    }
    if src[src.len() - p..].iter().any(|b| *b as usize != p) {
        return Err(PyValueError::new_err("bad pad"));
    }
    Ok(src[..src.len() - p].to_vec())
}

fn chk(key: &[u8], iv: &[u8], data: &[u8]) -> PyResult<()> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("iv must be 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("data must be multiple of 16"));
    }
    Ok(())
}

fn enc_raw(key: &[u8], iv: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    chk(key, iv, data)?;
    let aes = Aes256::new_from_slice(key).map_err(|_| PyValueError::new_err("bad key"))?;
    let mut x = iv[..16].to_vec();
    let mut y = iv[16..].to_vec();
    let mut out = Vec::with_capacity(data.len());
    for blk in data.chunks_exact(16) {
        let mut tmp = [0u8; 16];
        for i in 0..16 {
            tmp[i] = blk[i] ^ x[i];
        }
        let mut ga = GenericArray::clone_from_slice(&tmp);
        aes.encrypt_block(&mut ga);
        let mut c = [0u8; 16];
        for i in 0..16 {
            c[i] = ga[i] ^ y[i];
        }
        x.copy_from_slice(&c);
        y.copy_from_slice(blk);
        out.extend_from_slice(&c);
    }
    Ok(out)
}

fn dec_raw(key: &[u8], iv: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    chk(key, iv, data)?;
    let aes = Aes256::new_from_slice(key).map_err(|_| PyValueError::new_err("bad key"))?;
    let mut x = iv[..16].to_vec();
    let mut y = iv[16..].to_vec();
    let mut out = Vec::with_capacity(data.len());
    for blk in data.chunks_exact(16) {
        let mut tmp = [0u8; 16];
        for i in 0..16 {
            tmp[i] = blk[i] ^ y[i];
        }
        let mut ga = GenericArray::clone_from_slice(&tmp);
        aes.decrypt_block(&mut ga);
        let mut p = [0u8; 16];
        for i in 0..16 {
            p[i] = ga[i] ^ x[i];
        }
        x.copy_from_slice(blk);
        y.copy_from_slice(&p);
        out.extend_from_slice(&p);
    }
    Ok(out)
}

#[pyfunction]
fn aes_ige_enc(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    let raw = pad(data);
    enc_raw(key, iv, &raw)
}

#[pyfunction]
fn aes_ige_dec(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    let raw = dec_raw(key, iv, data)?;
    unpad(&raw)
}

#[pyfunction]
fn aes_ige_enc_raw(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    enc_raw(key, iv, data)
}

#[pyfunction]
fn aes_ige_dec_raw(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    dec_raw(key, iv, data)
}

#[pyfunction]
fn cut(py: Python<'_>, buf: &[u8]) -> PyResult<(Vec<Py<PyBytes>>, Py<PyBytes>)> {
    let mut i = 0usize;
    let mut out = Vec::new();
    while i + 4 <= buf.len() {
        let n = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        if n == 0 {
            return Err(PyValueError::new_err("zero frame"));
        }
        if i + 4 + n > buf.len() {
            break;
        }
        out.push(PyBytes::new(py, &buf[i + 4..i + 4 + n]).into());
        i += 4 + n;
    }
    Ok((out, PyBytes::new(py, &buf[i..]).into()))
}

#[pyfunction]
fn pack(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[pyfunction]
fn aes_gcm_encrypt(py: Python<'_>, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("nonce must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("bad key"))?;
    let n = Nonce::from_slice(nonce);
    let ct = cipher
        .encrypt(n, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|_| PyValueError::new_err("encryption failed"))?;
    Ok(PyBytes::new(py, &ct).into())
}

#[pyfunction]
fn aes_gcm_decrypt(py: Python<'_>, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("nonce must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("bad key"))?;
    let n = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(n, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| PyValueError::new_err("decryption failed (wrong key or corrupted data)"))?;
    Ok(PyBytes::new(py, &pt).into())
}

#[pymodule]
fn ext(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_ige_enc, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_dec, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_enc_raw, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ige_dec_raw, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cut, m)?)?;
    m.add_function(wrap_pyfunction!(pack, m)?)?;
    Ok(())
}
