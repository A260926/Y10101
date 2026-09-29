//! 本地演示用密码学：
//! - Ed25519 签名（制品 / 证明 / 撤销 / 根锚点同一套）；
//! - key id = sha256(公钥) 的前 16 字节十六进制；
//! - 私钥使用 PBKDF2(pass) -> AES-256-GCM 加密落盘，明文私钥从不离开本模块调用栈。

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pbkdf2::pbkdf2_hmac_array;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const PBKDF2_ROUNDS: u32 = 120_000;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn kid_of(public_hex: &str) -> Result<String> {
    let raw =
        hex::decode(public_hex).map_err(|_| Error::BadRequest("公钥必须是十六进制".into()))?;
    if raw.len() != 32 {
        return Err(Error::BadRequest("公钥长度必须为 32 字节".into()));
    }
    Ok(sha256_hex(&raw)[..32].to_string())
}

pub struct GeneratedKey {
    pub kid: String,
    pub public_hex: String,
    /// 已加密的私钥信封（base64），仅供存储层保管。
    pub encrypted_private: String,
}

pub fn generate_key(passphrase: &str) -> Result<GeneratedKey> {
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let public_hex = hex::encode(signing.verifying_key().to_bytes());
    let kid = kid_of(&public_hex)?;
    let encrypted_private = encrypt_private(&signing.to_bytes(), passphrase)?;
    Ok(GeneratedKey {
        kid,
        public_hex,
        encrypted_private,
    })
}

pub fn encrypt_private(secret: &[u8; 32], passphrase: &str) -> Result<String> {
    let salt = rand::random::<[u8; 16]>();
    let nonce_bytes = rand::random::<[u8; 12]>();
    let key = pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), &salt, PBKDF2_ROUNDS);
    let cipher = Aes256Gcm::new(&key.into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_ref())
        .map_err(|_| Error::Crypto("私钥加密失败".into()))?;
    let mut envelope = Vec::with_capacity(16 + 12 + ct.len());
    envelope.extend_from_slice(b"v1");
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(&envelope))
}

fn decrypt_private(envelope_b64: &str, passphrase: &str) -> Result<[u8; 32]> {
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(envelope_b64)
        .map_err(|_| Error::Crypto("私钥信封格式错误".into()))?;
    if envelope.len() < 2 + 16 + 12 + 16 || &envelope[..2] != b"v1" {
        return Err(Error::Crypto("私钥信封版本/长度错误".into()));
    }
    let salt = &envelope[2..18];
    let nonce_bytes = &envelope[18..30];
    let ct = &envelope[30..];
    let key = pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), salt, PBKDF2_ROUNDS);
    let cipher = Aes256Gcm::new(&key.into());
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| Error::Crypto("私钥解密失败（口令错误或信封损坏）".into()))?;
    pt.try_into()
        .map_err(|_| Error::Crypto("私钥长度错误".into()))
}

fn signing_key(encrypted: &str, passphrase: &str) -> Result<SigningKey> {
    let bytes = decrypt_private(encrypted, passphrase)?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// 用本地保管的加密私钥签名。明文私钥不返回、不落日志。
pub fn sign_with_stored(encrypted: &str, passphrase: &str, msg: &[u8]) -> Result<String> {
    let sk = signing_key(encrypted, passphrase)?;
    Ok(hex::encode(sk.sign(msg).to_bytes()))
}

pub fn verify_hex(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pub_raw) = hex::decode(public_hex) else {
        return false;
    };
    let Ok(sig_raw) = hex::decode(sig_hex) else {
        return false;
    };
    if pub_raw.len() != 32 || sig_raw.len() != 64 {
        return false;
    }
    let mut vk_bytes = [0u8; 32];
    vk_bytes.copy_from_slice(&pub_raw);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_raw);
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(msg, &sig).is_ok()
}

/// 制品签名绑定：摘要 + 声明签署时刻（防止拿同一签名去套别的声称时间）。
pub fn artifact_message(digest_hex: &str, claimed_at: i64) -> Vec<u8> {
    format!("trustpath-artifact-v1\ndigest={digest_hex}\nclaimed_at={claimed_at}\n").into_bytes()
}

/// 根锚点：root 自行声明信任锚与生效区间。
pub fn root_anchor_message(kid: &str, not_before: i64, not_after: i64) -> Vec<u8> {
    format!("trustpath-root-anchor-v1\nkid={kid}\nnot_before={not_before}\nnot_after={not_after}\n")
        .into_bytes()
}

/// 轮换/中间证明：issuer 在区间内担保 child（含 child 用途）。
pub fn rotation_message(
    issuer: &str,
    child: &str,
    child_usage: &str,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    format!(
        "trustpath-rotation-v1\nissuer={issuer}\nchild={child}\nchild_usage={child_usage}\nnot_before={not_before}\nnot_after={not_after}\n"
    )
    .into_bytes()
}

/// 撤销：撤销人、被撤销 key、原因、记录时刻（决定影响范围起点）。
pub fn revocation_message(issuer: &str, subject: &str, reason: &str, recorded_at: i64) -> Vec<u8> {
    format!(
        "trustpath-revocation-v1\nissuer={issuer}\nsubject={subject}\nreason={reason}\nrecorded_at={recorded_at}\n"
    )
    .into_bytes()
}

/// 纠错：issuer 声明某事件被取代。
pub fn supersede_message(issuer: &str, target_event: &str, recorded_at: i64) -> Vec<u8> {
    format!(
        "trustpath-supersede-v1\nissuer={issuer}\ntarget_event={target_event}\nrecorded_at={recorded_at}\n"
    )
    .into_bytes()
}
