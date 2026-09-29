//! 签名信任路径实验台 —— 服务库。
//! 私钥仅以加密信封保存在 SQLite 中；API/日志/导出只暴露 key id 与公钥。

pub mod batch;
pub mod crypto;
pub mod error;
pub mod log;
pub mod seed;
pub mod store;
pub mod types;
pub mod ui_page;
pub mod verify;
pub mod web;

use error::Result;
use store::Store;
use verify::{Engine, KeyInfo, VerifyReport};

/// 在“当前信任图”上做单条验证。
pub fn verify_once(
    store: &Store,
    digest: &str,
    kid: &str,
    signature: &str,
    claimed_at: types::TimeSec,
    verify_at: types::TimeSec,
) -> Result<VerifyReport> {
    let graph = store.current_graph()?;
    let keys = store
        .list_keys()?
        .into_iter()
        .map(|k| KeyInfo {
            kid: k.kid,
            public_hex: k.public_key,
            usage: k.usage,
        })
        .collect();
    Ok(Engine::new(graph, keys).verify(digest, kid, signature, claimed_at, verify_at))
}
