//! 预置演示场景（时间轴固定，演示结果不受机器当前时间影响）。
//!
//! 时间点（Unix 秒）：
//!   T1=1_700_000_000  根锚点生效起点
//!   T2=+100           根 -> 中间证明
//!   T3=+200           中间 -> 制品签名密钥
//!   T4=+300           制品 A 被签名
//!   T5=+400           制品 B（轮换断档后的旧密钥）被签名
//!   T6=+500           中间密钥轮换新证明（重叠轮换）
//!   T7=+600           旧中间密钥被记录 compromise
//!   T8=+700           验证时刻一（compromise 之后）
//!   T9=+450           验证时刻零（compromise 之前，仍 current-trusted）
//!
//! 另有一个“孤儿”签名密钥：故意不给它上级证明，用于演示 incomplete -> 补齐 -> trusted。

use crate::store::{BatchInput, Store};
use crate::types::{KeyRow, RevokeReason, SignatureRow, Usage};

pub const T1: i64 = 1_700_000_000;
pub const T2: i64 = T1 + 100;
pub const T3: i64 = T1 + 200;
pub const T4: i64 = T1 + 300;
pub const T5: i64 = T1 + 400;
pub const T6: i64 = T1 + 500;
pub const T7: i64 = T1 + 600;
pub const VERIFY_AFTER: i64 = T1 + 700;
pub const VERIFY_BEFORE: i64 = T1 + 450;

pub const DIGEST_A: &str = "a171ce0000000000000000000000000000000000000000000000000000000001";
pub const DIGEST_B: &str = "b0b5000000000000000000000000000000000000000000000000000000000002";
pub const DIGEST_ORPHAN: &str = "0770a40000000000000000000000000000000000000000000000000000000003";

#[derive(Clone)]
pub struct SeedIds {
    pub root: KeyRow,
    pub intermediate: KeyRow,
    pub leaf: KeyRow,
    pub intermediate2: KeyRow,
    pub orphan: KeyRow,
    pub sig_a: SignatureRow,
    pub sig_b: SignatureRow,
    pub sig_orphan: SignatureRow,
}

pub fn is_seeded(store: &Store) -> bool {
    store
        .list_events()
        .map(|evs| {
            evs.iter()
                .any(|e| e.idem_key.as_deref() == Some("seed:anchor:r1"))
        })
        .unwrap_or(false)
}

/// 幂等预置；expected_version 传 -1 表示接受任意当前版本（仅种子使用）。
pub fn seed(store: &Store) -> crate::error::Result<SeedIds> {
    let root = store.create_key(Usage::Root, Some("seed:key:root".into()))?;
    let intermediate =
        store.create_key(Usage::Intermediate, Some("seed:key:intermediate".into()))?;
    let leaf = store.create_key(Usage::Signing, Some("seed:key:leaf".into()))?;
    let intermediate2 =
        store.create_key(Usage::Intermediate, Some("seed:key:intermediate2".into()))?;
    let orphan = store.create_key(Usage::Signing, Some("seed:key:orphan".into()))?;

    // 根锚点覆盖很长区间。
    store.anchor_root(
        &root.kid,
        T1,
        T1 + 10_000,
        Some("seed:anchor:r1".into()),
        -1,
    )?;

    // 根 -> 中间 I（区间 T2..T6-1，结束于轮换点之后不久前）
    store.rotate(
        &root.kid,
        &intermediate.kid,
        T2,
        T1 + 10_000,
        Some("seed:rotation:r-i1".into()),
        -1,
    )?;
    // 重叠轮换：中间 I2 在 T6 前后与 I 重叠（测试 overlapping rotation）
    store.rotate(
        &root.kid,
        &intermediate2.kid,
        T1 + 450,
        T1 + 10_000,
        Some("seed:rotation:r-i2".into()),
        -1,
    )?;
    // I -> leaf L（宽区间）
    store.rotate(
        &intermediate.kid,
        &leaf.kid,
        T3,
        T1 + 10_000,
        Some("seed:rotation:i1-l".into()),
        -1,
    )?;

    // T7 记录 I 被 compromise（影响范围从 T7 起，不回溯）
    store.revoke(
        &root.kid,
        &intermediate.kid,
        RevokeReason::Compromise,
        T7,
        Some("seed:revoke:i1-compromise".into()),
        -1,
    )?;

    // 制品签名
    let sig_a = store
        .sign_artifact(&leaf.kid, DIGEST_A, T4, Some("seed:sig:a".into()))?
        .0;
    // B：leaf 在 T5 签署（与 A 同一路径），用于另一组验证时刻对比
    let sig_b = store
        .sign_artifact(&leaf.kid, DIGEST_B, T5, Some("seed:sig:b".into()))?
        .0;
    // orphan：无任何证明
    let sig_orphan = store
        .sign_artifact(
            &orphan.kid,
            DIGEST_ORPHAN,
            T4,
            Some("seed:sig:orphan".into()),
        )?
        .0;

    Ok(SeedIds {
        root,
        intermediate,
        leaf,
        intermediate2,
        orphan,
        sig_a,
        sig_b,
        sig_orphan,
    })
}

/// 预置演示批次（同时在两个时刻验证制品 A）。
pub fn demo_batch_inputs(ids: &SeedIds) -> Vec<BatchInput> {
    vec![
        BatchInput {
            digest: DIGEST_A.into(),
            kid: ids.leaf.kid.clone(),
            signature: ids.sig_a.signature.clone(),
            claimed_at: T4,
            verify_at: VERIFY_BEFORE,
        },
        BatchInput {
            digest: DIGEST_A.into(),
            kid: ids.leaf.kid.clone(),
            signature: ids.sig_a.signature.clone(),
            claimed_at: T4,
            verify_at: VERIFY_AFTER,
        },
        BatchInput {
            digest: DIGEST_ORPHAN.into(),
            kid: ids.orphan.kid.clone(),
            signature: ids.sig_orphan.signature.clone(),
            claimed_at: T4,
            verify_at: VERIFY_AFTER,
        },
    ]
}
