//! 批量验证：批次创建时已冻结信任图；处理期间任何新增撤销/轮换都不影响本批。
//! 单条结果提交与游标推进在同一事务，进程退出后重放不会重复产出结果。

use crate::error::Result;
use crate::store::{BatchItemRecord, Store};
use crate::verify::{Engine, KeyInfo, VerifyReport};

#[derive(serde::Serialize)]
pub struct BatchRun {
    pub batch_id: String,
    pub graph_digest: String,
    pub graph_version: i64,
    pub total: usize,
    pub processed_now: usize,
    pub already_done: usize,
    pub remaining: usize,
    pub results: Vec<VerifyReport>,
}

/// 处理（或恢复处理）一个批次。重复调用是安全的：已完成条目直接跳过。
pub fn run_batch(store: &Store, batch_id: &str) -> Result<BatchRun> {
    let frozen = store.frozen_graph(batch_id)?;
    let pending: Vec<BatchItemRecord> = store.pending_items(batch_id)?;
    let all_stored = store.item_results(batch_id)?;
    let already_done = all_stored.iter().filter(|r| r.is_some()).count();
    let total = all_stored.len();

    let keys = store.list_keys()?;
    let key_infos: Vec<KeyInfo> = keys
        .into_iter()
        .map(|k| KeyInfo {
            kid: k.kid,
            public_hex: k.public_key,
            usage: k.usage,
        })
        .collect();

    let engine = Engine::new(frozen.clone(), key_infos);
    let mut results: Vec<VerifyReport> = Vec::new();
    let mut processed_now = 0usize;

    for item in &pending {
        // 测试用崩溃窗口：结果已算出但游标尚未提交。
        store.crash_hook();
        let report = engine.verify(
            &item.digest,
            &item.kid,
            &item.signature,
            item.claimed_at,
            item.verify_at,
        );
        let json = serde_json::to_string(&report).expect("report 可序列化");
        let committed = store.commit_item(batch_id, item.idx, &json)?;
        if committed {
            processed_now += 1;
        }
        results.push(report);
    }

    // 返回最终全部结果（含此前已完成项，便于恢复后展示一致视图）。
    let stored = store.item_results(batch_id)?;
    let mut all = Vec::new();
    for j in stored.into_iter().flatten() {
        let rep: VerifyReport = serde_json::from_str(&j).expect("存档结果可反序列化");
        all.push(rep);
    }

    Ok(BatchRun {
        batch_id: batch_id.to_string(),
        graph_digest: frozen.digest,
        graph_version: frozen.graph_version,
        total,
        processed_now,
        already_done,
        remaining: pending.len().saturating_sub(processed_now),
        results: all,
    })
}
