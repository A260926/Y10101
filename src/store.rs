//! SQLite 持久化：密钥表 + 只追加信任事件日志 + 制品签名 + 批次/游标。
//!
//! 关键性质：
//! * trust_events 只追加；纠错写入新的 supersede 事件并回填 superseded_by；
//! * 相同 idem_key+内容返回原记录；idem_key 相同但内容不同 -> 冲突；
//! * 信任事件写入带 expected_version 乐观并发控制（meta.graph_version 单调递增）；
//! * 批次创建时冻结图摘要；逐条结果与游标在同一事务推进，崩溃可安全重放。

use crate::crypto;
use crate::error::{Error, Result};
use crate::types::{
    Clock, EventKind, EventRow, KeyRow, RevokeReason, SignatureRow, TimeSec, Usage,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
    passphrase: String,
    clock: Box<dyn Clock>,
}

/// 冻结的信任图（批次创建时刻）。events 只含当时有效（未被取代）事件。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrozenGraph {
    pub graph_version: i64,
    pub digest: String,
    pub events: Vec<EventRow>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchRow {
    pub id: String,
    pub frozen_json: String,
    pub graph_version: i64,
    pub graph_digest: String,
    pub created_at: TimeSec,
}

fn parse_usage(s: String) -> Usage {
    match s.as_str() {
        "root" => Usage::Root,
        "intermediate" => Usage::Intermediate,
        _ => Usage::Signing,
    }
}
fn parse_reason(s: Option<String>) -> Option<RevokeReason> {
    s.map(|v| {
        if v == "compromise" {
            RevokeReason::Compromise
        } else {
            RevokeReason::Superseded
        }
    })
}
fn parse_kind(s: String) -> EventKind {
    match s.as_str() {
        "root_anchor" => EventKind::RootAnchor,
        "rotation" => EventKind::Rotation,
        "revocation" => EventKind::Revocation,
        _ => EventKind::Supersede,
    }
}

fn row_to_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    let kind: String = r.get("kind")?;
    let reason: Option<String> = r.get("reason")?;
    Ok(EventRow {
        seq: r.get("seq")?,
        id: r.get("id")?,
        kind: parse_kind(kind),
        issuer_kid: r.get("issuer_kid")?,
        child_kid: r.get("child_kid")?,
        subject_kid: r.get("subject_kid")?,
        superseded_event: r.get("superseded_event")?,
        reason: parse_reason(reason),
        recorded_at: r.get("recorded_at")?,
        not_before: r.get("not_before")?,
        not_after: r.get("not_after")?,
        signature: r.get("signature")?,
        idem_key: r.get("idem_key")?,
        content_hash: r.get("content_hash")?,
        superseded_by: r.get("superseded_by")?,
        created_at: r.get("created_at")?,
    })
}

impl Store {
    pub fn open(path: &str, passphrase: &str, clock: Box<dyn Clock>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Store {
            conn: Mutex::new(conn),
            passphrase: passphrase.to_string(),
            clock,
        };
        store.migrate()?;
        Ok(store)
    }

    /// 测试用内存库。
    pub fn open_in_memory(passphrase: &str, clock: Box<dyn Clock>) -> Result<Store> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Store {
            conn: Mutex::new(conn),
            passphrase: passphrase.to_string(),
            clock,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let conn = self.conn.get_mut().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS keys (
                kid TEXT PRIMARY KEY,
                public_key TEXT NOT NULL UNIQUE,
                usage TEXT NOT NULL,
                encrypted_private TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                idem_key TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS trust_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                issuer_kid TEXT NOT NULL,
                child_kid TEXT,
                subject_kid TEXT,
                superseded_event TEXT,
                reason TEXT,
                recorded_at INTEGER,
                not_before INTEGER,
                not_after INTEGER,
                signature TEXT NOT NULL,
                idem_key TEXT UNIQUE,
                content_hash TEXT NOT NULL,
                superseded_by TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_issuer ON trust_events(issuer_kid);
            CREATE INDEX IF NOT EXISTS idx_events_child ON trust_events(child_kid);
            CREATE INDEX IF NOT EXISTS idx_events_subject ON trust_events(subject_kid);
            CREATE TABLE IF NOT EXISTS artifact_signatures (
                id TEXT PRIMARY KEY,
                kid TEXT NOT NULL,
                digest TEXT NOT NULL,
                signature TEXT NOT NULL,
                claimed_at INTEGER NOT NULL,
                idem_key TEXT UNIQUE,
                content_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batches (
                id TEXT PRIMARY KEY,
                frozen_json TEXT NOT NULL,
                graph_version INTEGER NOT NULL,
                graph_digest TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batch_items (
                batch_id TEXT NOT NULL,
                item_idx INTEGER NOT NULL,
                digest TEXT NOT NULL,
                kid TEXT NOT NULL,
                signature TEXT NOT NULL,
                claimed_at INTEGER NOT NULL,
                verify_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                PRIMARY KEY (batch_id, item_idx)
            );
            "#,
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('graph_version', 0)",
            [],
        )?;
        Ok(())
    }

    pub fn now(&self) -> TimeSec {
        self.clock.now()
    }

    pub fn graph_version(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT value FROM meta WHERE key='graph_version'",
            [],
            |r| r.get::<_, i64>(0),
        )?)
    }

    // ---------- 密钥 ----------

    /// 生成并登记本地演示密钥。返回内容只含公钥/key id（加密私钥仅入库）。
    pub fn create_key(&self, usage: Usage, idem_key: Option<String>) -> Result<KeyRow> {
        let now = self.now();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(ik) = idem_key.as_deref() {
            if let Some(row) = tx
                .query_row(
                    "SELECT kid, public_key, usage, created_at FROM keys WHERE idem_key=?1",
                    params![ik],
                    |r| {
                        let u: String = r.get(2)?;
                        Ok(KeyRow {
                            kid: r.get(0)?,
                            public_key: r.get(1)?,
                            usage: parse_usage(u),
                            created_at: r.get(3)?,
                        })
                    },
                )
                .optional()?
            {
                return Ok(row);
            }
        }
        // 极小概率碰撞时重试
        let gen = loop {
            let g = crypto::generate_key(&self.passphrase)?;
            let collision: i64 = tx.query_row(
                "SELECT COUNT(*) FROM keys WHERE kid=?1",
                params![g.kid],
                |r| r.get(0),
            )?;
            if collision == 0 {
                break g;
            }
        };
        tx.execute(
            "INSERT INTO keys(kid, public_key, usage, encrypted_private, created_at, idem_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                gen.kid,
                gen.public_hex,
                usage.as_str(),
                gen.encrypted_private,
                now,
                idem_key
            ],
        )?;
        tx.commit()?;
        Ok(KeyRow {
            kid: gen.kid,
            public_key: gen.public_hex,
            usage,
            created_at: now,
        })
    }

    pub fn key(&self, kid: &str) -> Result<KeyRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT kid, public_key, usage, created_at FROM keys WHERE kid=?1",
            params![kid],
            |r| {
                let usage: String = r.get(2)?;
                Ok(KeyRow {
                    kid: r.get(0)?,
                    public_key: r.get(1)?,
                    usage: parse_usage(usage),
                    created_at: r.get(3)?,
                })
            },
        )
        .map_err(|_| Error::NotFound(format!("未知 key id: {kid}")))
    }

    fn key_usage(&self, conn: &Connection, kid: &str) -> Result<Option<Usage>> {
        let v: Option<String> = conn
            .query_row("SELECT usage FROM keys WHERE kid=?1", params![kid], |r| {
                r.get(0)
            })
            .ok();
        Ok(v.map(parse_usage))
    }

    fn encrypted_private(&self, conn: &Connection, kid: &str) -> Result<String> {
        conn.query_row(
            "SELECT encrypted_private FROM keys WHERE kid=?1",
            params![kid],
            |r| r.get(0),
        )
        .map_err(|_| Error::NotFound(format!("未找到签名密钥: {kid}")))
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT kid, public_key, usage, created_at FROM keys ORDER BY created_at, kid",
        )?;
        let rows = stmt.query_map([], |r| {
            let usage: String = r.get(2)?;
            Ok(KeyRow {
                kid: r.get(0)?,
                public_key: r.get(1)?,
                usage: parse_usage(usage),
                created_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---------- 信任事件（只追加） ----------

    #[allow(clippy::too_many_arguments)]
    fn append_event_locked(
        &self,
        tx: &rusqlite::Transaction<'_>,
        kind: EventKind,
        issuer_kid: &str,
        child_kid: Option<&str>,
        subject_kid: Option<&str>,
        superseded_event: Option<&str>,
        reason: Option<RevokeReason>,
        recorded_at: Option<TimeSec>,
        not_before: Option<TimeSec>,
        not_after: Option<TimeSec>,
        signature: &str,
        idem_key: Option<&str>,
        content_hash: &str,
        expected_version: i64,
    ) -> Result<(EventRow, bool)> {
        let current: i64 = tx.query_row(
            "SELECT value FROM meta WHERE key='graph_version'",
            [],
            |r| r.get(0),
        )?;
        // -1 表示接受当前任意版本（种子/演示快捷操作使用）；正式并发仍需显式版本。
        let expected_version = if expected_version < 0 {
            current
        } else {
            expected_version
        };
        if expected_version != current {
            return Err(Error::Conflict(format!(
                "信任图版本冲突：期望 {expected_version}，当前 {current}，请重新拉取后再追加"
            )));
        }

        // 幂等：相同 idem_key + 相同内容 -> 返回原记录（不推进版本）。
        if let Some(ik) = idem_key {
            if let Some(existing_id) = tx
                .query_row::<String, _, _>(
                    "SELECT id FROM trust_events WHERE idem_key=?1",
                    params![ik],
                    |r| r.get(0),
                )
                .optional()?
            {
                if existing_id == content_event_id(content_hash) {
                    let row = tx.query_row(
                        "SELECT * FROM trust_events WHERE id=?1",
                        params![existing_id],
                        row_to_event,
                    )?;
                    return Ok((row, false));
                }
                return Err(Error::Conflict(format!("幂等键 {ik} 已用于不同内容")));
            }
        }

        let id = content_event_id(content_hash);
        let now = self.now();
        tx.execute(
            "INSERT INTO trust_events
             (id, kind, issuer_kid, child_kid, subject_kid, superseded_event, reason,
              recorded_at, not_before, not_after, signature, idem_key, content_hash, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                id,
                kind.as_str(),
                issuer_kid,
                child_kid,
                subject_kid,
                superseded_event,
                reason.map(|r| r.as_str()),
                recorded_at,
                not_before,
                not_after,
                signature,
                idem_key,
                content_hash,
                now
            ],
        )?;
        tx.execute(
            "UPDATE meta SET value=value+1 WHERE key='graph_version'",
            [],
        )?;
        let row = tx.query_row(
            "SELECT * FROM trust_events WHERE id=?1",
            params![id],
            row_to_event,
        )?;
        Ok((row, true))
    }

    fn ensure_key(&self, conn: &Connection, kid: &str, need: Usage) -> Result<Usage> {
        let u = self
            .key_usage(conn, kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知 key id: {kid}")))?;
        if u != need {
            return Err(Error::BadRequest(format!(
                "密钥 {kid} 用途为 {}，此处需要 {}",
                u.as_str(),
                need.as_str()
            )));
        }
        Ok(u)
    }

    fn sign_as(&self, conn: &Connection, kid: &str, msg: &[u8]) -> Result<String> {
        let enc = self.encrypted_private(conn, kid)?;
        crypto::sign_with_stored(&enc, &self.passphrase, msg)
    }

    /// 创建根锚点（root 自签）。
    pub fn anchor_root(
        &self,
        root_kid: &str,
        not_before: TimeSec,
        not_after: TimeSec,
        idem_key: Option<String>,
        expected_version: i64,
    ) -> Result<(EventRow, bool)> {
        if not_after < not_before {
            return Err(Error::BadRequest(
                "生效区间非法：not_after < not_before".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        self.ensure_key(&tx, root_kid, Usage::Root)?;
        let msg = crypto::root_anchor_message(root_kid, not_before, not_after);
        let sig = self.sign_as(&tx, root_kid, &msg)?;
        let canonical = format!("root_anchor|{root_kid}|{not_before}|{not_after}|{sig}");
        let hash = crypto::sha256_hex(canonical.as_bytes());
        self.append_event_locked(
            &tx,
            EventKind::RootAnchor,
            root_kid,
            None,
            None,
            None,
            None,
            None,
            Some(not_before),
            Some(not_after),
            &sig,
            idem_key.as_deref(),
            &hash,
            expected_version,
        )
        .and_then(|r| {
            tx.commit()?;
            Ok(r)
        })
    }
}

/// 事件 id 由其完整内容（含签名）决定，天然支持去重与幂等比较。
fn content_event_id(content_hash: &str) -> String {
    format!("ev_{}", &content_hash[..24])
}

impl Store {
    /// 追加轮换/中间证明。issuer 必须能签发证明；签名由本地私钥产生。
    pub fn rotate(
        &self,
        issuer_kid: &str,
        child_kid: &str,
        not_before: TimeSec,
        not_after: TimeSec,
        idem_key: Option<String>,
        expected_version: i64,
    ) -> Result<(EventRow, bool)> {
        if not_after < not_before {
            return Err(Error::BadRequest(
                "生效区间非法：not_after < not_before".into(),
            ));
        }
        if issuer_kid == child_kid {
            return Err(Error::BadRequest("轮换证明不能自签（根锚点除外）".into()));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let issuer_usage = self
            .key_usage(&tx, issuer_kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知签发者 key id: {issuer_kid}")))?;
        if !issuer_usage.can_issue_cert() {
            return Err(Error::BadRequest(format!(
                "密钥 {issuer_kid}（{}）不允许签发证明",
                issuer_usage.as_str()
            )));
        }
        let child_usage = self
            .key_usage(&tx, child_kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知子密钥 key id: {child_kid}")))?;
        if child_usage == Usage::Root {
            return Err(Error::BadRequest("轮换证明不能把 root 作为下级".into()));
        }
        let msg = crypto::rotation_message(
            issuer_kid,
            child_kid,
            child_usage.as_str(),
            not_before,
            not_after,
        );
        let sig = self.sign_as(&tx, issuer_kid, &msg)?;
        let canonical = format!(
            "rotation|{issuer_kid}|{child_kid}|{}|{not_before}|{not_after}|{sig}",
            child_usage.as_str()
        );
        let hash = crypto::sha256_hex(canonical.as_bytes());
        let r = self.append_event_locked(
            &tx,
            EventKind::Rotation,
            issuer_kid,
            Some(child_kid),
            None,
            None,
            None,
            None,
            Some(not_before),
            Some(not_after),
            &sig,
            idem_key.as_deref(),
            &hash,
            expected_version,
        )?;
        tx.commit()?;
        Ok(r)
    }

    /// 追加撤销事件。撤销必须由被撤销 key 的直接上级（在图上）签发；
    /// root 只能自撤销（compromise）。recorded_at 决定影响范围起点。
    pub fn revoke(
        &self,
        issuer_kid: &str,
        subject_kid: &str,
        reason: RevokeReason,
        recorded_at: TimeSec,
        idem_key: Option<String>,
        expected_version: i64,
    ) -> Result<(EventRow, bool)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let issuer_usage = self
            .key_usage(&tx, issuer_kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知签发者 key id: {issuer_kid}")))?;
        if self.key_usage(&tx, subject_kid)?.is_none() {
            return Err(Error::BadRequest(format!(
                "未知被撤销 key id: {subject_kid}"
            )));
        }
        if issuer_kid == subject_kid {
            if issuer_usage != Usage::Root {
                return Err(Error::BadRequest("只有 root 允许自撤销".into()));
            }
        } else if !issuer_usage.can_issue_cert() {
            return Err(Error::BadRequest(format!(
                "密钥 {issuer_kid} 无权撤销其他 key"
            )));
        }
        let msg = crypto::revocation_message(issuer_kid, subject_kid, reason.as_str(), recorded_at);
        let sig = self.sign_as(&tx, issuer_kid, &msg)?;
        let canonical = format!(
            "revocation|{issuer_kid}|{subject_kid}|{}|{recorded_at}|{sig}",
            reason.as_str()
        );
        let hash = crypto::sha256_hex(canonical.as_bytes());
        let r = self.append_event_locked(
            &tx,
            EventKind::Revocation,
            issuer_kid,
            None,
            Some(subject_kid),
            None,
            Some(reason),
            Some(recorded_at),
            None,
            None,
            &sig,
            idem_key.as_deref(),
            &hash,
            expected_version,
        )?;
        tx.commit()?;
        Ok(r)
    }

    /// 追加纠错事件：issuer 声明 target_event 被取代。只追加，不删除。
    pub fn supersede(
        &self,
        issuer_kid: &str,
        target_event_id: &str,
        recorded_at: TimeSec,
        idem_key: Option<String>,
        expected_version: i64,
    ) -> Result<(EventRow, bool)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let issuer_usage = self
            .key_usage(&tx, issuer_kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知签发者 key id: {issuer_kid}")))?;
        let target: EventRow = tx
            .query_row(
                "SELECT * FROM trust_events WHERE id=?1",
                params![target_event_id],
                row_to_event,
            )
            .map_err(|_| Error::NotFound(format!("未知事件 id: {target_event_id}")))?;
        if matches!(target.kind, EventKind::Supersede) {
            return Err(Error::BadRequest("不允许对纠错事件再纠错".into()));
        }
        if target.superseded_by.is_some() {
            return Err(Error::Conflict(format!(
                "事件 {target_event_id} 已被纠错取代"
            )));
        }
        // 只有原事件的签发者可以纠错它；root 锚点只能自己纠错。
        if target.issuer_kid != issuer_kid {
            return Err(Error::BadRequest(
                "只有原事件的签发者可以追加纠错事件".into(),
            ));
        }
        let _ = issuer_usage;
        let msg = crypto::supersede_message(issuer_kid, target_event_id, recorded_at);
        let sig = self.sign_as(&tx, issuer_kid, &msg)?;
        let canonical = format!("supersede|{issuer_kid}|{target_event_id}|{recorded_at}|{sig}");
        let hash = crypto::sha256_hex(canonical.as_bytes());
        let r = self.append_event_locked(
            &tx,
            EventKind::Supersede,
            issuer_kid,
            None,
            None,
            Some(target_event_id),
            None,
            Some(recorded_at),
            None,
            None,
            &sig,
            idem_key.as_deref(),
            &hash,
            expected_version,
        )?;
        tx.execute(
            "UPDATE trust_events SET superseded_by=?1 WHERE id=?2",
            params![r.0.id, target_event_id],
        )?;
        tx.commit()?;
        Ok(r)
    }

    pub fn list_events(&self) -> Result<Vec<EventRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM trust_events ORDER BY seq")?;
        let rows = stmt.query_map([], row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn event(&self, id: &str) -> Result<EventRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM trust_events WHERE id=?1",
            params![id],
            row_to_event,
        )
        .map_err(|_| Error::NotFound(format!("未知事件: {id}")))
    }

    // ---------- 制品签名 ----------

    /// 用本地保管的私钥对“摘要+声明签署时刻”签名。
    pub fn sign_artifact(
        &self,
        kid: &str,
        digest: &str,
        claimed_at: TimeSec,
        idem_key: Option<String>,
    ) -> Result<(SignatureRow, bool)> {
        let digest = digest.trim().to_lowercase();
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::BadRequest(
                "摘要必须是 64 位十六进制（sha256）".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let usage = self
            .key_usage(&tx, kid)?
            .ok_or_else(|| Error::BadRequest(format!("未知签名密钥: {kid}")))?;
        if usage == Usage::Root {
            return Err(Error::BadRequest(
                "root 密钥不允许直接签制品（key usage 不符）".into(),
            ));
        }
        if let Some(ik) = idem_key.as_deref() {
            if let Some(existing) = tx
                .query_row::<SignatureRow, _, _>(
                    "SELECT * FROM artifact_signatures WHERE idem_key=?1",
                    params![ik],
                    sig_row,
                )
                .optional()?
            {
                let same = existing.kid == kid
                    && existing.digest == digest
                    && existing.claimed_at == claimed_at;
                if !same {
                    return Err(Error::Conflict(format!("幂等键 {ik} 已用于不同的制品签名")));
                }
                return Ok((existing, false));
            }
        }
        let msg = crypto::artifact_message(&digest, claimed_at);
        let sig = self.sign_as(&tx, kid, &msg)?;
        let canonical = format!("artifact|{kid}|{digest}|{claimed_at}|{sig}");
        let hash = crypto::sha256_hex(canonical.as_bytes());
        let id = format!("sig_{}", &hash[..24]);
        let now = self.now();
        tx.execute(
            "INSERT INTO artifact_signatures(id, kid, digest, signature, claimed_at, idem_key, content_hash, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, kid, digest, sig, claimed_at, idem_key, hash, now],
        )?;
        let row = tx.query_row(
            "SELECT * FROM artifact_signatures WHERE id=?1",
            params![id],
            sig_row,
        )?;
        tx.commit()?;
        Ok((row, true))
    }

    pub fn list_signatures(&self) -> Result<Vec<SignatureRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM artifact_signatures ORDER BY created_at, id")?;
        let rows = stmt.query_map([], sig_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn sig_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SignatureRow> {
    Ok(SignatureRow {
        id: r.get("id")?,
        kid: r.get("kid")?,
        digest: r.get("digest")?,
        signature: r.get("signature")?,
        claimed_at: r.get("claimed_at")?,
        idem_key: r.get("idem_key")?,
        content_hash: r.get("content_hash")?,
        created_at: r.get("created_at")?,
    })
}

impl Store {
    // ---------- 信任图 / 冻结 ----------

    fn all_events_locked(conn: &Connection) -> Result<Vec<EventRow>> {
        let mut stmt = conn.prepare("SELECT * FROM trust_events ORDER BY seq")?;
        let rows = stmt.query_map([], row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 计算“有效”事件：supersede 事件把目标事件标记为取代（含传递闭包）。
    /// 冻结时根据当时已存在的 supersede 集合独立计算，保证批次内一致。
    pub fn active_events(events: &[EventRow]) -> Vec<EventRow> {
        let mut dead: std::collections::HashSet<String> = std::collections::HashSet::new();
        // 定点收敛（允许 A 纠错 B、B 纠错 C 的链式结构）。
        loop {
            let before = dead.len();
            for ev in events {
                if let (EventKind::Supersede, Some(target)) =
                    (ev.kind, ev.superseded_event.as_deref())
                {
                    // 纠错事件自身若已被（不可能，但保持一致）标记，则不生效
                    if dead.contains(&ev.id) {
                        continue;
                    }
                    dead.insert(target.to_string());
                }
            }
            if dead.len() == before {
                break;
            }
        }
        events
            .iter()
            .filter(|e| !dead.contains(&e.id) && !matches!(e.kind, EventKind::Supersede))
            .cloned()
            .collect()
    }

    /// 构建当前图快照。digest 对有效事件做规范化哈希，导入顺序变化不影响摘要。
    pub fn current_graph(&self) -> Result<FrozenGraph> {
        let conn = self.conn.lock().unwrap();
        let version = conn.query_row(
            "SELECT value FROM meta WHERE key='graph_version'",
            [],
            |r| r.get::<_, i64>(0),
        )?;
        let all = Self::all_events_locked(&conn)?;
        let active = Self::active_events(&all);
        let digest = Self::digest_events(&active);
        Ok(FrozenGraph {
            graph_version: version,
            digest,
            events: active,
        })
    }

    pub fn digest_events(events: &[EventRow]) -> String {
        // 按内容（非 seq）排序后哈希：同一语义图无论导入顺序摘要一致。
        let mut sorted: Vec<&EventRow> = events.iter().collect();
        sorted.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));
        let canonical: String = sorted
            .iter()
            .map(|e| e.content_hash.as_str())
            .collect::<Vec<_>>()
            .join("|");
        crypto::sha256_hex(canonical.as_bytes())
    }

    // ---------- 批次：冻结 + 逐项游标 ----------

    /// 创建批次：立刻冻结当前图；运行中新增撤销不影响本批（下一批生效）。
    pub fn create_batch(&self, items: Vec<BatchInput>) -> Result<String> {
        if items.is_empty() {
            return Err(Error::BadRequest("批次至少包含一条验证".into()));
        }
        let graph = self.current_graph()?;
        let frozen_json = serde_json::to_string(&graph).expect("graph 可序列化");
        let id = format!(
            "batch_{}",
            &crypto::sha256_hex(format!("{}|{}", graph.digest, self.now()).as_bytes())[..16]
        );
        let now = self.now();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO batches(id, frozen_json, graph_version, graph_digest, created_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![id, frozen_json, graph.graph_version, graph.digest, now],
        )?;
        for (idx, it) in items.iter().enumerate() {
            tx.execute(
                "INSERT INTO batch_items(batch_id, item_idx, digest, kid, signature, claimed_at, verify_at, status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'pending')",
                params![id, idx as i64, it.digest, it.kid, it.signature, it.claimed_at, it.verify_at],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn batch(&self, id: &str) -> Result<BatchRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, frozen_json, graph_version, graph_digest, created_at FROM batches WHERE id=?1",
            params![id],
            |r| {
                Ok(BatchRow {
                    id: r.get(0)?,
                    frozen_json: r.get(1)?,
                    graph_version: r.get(2)?,
                    graph_digest: r.get(3)?,
                    created_at: r.get(4)?,
                })
            },
        )
        .map_err(|_| Error::NotFound(format!("未知批次: {id}")))
    }

    pub fn frozen_graph(&self, id: &str) -> Result<FrozenGraph> {
        let row = self.batch(id)?;
        let graph: FrozenGraph = serde_json::from_str(&row.frozen_json)
            .map_err(|_| Error::Internal("冻结图反序列化失败".into()))?;
        Ok(graph)
    }

    /// 取出一批待处理条目（快照隔离）。
    pub fn pending_items(&self, batch_id: &str) -> Result<Vec<BatchItemRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT item_idx, digest, kid, signature, claimed_at, verify_at
             FROM batch_items WHERE batch_id=?1 AND status='pending' ORDER BY item_idx",
        )?;
        let rows = stmt.query_map(params![batch_id], |r| {
            Ok(BatchItemRecord {
                idx: r.get(0)?,
                digest: r.get(1)?,
                kid: r.get(2)?,
                signature: r.get(3)?,
                claimed_at: r.get(4)?,
                verify_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 提交单条结果并推进游标（同事务）。
    /// 已完成的条目返回 false，恢复重放时不会重复产出结果。
    pub fn commit_item(&self, batch_id: &str, idx: i64, result_json: &str) -> Result<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let affected = tx.execute(
            "UPDATE batch_items SET status='done', result_json=?1
             WHERE batch_id=?2 AND item_idx=?3 AND status='pending'",
            params![result_json, batch_id, idx],
        )?;
        tx.commit()?;
        Ok(affected == 1)
    }

    /// 测试钩子：在“计算结果”与“提交游标”之间制造崩溃窗口。
    pub fn crash_hook(&self) {
        if std::env::var("TRUSTPATH_CRASH_AT_COMMIT").is_ok() {
            // 立即退出且不运行析构：模拟单条结果提交前进程死亡。
            eprintln!("CRASH_HOOK: aborting between result computation and cursor commit");
            std::process::abort();
        }
    }

    pub fn item_results(&self, batch_id: &str) -> Result<Vec<Option<String>>> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM batch_items WHERE batch_id=?1",
            params![batch_id],
            |r| r.get(0),
        )?;
        let mut stmt = conn.prepare(
            "SELECT item_idx, result_json FROM batch_items WHERE batch_id=?1 ORDER BY item_idx",
        )?;
        let map = stmt.query_map(params![batch_id], |r| {
            Ok::<_, rusqlite::Error>((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        let mut out = vec![None; count as usize];
        for row in map {
            let (idx, json) = row?;
            out[idx as usize] = json;
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct BatchInput {
    pub digest: String,
    pub kid: String,
    pub signature: String,
    pub claimed_at: TimeSec,
    pub verify_at: TimeSec,
}

#[derive(Debug, Clone)]
pub struct BatchItemRecord {
    pub idx: i64,
    pub digest: String,
    pub kid: String,
    pub signature: String,
    pub claimed_at: TimeSec,
    pub verify_at: TimeSec,
}
