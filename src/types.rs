//! 领域类型：全程只以 key id / 公钥描述签名者，私钥字节不出现在这些结构中。

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix 秒，全部生效区间与“历史时刻”都使用它。
pub type TimeSec = i64;

/// 密钥用途（X.509 key usage 的极简版本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Usage {
    /// 根锚点：可签中间证明，也可撤销/轮换其下级。
    Root,
    /// 中间签名者：可签制品、下级证明、撤销/轮换。
    Intermediate,
    /// 末端制品签名密钥。
    Signing,
}

impl Usage {
    pub fn as_str(self) -> &'static str {
        match self {
            Usage::Root => "root",
            Usage::Intermediate => "intermediate",
            Usage::Signing => "signing",
        }
    }
    /// 是否允许签发“下级证明”（轮换/中间锚定）。
    pub fn can_issue_cert(self) -> bool {
        matches!(self, Usage::Root | Usage::Intermediate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    /// 私钥疑似泄露：影响范围从 recorded_at 起，不回溯抹掉泄露前的历史有效签名。
    Compromise,
    /// 主动轮换/被取代：影响范围从 recorded_at 起（前向），
    /// 与新轮换证明的 not_before 一起决定连续区间。
    Superseded,
}

impl RevokeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RevokeReason::Compromise => "compromise",
            RevokeReason::Superseded => "superseded",
        }
    }
}

/// 信任事件类型。所有事件只追加，纠错通过 `Supersede` 追加。
impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::RootAnchor => "root_anchor",
            EventKind::Rotation => "rotation",
            EventKind::Revocation => "revocation",
            EventKind::Supersede => "supersede",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// 根锚点：把一个 root 密钥锚定为信任起点。
    RootAnchor,
    /// 轮换/中间证明：issuer 在 [not_before, not_after] 内担保 child。
    Rotation,
    /// 撤销事件：issuer 撤销 subject，语义见 [`RevokeReason`]。
    Revocation,
    /// 纠错事件：声明另一个 trust 事件被取代（不删除旧记录）。
    Supersede,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRow {
    pub kid: String,
    pub public_key: String,
    pub usage: Usage,
    pub created_at: TimeSec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub seq: i64,
    pub id: String,
    pub kind: EventKind,
    pub issuer_kid: String,
    pub child_kid: Option<String>,
    pub subject_kid: Option<String>,
    pub superseded_event: Option<String>,
    pub reason: Option<RevokeReason>,
    pub recorded_at: Option<TimeSec>,
    pub not_before: Option<TimeSec>,
    pub not_after: Option<TimeSec>,
    pub signature: String,
    pub idem_key: Option<String>,
    pub content_hash: String,
    pub superseded_by: Option<String>,
    pub created_at: TimeSec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRow {
    pub id: String,
    pub kid: String,
    pub digest: String,
    pub signature: String,
    pub claimed_at: TimeSec,
    pub idem_key: Option<String>,
    pub content_hash: String,
    pub created_at: TimeSec,
}

/// 可注入时钟。
pub trait Clock: Send + Sync {
    fn now(&self) -> TimeSec;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> TimeSec {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as TimeSec)
            .unwrap_or(0)
    }
}

/// 测试时钟：可手动拨针。
#[derive(Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<TimeSec>>,
}
impl FakeClock {
    pub fn new(t: TimeSec) -> Self {
        Self {
            inner: Arc::new(Mutex::new(t)),
        }
    }
    pub fn set(&self, t: TimeSec) {
        *self.inner.lock().unwrap() = t;
    }
    pub fn advance(&self, secs: TimeSec) {
        *self.inner.lock().unwrap() += secs;
    }
}
impl Clock for FakeClock {
    fn now(&self) -> TimeSec {
        *self.inner.lock().unwrap()
    }
}

/// 把时间格式化为可读 UTC（页面用，不参与任何判定）。
pub fn fmt_time(t: TimeSec) -> String {
    // 2000-01-01T00:00:00Z 对应 946684800，做一个极小换算，避免引入时间库。
    let days = t.div_euclid(86400); // 自 1970-01-01 的天数
    let secs = t.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        mo,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

// Howard Hinnant 的 days -> civil 算法。
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::fmt_time;
    #[test]
    fn formats_known_epoch_values() {
        assert_eq!(fmt_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(fmt_time(1_700_000_700), "2023-11-14T22:25:00Z");
        assert_eq!(fmt_time(1_000_000_000), "2001-09-09T01:46:40Z");
    }
}
