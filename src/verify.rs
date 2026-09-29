//! 信任路径验证引擎。
//!
//! 输入：制品摘要、签名、声明签署时刻 claimed_at、验证时刻 verify_at。
//! 引擎枚举从签名者到根锚点的所有可能路径，逐条检查：
//!   1. 签名（制品签名、每个证明、每个撤销）；
//!   2. key usage（root/intermediate/signing 各自能做什么）；
//!   3. 生效区间（签署时刻必须落在区间内；验证时刻决定 current / historical）；
//!   4. 轮换连续性（相邻证明区间必须相交）；
//!   5. 撤销语义（compromise 与 superseded 都只从 recorded_at 起生效，不回溯）。
//!
//! 缺中间证明 => incomplete（补齐后可变成 trusted），与密码学意义上的 invalid 严格区分。

use crate::crypto;
use crate::store::FrozenGraph;
use crate::types::{fmt_time, EventKind, EventRow, RevokeReason, TimeSec, Usage};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Trusted,
    Historical,
    Invalid,
    Incomplete,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Trusted => "trusted",
            Verdict::Historical => "historical",
            Verdict::Invalid => "invalid",
            Verdict::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Step {
    pub check: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Link {
    pub kid: String,
    pub usage: String,
    pub role: String, // leaf | intermediate | root
    pub event_id: String,
    pub kind: String,
    pub not_before: Option<TimeSec>,
    pub not_after: Option<TimeSec>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PathReport {
    pub status: String, // trusted | historical | invalid | incomplete
    pub chain: Vec<Link>,
    pub root_kid: Option<String>,
    pub gap_kid: Option<String>,
    pub steps: Vec<Step>,
    pub rank_key: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyInfo {
    pub kid: String,
    pub public_hex: String,
    pub usage: Usage,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    pub verdict: Verdict,
    pub summary: String,
    pub digest: String,
    pub signer_kid: String,
    pub claimed_at: TimeSec,
    pub verify_at: TimeSec,
    pub graph_digest: String,
    pub global_steps: Vec<Step>,
    pub adopted: Option<PathReport>,
    pub rejected: Vec<PathReport>,
}

struct RawChain {
    /// 叶子 -> ... -> 紧邻根的证明，每个元素为 rotation 事件。
    edge_events: Vec<EventRow>,
    anchor: Option<EventRow>,
    /// 缺少证明的 key（向上找不到 rotation/anchor）。
    gap: Option<String>,
    gap_reason: String,
}

pub struct Engine {
    keys: BTreeMap<String, KeyInfo>,
    anchors: BTreeMap<String, Vec<EventRow>>,     // root kid
    edges: BTreeMap<String, Vec<EventRow>>,       // child kid
    revocations: BTreeMap<String, Vec<EventRow>>, // subject kid
    pub graph_digest: String,
}

fn t(t: TimeSec) -> String {
    format!("{} ({})", t, fmt_time(t))
}

impl Engine {
    pub fn new(graph: FrozenGraph, keys: Vec<KeyInfo>) -> Self {
        let mut keymap = BTreeMap::new();
        for k in keys {
            keymap.insert(k.kid.clone(), k);
        }
        let mut anchors: BTreeMap<String, Vec<EventRow>> = BTreeMap::new();
        let mut edges: BTreeMap<String, Vec<EventRow>> = BTreeMap::new();
        let mut revocations: BTreeMap<String, Vec<EventRow>> = BTreeMap::new();
        for ev in graph.events {
            match ev.kind {
                EventKind::RootAnchor => anchors.entry(ev.issuer_kid.clone()).or_default().push(ev),
                EventKind::Rotation => {
                    if let Some(child) = ev.child_kid.clone() {
                        edges.entry(child).or_default().push(ev);
                    }
                }
                EventKind::Revocation => {
                    if let Some(subject) = ev.subject_kid.clone() {
                        revocations.entry(subject).or_default().push(ev);
                    }
                }
                EventKind::Supersede => {}
            }
        }
        // 固定排序：同内容去重、按签发者与内容哈希。导入顺序不影响结果。
        for v in anchors.values_mut() {
            v.sort_by(|a, b| {
                a.issuer_kid
                    .cmp(&b.issuer_kid)
                    .then_with(|| a.content_hash.cmp(&b.content_hash))
            });
            v.dedup_by(|a, b| a.id == b.id);
        }
        for v in edges.values_mut() {
            v.sort_by(|a, b| {
                a.issuer_kid
                    .cmp(&b.issuer_kid)
                    .then_with(|| a.content_hash.cmp(&b.content_hash))
            });
            v.dedup_by(|a, b| a.id == b.id);
        }
        for v in revocations.values_mut() {
            v.sort_by(|a, b| a.recorded_at.cmp(&b.recorded_at).then(a.id.cmp(&b.id)));
            v.dedup_by(|a, b| a.id == b.id);
        }
        Engine {
            keys: keymap,
            anchors,
            edges,
            revocations,
            graph_digest: graph.digest,
        }
    }

    /// 验证入口。
    pub fn verify(
        &self,
        digest: &str,
        signer_kid: &str,
        signature_hex: &str,
        claimed_at: TimeSec,
        verify_at: TimeSec,
    ) -> VerifyReport {
        let digest = digest.trim().to_lowercase();
        let mut global = Vec::new();

        // 0) 输入时间关系
        if claimed_at > verify_at {
            global.push(Step {
                check: "时间关系".into(),
                ok: false,
                detail: format!(
                    "声明签署时刻 {} 晚于验证时刻 {}，不接受未来签署",
                    t(claimed_at),
                    t(verify_at)
                ),
            });
            return self.finalize(
                Verdict::Invalid,
                digest,
                signer_kid,
                claimed_at,
                verify_at,
                global,
                vec![],
            );
        }

        // 1) 制品签名必须由声明签名者公钥验证通过，且绑定 claimed_at。
        let signer = self.keys.get(signer_kid);
        let artifact_msg = crypto::artifact_message(&digest, claimed_at);
        let sig_ok = match signer {
            Some(k) => crypto::verify_hex(&k.public_hex, &artifact_msg, signature_hex),
            None => false,
        };
        if signer.is_none() {
            global.push(Step {
                check: "签名者存在".into(),
                ok: false,
                detail: format!("key id {signer_kid} 在信任图引用的密钥表中不存在"),
            });
            return self.finalize(
                Verdict::Invalid,
                digest,
                signer_kid,
                claimed_at,
                verify_at,
                global,
                vec![],
            );
        }
        global.push(Step {
            check: "制品签名".into(),
            ok: sig_ok,
            detail: if sig_ok {
                format!(
                    "用 {} 的公钥验证 sig 成功；签名负载绑定 digest 与声明签署时刻 {}",
                    signer_kid, t(claimed_at)
                )
            } else {
                "公钥验证失败：签名不是由该 key 对 (digest, claimed_at) 所签（摘要不匹配、签名被改或声称时间被改都会失败）".into()
            },
        });
        if !sig_ok {
            return self.finalize(
                Verdict::Invalid,
                digest,
                signer_kid,
                claimed_at,
                verify_at,
                global,
                vec![],
            );
        }

        // 2) key usage：root 不能直接签制品。
        let leaf_usage = signer.unwrap().usage;
        let usage_ok = leaf_usage != Usage::Root;
        global.push(Step {
            check: "key usage（末端）".into(),
            ok: usage_ok,
            detail: format!(
                "签名者 {} 用途为 {}；{}",
                signer_kid,
                leaf_usage.as_str(),
                if usage_ok {
                    "允许签制品"
                } else {
                    "root 锚点密钥不允许直接签制品"
                }
            ),
        });
        if !usage_ok {
            return self.finalize(
                Verdict::Invalid,
                digest,
                signer_kid,
                claimed_at,
                verify_at,
                global,
                vec![],
            );
        }

        // 3) 枚举所有原始路径（含缺口路径）并逐一评估。
        let raws = self.enumerate(signer_kid);
        let mut reports: Vec<PathReport> = raws
            .into_iter()
            .map(|raw| self.evaluate_path(raw, signer_kid, claimed_at, verify_at))
            .collect();
        // 内容完全相同的路径（同事件集合）去重。
        reports.sort_by_key(|a| a.rank_key.join(","));
        reports.dedup_by(|a, b| a.rank_key == b.rank_key);

        self.finalize(
            Verdict::Invalid,
            digest,
            signer_kid,
            claimed_at,
            verify_at,
            global,
            reports,
        )
    }

    // ---------- 路径枚举 ----------

    fn enumerate(&self, leaf: &str) -> Vec<RawChain> {
        let mut out = Vec::new();
        self.dfs(leaf, &[], &mut BTreeSet::new(), &mut out);
        if out.is_empty() {
            out.push(RawChain {
                edge_events: Vec::new(),
                anchor: None,
                gap: Some(leaf.to_string()),
                gap_reason: "签名者既无入向轮换证明也不是根锚点".into(),
            });
        }
        out
    }

    fn dfs(
        &self,
        kid: &str,
        edges_so_far: &[EventRow],
        visited: &mut BTreeSet<String>,
        out: &mut Vec<RawChain>,
    ) {
        if !self.keys.contains_key(kid) {
            out.push(RawChain {
                edge_events: edges_so_far.to_vec(),
                anchor: None,
                gap: Some(kid.to_string()),
                gap_reason: format!("key id {kid} 在密钥表中不存在（中间证明指向未知密钥）"),
            });
            return;
        }
        let mut produced = false;
        if let Some(anchors) = self.anchors.get(kid) {
            for anchor in anchors {
                produced = true;
                out.push(RawChain {
                    edge_events: edges_so_far.to_vec(),
                    anchor: Some(anchor.clone()),
                    gap: None,
                    gap_reason: String::new(),
                });
            }
        }
        if let Some(incoming) = self.edges.get(kid) {
            for edge in incoming {
                let issuer = edge.issuer_kid.clone();
                if visited.contains(&issuer) {
                    out.push(RawChain {
                        edge_events: edges_so_far.to_vec(),
                        anchor: None,
                        gap: Some(issuer),
                        gap_reason: "证明链出现环，无法到达锚点".into(),
                    });
                    continue;
                }
                produced = true;
                let mut next = edges_so_far.to_vec();
                next.push(edge.clone());
                visited.insert(kid.to_string());
                self.dfs(&issuer, &next, visited, out);
                visited.remove(kid);
            }
        }
        if !produced {
            out.push(RawChain {
                edge_events: edges_so_far.to_vec(),
                anchor: None,
                gap: Some(kid.to_string()),
                gap_reason: format!("缺少 {kid} 的上级证明或根锚点（导入中间证明后可补齐）"),
            });
        }
    }

    // ---------- 单路径评估 ----------

    fn evaluate_path(
        &self,
        raw: RawChain,
        leaf: &str,
        claimed_at: TimeSec,
        verify_at: TimeSec,
    ) -> PathReport {
        let mut steps = Vec::new();
        let mut chain: Vec<Link> = Vec::new();
        let mut rank = vec!["trusted".to_string()];

        // 缺口路径：路径本身不算密码学失败 -> incomplete。
        if raw.anchor.is_none() {
            let gap = raw.gap.clone().unwrap_or_else(|| "?".into());
            for ev in &raw.edge_events {
                if let Some(child) = &ev.child_kid {
                    if let Some(k) = self.keys.get(child) {
                        chain.push(Link {
                            kid: child.clone(),
                            usage: k.usage.as_str().into(),
                            role: role_for(k.usage),
                            event_id: ev.id.clone(),
                            kind: ev.kind.as_str().into(),
                            not_before: ev.not_before,
                            not_after: ev.not_after,
                        });
                    }
                }
            }
            steps.push(Step {
                check: "路径完整性".into(),
                ok: false,
                detail: format!(
                    "incomplete：{}。补齐缺失的中间证明或根锚点后可重新评估",
                    raw.gap_reason
                ),
            });
            rank[0] = "incomplete".to_string();
            rank.push("9999".to_string());
            rank.push(gap.clone());
            return PathReport {
                status: "incomplete".into(),
                chain,
                root_kid: None,
                gap_kid: Some(gap),
                steps,
                rank_key: rank,
            };
        }

        let anchor = raw.anchor.unwrap();
        let mut invalid = false;
        let mut historical_only = false;
        let mut revoked_note: Option<String> = None;

        // 链上每个 key（叶子 -> 根）与证明。
        // rotation 事件的 child 依次是当前 key，issuer 是上级。
        let mut current_kid = leaf.to_string();

        // 末端 revocation 检查（在 claimed_at / verify_at 两个时刻）。
        let leaf_rev = self.check_revocation(
            &current_kid,
            &anchor.issuer_kid,
            leaf,
            claimed_at,
            verify_at,
            &mut steps,
        );
        match leaf_rev {
            RevVerdict::InvalidCurrent | RevVerdict::InvalidAtSigning => invalid = true,
            RevVerdict::Historical(note) => {
                historical_only = true;
                revoked_note = Some(note);
            }
            RevVerdict::Ok | RevVerdict::NoRevocation | RevVerdict::Ignored => {}
        }

        let mut prev_nb: Option<TimeSec> = None;
        let mut prev_na: Option<TimeSec> = None;

        for (i, edge) in raw.edge_events.iter().enumerate() {
            let child_kid = edge.child_kid.clone().unwrap_or_default();
            let issuer_kid = edge.issuer_kid.clone();
            let child_key = self.keys.get(&child_kid);
            let issuer_key = self.keys.get(&issuer_kid);
            let tag = format!("证明#{} {} <- {}", i + 1, issuer_kid, child_kid);

            // 签名验证
            let child_usage = child_key.map(|k| k.usage).unwrap_or(Usage::Signing);
            let nb = edge.not_before.unwrap_or(0);
            let na = edge.not_after.unwrap_or(0);
            let msg =
                crypto::rotation_message(&issuer_kid, &child_kid, child_usage.as_str(), nb, na);
            let sig_ok = issuer_key
                .map(|k| crypto::verify_hex(&k.public_hex, &msg, &edge.signature))
                .unwrap_or(false);
            steps.push(Step {
                check: format!("{tag}：签名"),
                ok: sig_ok,
                detail: if sig_ok {
                    format!("用签发者 {} 的公钥验证轮换证明签名成功", issuer_kid)
                } else {
                    format!(
                        "轮换证明签名验证失败（可能不是 {} 所签或内容被改）",
                        issuer_kid
                    )
                },
            });
            if !sig_ok {
                invalid = true;
            }

            // key usage
            let issuer_can = issuer_key
                .map(|k| k.usage.can_issue_cert())
                .unwrap_or(false);
            let child_role_ok = child_key.map(|k| k.usage != Usage::Root).unwrap_or(false);
            let usage_ok = issuer_can && child_role_ok;
            steps.push(Step {
                check: format!("{tag}：key usage"),
                ok: usage_ok,
                detail: format!(
                    "签发者 {} 用途={}（能否签证明：{}）；下级 {} 用途={}（{}）",
                    issuer_kid,
                    issuer_key.map(|k| k.usage.as_str()).unwrap_or("未知"),
                    issuer_can,
                    child_kid,
                    child_key.map(|k| k.usage.as_str()).unwrap_or("未知"),
                    if child_role_ok {
                        "非 root，允许被担保"
                    } else {
                        "root 不能作为下级"
                    }
                ),
            });
            if !usage_ok {
                invalid = true;
            }

            // 生效区间（签署时刻）
            let in_claim = claimed_at >= nb && claimed_at <= na;
            steps.push(Step {
                check: format!("{tag}：生效区间@签署"),
                ok: in_claim,
                detail: format!(
                    "区间 [{} , {}]，声明签署时刻 {} {}",
                    t(nb),
                    t(na),
                    t(claimed_at),
                    if in_claim {
                        "在区间内"
                    } else {
                        "不在区间内"
                    }
                ),
            });
            if !in_claim {
                invalid = true;
            }

            // 生效区间（验证时刻）
            let in_verify = verify_at >= nb && verify_at <= na;
            steps.push(Step {
                check: format!("{tag}：生效区间@验证"),
                ok: in_verify,
                detail: format!(
                    "验证时刻 {} {}该证明区间；{}",
                    t(verify_at),
                    if in_verify { "仍在" } else { "已不在" },
                    if in_verify {
                        "当前有效".into()
                    } else if in_claim {
                        "签署时有效、验证时已过期 -> 仅可能构成历史有效".into()
                    } else {
                        String::new()
                    }
                ),
            });
            if !in_verify && in_claim {
                historical_only = true;
            }

            // 轮换连续性：与下一段（更靠近叶子）证明区间相交。
            // raw.edge_events 顺序为叶子侧在前，故 prev_* 是 child 侧区间。
            if let (Some(pnb), Some(pna)) = (prev_nb, prev_na) {
                let overlap = !(na < pnb || nb > pna);
                steps.push(Step {
                    check: format!("{tag}：轮换连续性"),
                    ok: overlap,
                    detail: format!(
                        "本段区间 [{}, {}] 与叶子侧相邻区间 [{}, {}] {}（不相交则轮换断档）",
                        t(nb),
                        t(na),
                        t(pnb),
                        t(pna),
                        if overlap { "相交" } else { "不相交" }
                    ),
                });
                if !overlap {
                    invalid = true;
                }
            }
            prev_nb = Some(nb);
            prev_na = Some(na);

            // 撤销检查：child 由其直接上级 issuer 撤销才有效（路径内校验）。
            let verdict = self.check_revocation(
                &child_kid,
                &issuer_kid,
                &tag,
                claimed_at,
                verify_at,
                &mut steps,
            );
            match verdict {
                RevVerdict::InvalidCurrent | RevVerdict::InvalidAtSigning => invalid = true,
                RevVerdict::Historical(note) => {
                    historical_only = true;
                    revoked_note = Some(note);
                }
                _ => {}
            }

            chain.push(Link {
                kid: child_kid,
                usage: child_usage.as_str().into(),
                role: role_for(child_usage),
                event_id: edge.id.clone(),
                kind: "rotation".into(),
                not_before: Some(nb),
                not_after: Some(na),
            });

            current_kid = issuer_kid;
        }

        // 根锚点：自签签名 + 区间 + 根撤销。
        let rnb = anchor.not_before.unwrap_or(0);
        let rna = anchor.not_after.unwrap_or(0);
        let root_key = self.keys.get(&anchor.issuer_kid);
        let root_msg = crypto::root_anchor_message(&anchor.issuer_kid, rnb, rna);
        let root_sig_ok = root_key
            .map(|k| crypto::verify_hex(&k.public_hex, &root_msg, &anchor.signature))
            .unwrap_or(false);
        steps.push(Step {
            check: format!("根锚点 {}：签名", anchor.issuer_kid),
            ok: root_sig_ok,
            detail: if root_sig_ok {
                format!("根锚点由 {} 自签，验证成功", anchor.issuer_kid)
            } else {
                "根锚点自签签名验证失败".into()
            },
        });
        if !root_sig_ok {
            invalid = true;
        }
        let root_in_claim = claimed_at >= rnb && claimed_at <= rna;
        let root_in_verify = verify_at >= rnb && verify_at <= rna;
        steps.push(Step {
            check: format!("根锚点 {}：生效区间", anchor.issuer_kid),
            ok: root_in_claim,
            detail: format!(
                "锚点区间 [{}, {}]；签署时刻 {}，验证时刻 {}（{}）",
                t(rnb),
                t(rna),
                t(claimed_at),
                t(verify_at),
                match (root_in_claim, root_in_verify) {
                    (true, true) => "签署与验证时均有效",
                    (true, false) => "签署时有效，验证时已不在锚点区间 -> 历史有效",
                    _ => "签署时锚点未生效/已失效",
                }
            ),
        });
        if !root_in_claim {
            invalid = true;
        }
        if root_in_claim && !root_in_verify {
            historical_only = true;
        }

        // 轮换连续性最后一段：根锚点区间与最靠近根的证明区间相交。
        if let (Some(pnb), Some(pna)) = (prev_nb, prev_na) {
            let overlap = !(rna < pnb || rnb > pna);
            steps.push(Step {
                check: "根锚点：轮换连续性".into(),
                ok: overlap,
                detail: format!(
                    "锚点区间 [{}, {}] 与相邻证明区间 [{}, {}] {}",
                    t(rnb),
                    t(rna),
                    t(pnb),
                    t(pna),
                    if overlap {
                        "相交"
                    } else {
                        "不相交（根锚点未连续覆盖该证明）"
                    }
                ),
            });
            if !overlap {
                invalid = true;
            }
        }

        // 根自身撤销（仅 self）。
        let root_rev = self.check_revocation(
            &anchor.issuer_kid,
            &anchor.issuer_kid,
            "根锚点",
            claimed_at,
            verify_at,
            &mut steps,
        );
        match root_rev {
            RevVerdict::InvalidCurrent | RevVerdict::InvalidAtSigning => invalid = true,
            RevVerdict::Historical(note) => {
                historical_only = true;
                revoked_note = Some(note);
            }
            _ => {}
        }

        chain.push(Link {
            kid: anchor.issuer_kid.clone(),
            usage: Usage::Root.as_str().into(),
            role: "root".into(),
            event_id: anchor.id.clone(),
            kind: "root_anchor".into(),
            not_before: Some(rnb),
            not_after: Some(rna),
        });

        let status = if invalid {
            "invalid"
        } else if historical_only {
            "historical"
        } else {
            "trusted"
        };
        let _ = revoked_note;
        let _ = current_kid;

        // rank_key: 状态优先级 | 链长(短优先) | 根 kid | 各事件 id，保证确定性。
        rank[0] = match status {
            "trusted" => "0",
            "historical" => "1",
            _ => "2",
        }
        .to_string();
        rank.push(format!("{:04}", chain.len()));
        rank.push(anchor.issuer_kid.clone());
        for ev in &raw.edge_events {
            rank.push(ev.id.clone());
        }

        PathReport {
            status: status.into(),
            chain,
            root_kid: Some(anchor.issuer_kid),
            gap_kid: None,
            steps,
            rank_key: rank,
        }
    }

    // ---------- 撤销语义 ----------

    fn check_revocation(
        &self,
        subject: &str,
        required_issuer: &str,
        tag: &str,
        claimed_at: TimeSec,
        verify_at: TimeSec,
        steps: &mut Vec<Step>,
    ) -> RevVerdict {
        let Some(revs) = self.revocations.get(subject) else {
            return RevVerdict::NoRevocation;
        };
        let mut worst = RevVerdict::NoRevocation;
        for rev in revs {
            let reason = rev.reason.unwrap_or(RevokeReason::Superseded);
            let recorded = rev.recorded_at.unwrap_or(0);
            let issuer_key = self.keys.get(&rev.issuer_kid);
            let msg =
                crypto::revocation_message(&rev.issuer_kid, subject, reason.as_str(), recorded);
            let sig_ok = issuer_key
                .map(|k| crypto::verify_hex(&k.public_hex, &msg, &rev.signature))
                .unwrap_or(false);
            let authority_ok = rev.issuer_kid == required_issuer
                || (rev.issuer_kid == subject
                    && self.keys.get(subject).map(|k| k.usage) == Some(Usage::Root));
            let valid = sig_ok && authority_ok;
            let base = format!(
                "{tag}：撤销 {}（{}，recorded_at={}）",
                subject,
                reason.as_str(),
                t(recorded)
            );
            if !valid {
                steps.push(Step {
                    check: base,
                    ok: true,
                    detail: format!(
                        "该撤销事件签名={}、授权={}（撤销人 {}，本路径上级 {}）；视为无效撤销并忽略",
                        sig_ok, authority_ok, rev.issuer_kid, required_issuer
                    ),
                });
                worst = worst.widen(RevVerdict::Ignored);
                continue;
            }

            // 核心语义：撤销自 recorded_at 起生效，绝不回溯。
            if recorded <= claimed_at {
                // 签署时已被撤销（或当天）：签名无效。
                steps.push(Step {
                    check: base,
                    ok: false,
                    detail: format!(
                        "撤销在声明签署时刻 {} 之前/当时记录（{} <= {}），签署时该密钥已不可信 => invalid",
                        t(claimed_at), t(recorded), t(claimed_at)
                    ),
                });
                worst = worst.widen(RevVerdict::InvalidAtSigning);
            } else if recorded <= verify_at {
                // 签署时有效，验证时刻前被撤销：
                match reason {
                    RevokeReason::Compromise => {
                        // 泄露：历史签名不被回溯抹掉，但验证时刻不能再信任 => historical
                        steps.push(Step {
                            check: base,
                            ok: true,
                            detail: format!(
                                "compromise 记录于签署之后、验证之前（{} < {} <= {}）：\
                                 泄露前签出的历史签名保留历史有效性，不回溯抹掉；但验证时刻该路径不再是 current-trusted => historical",
                                t(claimed_at), t(recorded), t(verify_at)
                            ),
                        });
                        worst = worst.widen(RevVerdict::Historical(format!(
                            "{subject} 于 {} 被标记 compromise（签署 {} 之后）",
                            t(recorded),
                            t(claimed_at)
                        )));
                    }
                    RevokeReason::Superseded => {
                        steps.push(Step {
                            check: base,
                            ok: true,
                            detail: format!(
                                "superseded 记录于签署之后、验证之前（{} < {} <= {}）：\
                                 该密钥在 {} 被取代，旧密钥上的历史签名仍可解释为历史有效 => historical",
                                t(claimed_at), t(recorded), t(verify_at), t(recorded)
                            ),
                        });
                        worst = worst.widen(RevVerdict::Historical(format!(
                            "{subject} 于 {} 被取代（superseded）",
                            t(recorded)
                        )));
                    }
                }
            } else {
                steps.push(Step {
                    check: base,
                    ok: true,
                    detail: format!(
                        "撤销记录于验证时刻之后（{} > {}）：本次验证不生效，留待下一批/更晚验证时刻",
                        t(recorded), t(verify_at)
                    ),
                });
                worst = worst.widen(RevVerdict::Ok);
            }
        }
        worst
    }

    // ---------- 汇总 ----------

    #[allow(clippy::too_many_arguments)]
    fn finalize(
        &self,
        _early: Verdict,
        digest: String,
        signer_kid: &str,
        claimed_at: TimeSec,
        verify_at: TimeSec,
        global_steps: Vec<Step>,
        reports: Vec<PathReport>,
    ) -> VerifyReport {
        // 提前失败的路径（签名/usage/时间）直接构造结论。
        if reports.is_empty() {
            let failed = global_steps.iter().any(|s| !s.ok);
            let verdict = if failed {
                Verdict::Invalid
            } else {
                Verdict::Incomplete
            };
            let summary = match verdict {
                Verdict::Invalid => {
                    "制品签名或其声明无法通过密码学/用途检查，所有路径拒绝：invalid".into()
                }
                _ => "未找到可评估的信任路径：incomplete".into(),
            };
            return VerifyReport {
                verdict: verdict.clone(),
                summary,
                digest,
                signer_kid: signer_kid.into(),
                claimed_at,
                verify_at,
                graph_digest: self.graph_digest.clone(),
                global_steps,
                adopted: None,
                rejected: Vec::new(),
            };
        }

        // 状态优先级：trusted > historical > incomplete > invalid
        let rank = |s: &str| match s {
            "trusted" => 0u8,
            "historical" => 1,
            "incomplete" => 2,
            _ => 3,
        };
        let best_status = reports.iter().map(|r| rank(&r.status)).min().unwrap();
        let mut sorted = reports;
        sorted.sort_by(|a, b| {
            rank(&a.status)
                .cmp(&rank(&b.status))
                .then_with(|| a.chain.len().cmp(&b.chain.len()))
                .then_with(|| a.root_kid.cmp(&b.root_kid))
                .then_with(|| a.rank_key.join(",").cmp(&b.rank_key.join(",")))
        });
        let adopted = sorted.remove(0);
        let rejected = sorted;
        let verdict = match best_status {
            0 => Verdict::Trusted,
            1 => Verdict::Historical,
            2 => Verdict::Incomplete,
            _ => Verdict::Invalid,
        };
        let summary = match &verdict {
            Verdict::Trusted => format!(
                "采用经 {} 的路径：签名、用途、生效区间、轮换连续性与撤销语义全部满足，在验证时刻 {} 可信（trusted）",
                adopted.root_kid.as_deref().unwrap_or("?"),
                fmt_time(verify_at)
            ),
            Verdict::Historical => format!(
                "采用经 {} 的路径：签名在 {} 时有效，但在验证时刻 {} 仅为历史有效（historical）——可解释、可追溯，不是 current-trusted",
                adopted.root_kid.as_deref().unwrap_or("?"),
                fmt_time(claimed_at),
                fmt_time(verify_at)
            ),
            Verdict::Incomplete => format!(
                "所有可达路径都缺少中间证明或根锚点（缺口：{}）：incomplete。补齐缺失证明后重新验证即可，不判 invalid",
                adopted.gap_kid.as_deref().unwrap_or("?")
            ),
            Verdict::Invalid => {
                "不存在任何有效路径：全部路径在签名、用途、生效区间、连续性或撤销检查上失败：invalid".into()
            }
        };
        VerifyReport {
            verdict,
            summary,
            digest,
            signer_kid: signer_kid.into(),
            claimed_at,
            verify_at,
            graph_digest: self.graph_digest.clone(),
            global_steps,
            adopted: Some(adopted),
            rejected,
        }
    }
}

fn role_for(u: Usage) -> String {
    match u {
        Usage::Root => "root".into(),
        Usage::Intermediate => "intermediate".into(),
        Usage::Signing => "leaf".into(),
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum RevVerdict {
    Ok,
    NoRevocation,
    Ignored,
    InvalidAtSigning,
    InvalidCurrent,
    Historical(String),
}

impl RevVerdict {
    fn widen(self, other: RevVerdict) -> RevVerdict {
        // 更强的失败语义覆盖较弱的。
        let score = |v: &RevVerdict| match v {
            RevVerdict::InvalidAtSigning | RevVerdict::InvalidCurrent => 4,
            RevVerdict::Historical(_) => 3,
            RevVerdict::Ok => 1,
            RevVerdict::Ignored => 0,
            RevVerdict::NoRevocation => -1,
        };
        if score(&other) > score(&self) {
            other
        } else {
            self
        }
    }
}
