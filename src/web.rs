//! 极简 HTTP 服务（std::net + 每连接线程）。
//! 所有响应 DTO 都不包含 encrypted_private；日志也只记录 kid/事件 id。

use crate::log::Journal;
use crate::store::{BatchInput, Store};
use crate::types::{RevokeReason, Usage};
use crate::{batch, seed, verify_once};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub store: Store,
    pub log: Journal,
}

#[derive(Deserialize, Default)]
pub struct KeyReq {
    pub usage: String,
    pub idem_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EventReq {
    RootAnchor {
        root_kid: String,
        not_before: i64,
        not_after: i64,
        #[serde(default)]
        idem_key: Option<String>,
        #[serde(default = "any_version")]
        expected_version: i64,
    },
    Rotation {
        issuer_kid: String,
        child_kid: String,
        not_before: i64,
        not_after: i64,
        #[serde(default)]
        idem_key: Option<String>,
        #[serde(default = "any_version")]
        expected_version: i64,
    },
    Revocation {
        issuer_kid: String,
        subject_kid: String,
        reason: String,
        recorded_at: i64,
        #[serde(default)]
        idem_key: Option<String>,
        #[serde(default = "any_version")]
        expected_version: i64,
    },
    Supersede {
        issuer_kid: String,
        target_event_id: String,
        recorded_at: i64,
        #[serde(default)]
        idem_key: Option<String>,
        #[serde(default = "any_version")]
        expected_version: i64,
    },
}
fn any_version() -> i64 {
    -1
}

#[derive(Deserialize)]
struct SignReq {
    kid: String,
    digest: String,
    claimed_at: i64,
    #[serde(default)]
    idem_key: Option<String>,
}

#[derive(Deserialize)]
struct VerifyReq {
    digest: String,
    kid: String,
    signature: String,
    claimed_at: i64,
    verify_at: i64,
}

#[derive(Deserialize)]
struct BatchReq {
    #[serde(default)]
    use_demo: bool,
    #[serde(default)]
    items: Vec<RawItem>,
}
#[derive(Deserialize)]
struct RawItem {
    digest: String,
    kid: String,
    signature: String,
    claimed_at: i64,
    verify_at: i64,
}

fn parse_usage(s: &str) -> Result<Usage, (u16, String)> {
    match s {
        "root" => Ok(Usage::Root),
        "intermediate" => Ok(Usage::Intermediate),
        "signing" => Ok(Usage::Signing),
        other => Err((400, format!("未知用途: {other}"))),
    }
}
fn parse_reason(s: &str) -> Result<RevokeReason, (u16, String)> {
    match s {
        "compromise" => Ok(RevokeReason::Compromise),
        "superseded" => Ok(RevokeReason::Superseded),
        other => Err((
            400,
            format!("撤销原因必须是 compromise|superseded，收到 {other}"),
        )),
    }
}

pub fn serve(addr: &str, state: Arc<AppState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    state.log.log("info", "listen", &format!("addr={addr}"));
    serve_from(listener, state)
}

pub fn serve_from(listener: TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = state.clone();
                std::thread::spawn(move || {
                    let _ = handle(s, st);
                });
            }
            Err(e) => state.log.log("warn", "accept", &e.to_string()),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, state: Arc<AppState>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = find_header_end(&buf) {
            header_end = Some(p);
            break;
        }
        if buf.len() > 2_000_000 {
            break;
        }
    }
    let Some(end) = header_end else {
        return write_text(&mut stream, 400, "bad request");
    };
    let header = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = header.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let mut content_length = 0usize;
    for line in lines {
        if let Some(rest) = line.to_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buf[end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    if method == "GET" && path == "/" {
        return write_response(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            crate::ui_page::INDEX_HTML.as_bytes(),
        );
    }
    match route_json(&state, method, path, &body) {
        Ok((status, value)) => {
            let payload = serde_json::to_vec(&value).unwrap_or_default();
            write_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
            )
        }
        Err((status, msg)) => {
            let payload = serde_json::json!({ "error": msg, "code":"http_error" }).to_string();
            write_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn write_text(stream: &mut TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    write_response(stream, status, "text/plain; charset=utf-8", text.as_bytes())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

#[derive(Serialize)]
struct KeyDto {
    kid: String,
    public_key: String,
    usage: String,
    created_at: i64,
}
#[derive(Serialize)]
struct EventDto {
    seq: i64,
    id: String,
    kind: String,
    issuer_kid: String,
    child_kid: Option<String>,
    subject_kid: Option<String>,
    superseded_event: Option<String>,
    reason: Option<String>,
    recorded_at: Option<i64>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    signature_hidden: Option<String>,
    signature: String,
    idem_key: Option<String>,
    superseded_by: Option<String>,
    created_at: i64,
}
#[derive(Serialize)]
struct SigDto {
    id: String,
    kid: String,
    digest: String,
    signature: String,
    claimed_at: i64,
    idem_key: Option<String>,
    created_at: i64,
}

fn key_dto(k: crate::types::KeyRow) -> KeyDto {
    KeyDto {
        kid: k.kid,
        public_key: k.public_key,
        usage: k.usage.as_str().into(),
        created_at: k.created_at,
    }
}
fn event_dto(e: crate::types::EventRow) -> EventDto {
    EventDto {
        seq: e.seq,
        id: e.id,
        kind: e.kind.as_str().into(),
        issuer_kid: e.issuer_kid,
        child_kid: e.child_kid,
        subject_kid: e.subject_kid,
        superseded_event: e.superseded_event,
        reason: e.reason.map(|r| r.as_str().into()),
        recorded_at: e.recorded_at,
        not_before: e.not_before,
        not_after: e.not_after,
        signature_hidden: None,
        signature: e.signature,
        idem_key: e.idem_key,
        superseded_by: e.superseded_by,
        created_at: e.created_at,
    }
}
fn sig_dto(s: crate::types::SignatureRow) -> SigDto {
    SigDto {
        id: s.id,
        kid: s.kid,
        digest: s.digest,
        signature: s.signature,
        claimed_at: s.claimed_at,
        idem_key: s.idem_key,
        created_at: s.created_at,
    }
}

type RouteResult = Result<(u16, serde_json::Value), (u16, String)>;

fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, (u16, String)> {
    serde_json::from_slice(body).map_err(|e| (400, format!("JSON 解析失败: {e}")))
}

fn map_app_err(e: crate::error::Error) -> (u16, String) {
    let (status, body) = e.status_and_body();
    (status, body.error)
}

fn route_json(state: &Arc<AppState>, method: &str, path: &str, body: &[u8]) -> RouteResult {
    let store = &state.store;
    match (method, path) {
        ("GET", "/api/state") => {
            let keys = store.list_keys().map_err(map_app_err)?;
            let events = store.list_events().map_err(map_app_err)?;
            let sigs = store.list_signatures().map_err(map_app_err)?;
            let graph = store.current_graph().map_err(map_app_err)?;
            let seed_info = if seed::is_seeded(store) {
                serde_json::json!({
                    "root_kid_hint": "seed:key:root",
                    "t1": seed::T1, "t4": seed::T4, "t7": seed::T7,
                    "verify_before": seed::VERIFY_BEFORE, "verify_after": seed::VERIFY_AFTER,
                })
            } else {
                serde_json::Value::Null
            };
            // 给页面填入预置快捷按钮需要的具体 id/签名
            let demo = if seed::is_seeded(store) {
                let sigs_all = store.list_signatures().map_err(map_app_err)?;
                let find_sig = |d: &str| sigs_all.iter().find(|s| s.digest == d).cloned();
                let keys_all = store.list_keys().map_err(map_app_err)?;
                let find_key = |idem_hint_kid: Option<String>| {
                    keys_all
                        .iter()
                        .find(|k| Some(k.kid.clone()) == idem_hint_kid)
                        .cloned()
                };
                let _ = find_key;
                let sa = find_sig(seed::DIGEST_A);
                let so = find_sig(seed::DIGEST_ORPHAN);
                let leaf_kid = sa.as_ref().map(|s| s.kid.clone());
                let orphan_kid = so.as_ref().map(|s| s.kid.clone());
                let intermediate_kid = keys_all
                    .iter()
                    .find(|k| {
                        k.usage == Usage::Intermediate && sigs_all.iter().all(|s| s.kid != k.kid)
                    })
                    .map(|k| k.kid.clone())
                    .or_else(|| {
                        keys_all
                            .iter()
                            .find(|k| k.usage == Usage::Intermediate)
                            .map(|k| k.kid.clone())
                    });
                serde_json::json!({
                    "digest_a": seed::DIGEST_A,
                    "leaf": leaf_kid,
                    "sig_a": sa.map(|s| s.signature),
                    "orphan": orphan_kid,
                    "intermediate": intermediate_kid,
                    "t1": seed::T1, "t3": seed::T3, "t4": seed::T4,
                    "verify_before": seed::VERIFY_BEFORE, "verify_after": seed::VERIFY_AFTER,
                })
            } else {
                serde_json::Value::Null
            };
            Ok((
                200,
                serde_json::json!({
                    "graph_version": graph.graph_version,
                    "graph_digest": graph.digest,
                    "keys": keys.into_iter().map(key_dto).collect::<Vec<_>>(),
                    "events": events.into_iter().map(event_dto).collect::<Vec<_>>(),
                    "signatures": sigs.into_iter().map(sig_dto).collect::<Vec<_>>(),
                    "seed": demo,
                    "seed_meta": seed_info,
                }),
            ))
        }

        ("POST", "/api/keys") => {
            let req: KeyReq = parse_json(body)?;
            let usage = parse_usage(&req.usage)?;
            let k = store.create_key(usage, req.idem_key).map_err(map_app_err)?;
            state.log.log(
                "info",
                "key_created",
                &format!("kid={} usage={}", k.kid, k.usage.as_str()),
            );
            Ok((200, serde_json::to_value(key_dto(k)).unwrap()))
        }

        ("POST", "/api/events") => {
            let req: EventReq = parse_json(body)?;
            let resolve_v = |x: i64| -> Result<i64, (u16, String)> {
                if x < 0 {
                    store.graph_version().map_err(map_app_err)
                } else {
                    Ok(x)
                }
            };
            let (row, created) = match req {
                EventReq::RootAnchor {
                    root_kid,
                    not_before,
                    not_after,
                    idem_key,
                    expected_version,
                } => store.anchor_root(
                    &root_kid,
                    not_before,
                    not_after,
                    idem_key,
                    resolve_v(expected_version)?,
                ),
                EventReq::Rotation {
                    issuer_kid,
                    child_kid,
                    not_before,
                    not_after,
                    idem_key,
                    expected_version,
                } => store.rotate(
                    &issuer_kid,
                    &child_kid,
                    not_before,
                    not_after,
                    idem_key,
                    resolve_v(expected_version)?,
                ),
                EventReq::Revocation {
                    issuer_kid,
                    subject_kid,
                    reason,
                    recorded_at,
                    idem_key,
                    expected_version,
                } => {
                    let r = parse_reason(&reason)?;
                    store.revoke(
                        &issuer_kid,
                        &subject_kid,
                        r,
                        recorded_at,
                        idem_key,
                        resolve_v(expected_version)?,
                    )
                }
                EventReq::Supersede {
                    issuer_kid,
                    target_event_id,
                    recorded_at,
                    idem_key,
                    expected_version,
                } => store.supersede(
                    &issuer_kid,
                    &target_event_id,
                    recorded_at,
                    idem_key,
                    resolve_v(expected_version)?,
                ),
            }
            .map_err(map_app_err)?;
            state.log.log(
                "info",
                if created {
                    "event_appended"
                } else {
                    "event_idempotent_hit"
                },
                &format!("id={} kind={} created={created}", row.id, row.kind.as_str()),
            );
            Ok((
                200,
                serde_json::json!({
                    "created": created,
                    "id": row.id,
                    "event": event_dto(row),
                }),
            ))
        }

        ("POST", "/api/signatures") => {
            let req: SignReq = parse_json(body)?;
            let (row, created) = store
                .sign_artifact(&req.kid, &req.digest, req.claimed_at, req.idem_key)
                .map_err(map_app_err)?;
            state.log.log(
                "info",
                "artifact_signed",
                &format!("id={} kid={} created={created}", row.id, row.kid),
            );
            Ok((
                200,
                serde_json::json!({ "created": created, "signature": sig_dto(row) }),
            ))
        }

        ("POST", "/api/verify") => {
            let req: VerifyReq = parse_json(body)?;
            let report = verify_once(
                store,
                &req.digest,
                &req.kid,
                &req.signature,
                req.claimed_at,
                req.verify_at,
            )
            .map_err(map_app_err)?;
            state.log.log(
                "info",
                "verify",
                &format!(
                    "kid={} verdict={} digest={}",
                    req.kid,
                    report.verdict.as_str(),
                    &req.digest[..12]
                ),
            );
            Ok((200, serde_json::to_value(report).unwrap()))
        }

        ("POST", "/api/batches") => {
            let req: BatchReq = parse_json(body).unwrap_or(BatchReq {
                use_demo: true,
                items: vec![],
            });
            let items: Vec<BatchInput> = if req.use_demo {
                if !seed::is_seeded(store) {
                    seed::seed(store).map_err(map_app_err)?;
                }
                let sigs_all = store.list_signatures().map_err(map_app_err)?;
                let sa = sigs_all
                    .iter()
                    .find(|x| x.digest == seed::DIGEST_A)
                    .ok_or((500, "缺少预置签名 A".into()))?;
                let so = sigs_all
                    .iter()
                    .find(|x| x.digest == seed::DIGEST_ORPHAN)
                    .ok_or((500, "缺少预置 orphan 签名".into()))?;
                vec![
                    BatchInput {
                        digest: seed::DIGEST_A.into(),
                        kid: sa.kid.clone(),
                        signature: sa.signature.clone(),
                        claimed_at: seed::T4,
                        verify_at: seed::VERIFY_BEFORE,
                    },
                    BatchInput {
                        digest: seed::DIGEST_A.into(),
                        kid: sa.kid.clone(),
                        signature: sa.signature.clone(),
                        claimed_at: seed::T4,
                        verify_at: seed::VERIFY_AFTER,
                    },
                    BatchInput {
                        digest: seed::DIGEST_ORPHAN.into(),
                        kid: so.kid.clone(),
                        signature: so.signature.clone(),
                        claimed_at: seed::T4,
                        verify_at: seed::VERIFY_AFTER,
                    },
                ]
            } else {
                req.items
                    .into_iter()
                    .map(|i| BatchInput {
                        digest: i.digest,
                        kid: i.kid,
                        signature: i.signature,
                        claimed_at: i.claimed_at,
                        verify_at: i.verify_at,
                    })
                    .collect()
            };
            let id = store.create_batch(items).map_err(map_app_err)?;
            state
                .log
                .log("info", "batch_created", &format!("batch={id}"));
            Ok((200, serde_json::json!({ "batch_id": id })))
        }

        ("POST", p) if p.starts_with("/api/batches/") && p.ends_with("/run") => {
            let id = &p["/api/batches/".len()..p.len() - "/run".len()];
            let run = batch::run_batch(store, id).map_err(map_app_err)?;
            state.log.log(
                "info",
                "batch_run",
                &format!(
                    "batch={id} now={} skipped={}",
                    run.processed_now, run.already_done
                ),
            );
            Ok((200, serde_json::to_value(run).unwrap()))
        }

        ("GET", p) if p.starts_with("/api/batches/") => {
            let id = p.trim_start_matches("/api/batches/");
            let b = store.batch(id).map_err(map_app_err)?;
            let stored = store.item_results(id).map_err(map_app_err)?;
            let results: Vec<serde_json::Value> = stored
                .into_iter()
                .map(|j| {
                    j.and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect();
            Ok((
                200,
                serde_json::json!({
                    "batch_id": b.id, "graph_version": b.graph_version,
                    "graph_digest": b.graph_digest, "results": results,
                }),
            ))
        }

        ("GET", "/api/export") => {
            // 导出：只有公钥/key id/事件/签名；绝无私钥字段。
            let keys = store.list_keys().map_err(map_app_err)?;
            let events = store.list_events().map_err(map_app_err)?;
            let sigs = store.list_signatures().map_err(map_app_err)?;
            let graph = store.current_graph().map_err(map_app_err)?;
            Ok((
                200,
                serde_json::json!({
                    "keys": keys.into_iter().map(key_dto).collect::<Vec<_>>(),
                    "events": events.into_iter().map(event_dto).collect::<Vec<_>>(),
                    "artifact_signatures": sigs.into_iter().map(sig_dto).collect::<Vec<_>>(),
                    "graph_version": graph.graph_version,
                    "graph_digest": graph.digest,
                    "note": "只包含公钥与 key id；私钥仅以 AES-GCM 加密信封存于本地 SQLite，不在任何导出/API/日志中出现",
                }),
            ))
        }

        ("GET", "/api/logs") => Ok((200, serde_json::json!(state.log.snapshot()))),

        _ => Err((404, format!("没有这个路由: {method} {path}"))),
    }
}
