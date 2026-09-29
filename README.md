# 签名信任路径实验台（Signature Trust Path Lab）

用本地测试密钥解释“某个制品摘要在指定历史时刻是否可信”的 Rust 服务与网页。
数据保存在 SQLite；**私钥仅以 AES-256-GCM 加密信封落盘，API、日志与导出中只出现公钥与 key id。**

## 安装与演示

```bash
cargo build
cargo test
cargo run -- --listen 127.0.0.1:5231
# 打开 http://127.0.0.1:5231/ ，页面标题为“签名信任路径实验台”
```

可选参数：`--db <path>`（默认 `trustpath-lab.db`）、`--passphrase <本地演示口令>`、`--no-seed`。

预置制品 A 在两个验证时刻给出不同但可解释的结论：

| 验证时刻 | 结论 | 原因 |
| --- | --- | --- |
| T9 = compromise 记录之前 | `trusted` | 路径上所有证明有效、未撤销 |
| T8 = compromise 记录之后 | `historical` | 签名在签署时有效；compromise 不回溯抹掉泄露前历史签名，但验证时刻不再是 current-trusted |

## 模型

- **密钥**：Ed25519，`root / intermediate / signing` 三类用途；`key id = sha256(公钥)[..16]`。
- **信任事件（只追加）**：`root_anchor`、`rotation`、`revocation`、`supersede`。
  - 纠错不修改旧记录，而是追加 `supersede` 事件并回填 `superseded_by`（支持传递闭包）。
- **制品签名**：负载绑定 `digest + claimed_at`，防止拿同一签名套别的声称时间。
- **撤销语义**（`recorded_at` 决定影响范围起点，绝不回溯）：
  - `compromise`：`recorded_at <= claimed_at` 时签署 => `invalid`；签署在前、撤销在验证时刻前 => `historical`；
  - `superseded`：前向取代，旧密钥在取代前签出的历史签名同样保留为 `historical`；
  - 撤销事件必须由被撤销 key 的直接上级（root 可自撤销）签发，否则忽略。

## 验证判定

输入 `(digest, signature, claimed_at, verify_at)`，引擎枚举签名者到所有根锚点的全部路径，
逐条检查 **签名 / key usage / 生效区间 / 轮换连续性（相邻证明区间必须相交）/ 撤销语义**：

- `trusted`：存在一条在签署与验证时刻都成立的路径；
- `historical`：只有“签署时有效、验证时已过期或事后被撤销”的路径；
- `incomplete`：可达路径缺少中间证明或根锚点（补齐后可变为 trusted），**不等同 invalid**；
- `invalid`：不存在任何有效路径（密码学失败、用途不符、签署时区间/撤销不成立等）。

同长路径采用固定规则排序：状态优先级 → 链长（短优先）→ 根 key id → 各事件内容哈希；
与导入顺序无关。页面可以从结论沿“采用路径 / 拒绝路径”回到每个证明与每一步时间判断。

## 一致性

- **幂等导入**：相同 `idem_key + 内容` 返回原记录且不推进图版本；同键不同内容 => 409。
- **乐观并发**：追加信任事件需带 `expected_version`；两操作者并发时一方收到 409，重试即可。
- **批次冻结**：批次创建时固化图摘要（事件按内容哈希排序后哈希，导入顺序无关），
  运行期间新增撤销/轮换不影响本批，留到下一批。
- **崩溃恢复**：单条结果提交与批次游标推进在同一事务；进程在二者之间退出，恢复后不重复产出。
- **时钟可注入**：`types::Clock`/`FakeClock`，全部测试使用固定时间轴。

## API 摘要

- `POST /api/keys` 创建本地密钥（仅返回 kid/公钥）
- `POST /api/events` 追加 root_anchor / rotation / revocation / supersede
- `POST /api/signatures` 用本地私钥签制品
- `POST /api/verify` 单条验证（枚举全部路径并给逐步原因）
- `POST /api/batches`、`POST /api/batches/:id/run`、`GET /api/batches/:id`
- `GET /api/state`、`GET /api/export`、`GET /api/logs`

## 代码布局

- `src/crypto.rs` Ed25519 签名、key id、AES-GCM 私钥信封、规范化签名负载
- `src/store.rs` SQLite schema、只追加日志、幂等、版本号、冻结图、批次游标
- `src/verify.rs` 路径枚举与五类检查、撤销语义、确定性排序
- `src/batch.rs` 冻结图上的批量验证与恢复
- `src/web.rs` / `src/ui_page.rs` HTTP API 与页面
- `src/seed.rs` 固定时间轴的预置演示
- `tests/trustpath.rs`、`tests/crash_runner.rs` 28 项测试（含真实子进程崩溃恢复与私钥泄露扫描）
