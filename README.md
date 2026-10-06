# 治理规则例外审批服务

本项目在人工智能治理协作基础能力之上，提供**治理规则例外的全生命周期审批服务**：申请、分级审批、
限定主体与资源、自动到期、提前撤销、使用回指批准依据与事后复盘。所有状态变更进入哈希串联审计链，
所有写操作支持 request_id 幂等，状态持久化在 SQLite 中。

## 核心规则

- **显式到期且强制 TTL**：申请必须给出带时区的 `expires_at`；按风险评分自动定级
  （low <40 / medium 40-74 / high ≥75），最长存活时间分别为 30 天 / 7 天 / 24 小时。
- **分级审批**：low 需 L1（业务负责人）；medium 需 L1+L2（安全）；high 需 L1+L2+L3（风险委员会）。
  必须按级顺序审批，驳回即终态；申请人不能审批自己的申请；同一审批人不能在同一单跨级会签。
- **审批人范围约束**：审批人通过 `approver_scopes` 登记层级与负责的规则/资源/主体白名单（支持 `*`），
  只能在自己覆盖的范围内作出决定。
- **冲突互斥**：同一规则下，主体集合与资源集合有交集、且生效时间窗重叠的两个例外不能同时生效
  （最终批准时事务内校验）。
- **自动到期且不复活**：到期在任何读取/使用前惰性落盘为 `expired` 并写审计事件；终态持久化，
  服务重启后过期例外不会重新激活，逾期使用一律拒绝。
- **提前撤销**：管理员或覆盖该例外范围的审批人可凭理由撤销，撤销立即生效。
- **回指批准依据**：每次使用生成 basis 快照（各级批准人、审批审计事件哈希、时间窗、范围），
  `trace` 接口逐条核验审批事件真实存在且指向该例外。
- **事后复盘**：只有已到期/已撤销的例外才能登记复盘结论与剩余风险评分。
- **幂等**：申请、审批、撤销、使用、复盘均以 `request_id` 去重；重复提交（无论发生在审批后、
  撤销后还是重启后）返回同一资源与同一结果。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/approver-scopes` | 管理员登记/更新审批人层级与范围 |
| POST | `/exceptions` | 提交例外申请 |
| POST | `/exceptions/decisions` | 某一层级批准/驳回 |
| POST | `/exceptions/revoke` | 提前撤销生效中的例外 |
| POST | `/exceptions/use` | 在限定主体/资源内使用例外，返回批准依据 |
| GET  | `/exceptions/{id}/trace` | 回溯一次使用并核验批准依据 |
| GET  | `/exceptions/active` | 管理视图：当前生效例外、剩余时间与剩余风险 |
| GET  | `/exceptions/{id}` | 例外详情（含各级决定与复盘） |
| POST | `/exceptions/reviews` | 关闭后登记事后复盘 |
| POST | `/exceptions/sweep` | 主动触发到期清扫 |

写请求通过 `X-Actor-Id` 头标识操作者，请求体携带 `request_id`。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

覆盖申请 → 三级会签 → 使用留证 → 重启越过到期点 → 过期不复活/不可用 → 复盘的完整链路：

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的状态与审计历史继续保留。
