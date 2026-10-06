# 治理规则例外审批服务

本项目提供人工智能治理协作的服务端基础能力，并在此之上实现**治理规则例外审批**：业务团队可以申请临时放宽模型访问等治理规则，安全团队在分级审批、明确期限与冲突检查的约束下放行，任何使用例外完成的动作都能回指批准依据。基础层通过角色权限、请求幂等、SQLite 事务与审计链保持业务状态一致。

## 例外生命周期

`pending → active → expired / revoked → closed`；`pending` 也可能被 `rejected` 或 `cancelled`。

- **申请**：必须给出 `rule_id`、`subject_id`、`resource_id`、`risk_level` 与明确的 `expires_at`；有效期不得超过风险级别上限（low 30 天、medium 7 天、high 24 小时），杜绝"演示结束后仍然有效"的无期限例外。
- **分级审批**：low / medium / high 分别需要 1 / 2 / 3 级审批；审批人必须持有覆盖该组织、规则、资源与风险级别的 `approver_scope`（第三级必须由 admin 承担），不能审批自己的申请，也不能重复审批同一申请。
- **冲突检查**：同一 `(rule_id, subject_id, resource_id)` 上 `effect` 相反（allow / deny）的例外不能同时生效，最终一级审批在事务内完成冲突检查与激活。
- **自动到期**：到期由持久化的 `expires_at` 与当前时钟推导，所有读写路径都会先清理到期例外；服务重启时也会立即清理，过期例外不会重新激活。
- **提前撤销**：生效例外可由 admin 或负责范围内的审批人撤销；待审批申请可由申请人或 admin 取消。
- **使用追溯**：`record_exception_usage` 只允许例外限定的主体调用，并把批准依据（各级审批人 + 激活事件的审计哈希）快照进使用记录与审计链。
- **事后复盘**：例外到期或被撤销后，由 reviewer / admin 记录复盘结论（`no_issue` / `misuse_found` / `process_gap`），状态变为 `closed`。
- **幂等**：所有写操作通过 `request_id` 幂等，重复提交返回同一收据；同一 `request_id` 提交不同内容会得到 409。

## HTTP 接口

在基础接口（`/organizations`、`/actors`、`/sites`、`/domain-records`、`/audit-events`）之外新增：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/exception-requests` | 提交例外申请 |
| POST | `/approver-scopes` | 登记审批人负责范围（admin） |
| POST | `/exception-decisions` | 对当前层级作出 approved / rejected 决定 |
| POST | `/exception-revocations` | 撤销生效例外或取消待审批申请 |
| POST | `/exception-usages` | 记录一次例外使用并回指批准依据 |
| POST | `/exception-reviews` | 对已结束例外进行事后复盘 |
| GET | `/exception-requests?exception_id=` | 查看例外详情、审批链与复盘结果 |
| GET | `/exceptions/active` | 列出当前生效例外及剩余风险（admin / auditor） |
| GET | `/exception-usages?exception_id=` | 查看例外的使用记录（admin / auditor / reviewer） |

剩余风险 `residual_risk` 包含：风险级别权重（low=1 / medium=2 / high=3）× (1 + 使用次数) 的分值、剩余秒数与使用次数。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的状态与审计历史继续保留，已过期的例外保持失效。
