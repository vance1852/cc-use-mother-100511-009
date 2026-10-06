"""治理规则例外审批服务。

在基础服务之上提供例外申请、分级审批、自动到期、提前撤销、
事后复盘与使用追溯能力：例外必须带有明确到期时间，审批人只能
在登记的负责范围内作出决定，互相冲突的例外不会同时生效，
每一次使用例外完成的动作都能回指批准依据。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .audit import append_event, canonical_json, digest
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import WriteReceipt

if TYPE_CHECKING:
    from .service import DomainService


RISK_ORDER = {"low": 1, "medium": 2, "high": 3}
REQUIRED_TIERS = {"low": 1, "medium": 2, "high": 3}
MAX_TTL_SECONDS = {"low": 30 * 24 * 3600, "medium": 7 * 24 * 3600, "high": 24 * 3600}
RISK_WEIGHT = {"low": 1, "medium": 2, "high": 3}
EFFECTS = frozenset({"allow", "deny"})
DECISIONS = frozenset({"approved", "rejected"})
REVIEW_OUTCOMES = frozenset({"no_issue", "misuse_found", "process_gap"})
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


class ExceptionService:
    """协调例外申请、审批、到期、撤销、复盘和使用追溯。

    通过组合复用 DomainService 的操作者校验、幂等收据和审计链，
    所有状态变化都在 SQLite 事务中完成，重复提交返回同一收据。
    """

    def __init__(self, domain: DomainService) -> None:
        self._domain = domain
        self.database = domain.database
        # 启动时先清理：服务重启后已过期的例外不得重新激活。
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)

    def _now(self) -> str:
        return self._format(self._domain.clock.now())

    @staticmethod
    def _format(value: datetime) -> str:
        """生成固定宽度、可按字符串比较时间的 UTC 文本。"""

        return value.astimezone(timezone.utc).strftime(TIME_FORMAT) + "Z"

    @staticmethod
    def _moment(value: str) -> datetime:
        return datetime.fromisoformat(value).astimezone(timezone.utc)

    def _parse_expiry(self, value: Any, risk_level: str) -> str:
        try:
            parsed = datetime.fromisoformat(str(value).strip())
        except (TypeError, ValueError) as exc:
            raise ValidationError("expires_at 必须是 ISO 8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError("expires_at 必须包含时区")
        expires = parsed.astimezone(timezone.utc)
        now = self._domain.clock.now()
        if expires <= now:
            raise ValidationError("expires_at 必须晚于当前时间")
        if (expires - now).total_seconds() > MAX_TTL_SECONDS[risk_level]:
            raise ValidationError(f"有效期超过 {risk_level} 风险允许的最长时限")
        return self._format(expires)

    def _comment(self, value: Any) -> str:
        if value is None:
            return ""
        value = str(value).strip()
        if len(value) > 500:
            raise ValidationError("comment 不能超过 500 个字符")
        return value

    def _wildcard(self, value: str, field: str) -> str:
        value = str(value).strip()
        if value == "*":
            return value
        return self._domain._identifier(value, field)

    def _load(self, connection, exception_id: str):
        row = connection.execute(
            "SELECT * FROM exception_requests WHERE exception_id=?", (str(exception_id).strip(),)
        ).fetchone()
        if row is None:
            raise NotFoundError("例外申请不存在")
        return row

    def _usage_count(self, connection, exception_id: str) -> int:
        return connection.execute(
            "SELECT COUNT(*) AS count FROM exception_usages WHERE exception_id=?", (exception_id,)
        ).fetchone()["count"]

    def _sweep_expired(self, connection) -> None:
        """把已越过到期时间的生效例外转为 expired，并写入审计链。"""

        now = self._now()
        rows = connection.execute(
            "SELECT exception_id, expires_at FROM exception_requests WHERE status='active' AND expires_at<=?",
            (now,),
        ).fetchall()
        for row in rows:
            connection.execute(
                "UPDATE exception_requests SET status='expired', ended_at=?, end_reason='expired' "
                "WHERE exception_id=?",
                (now, row["exception_id"]),
            )
            append_event(connection, actor_id="system", action="exception.expired",
                         resource_type="exception", resource_id=row["exception_id"],
                         detail={"expires_at": row["expires_at"]}, occurred_at=now)

    def _scope_covers(self, connection, actor_id: str, row, tier: int) -> bool:
        """判断操作者是否持有覆盖该例外指定层级的审批范围。"""

        scopes = connection.execute(
            "SELECT * FROM approver_scopes WHERE actor_id=? AND organization_id=? AND tier=?",
            (actor_id, row["organization_id"], tier),
        ).fetchall()
        for scope in scopes:
            if scope["rule_id"] not in ("*", row["rule_id"]):
                continue
            if scope["resource_id"] not in ("*", row["resource_id"]):
                continue
            if RISK_ORDER[row["risk_level"]] > RISK_ORDER[scope["max_risk_level"]]:
                continue
            return True
        return False

    def _any_scope_covers(self, connection, actor_id: str, row) -> bool:
        return any(self._scope_covers(connection, actor_id, row, tier) for tier in (1, 2, 3))

    def _ensure_no_conflict(self, connection, row) -> None:
        """同一规则、主体、资源上 effect 相反的例外不能同时生效。"""

        conflicts = connection.execute(
            "SELECT exception_id FROM exception_requests "
            "WHERE status='active' AND rule_id=? AND subject_id=? AND resource_id=? AND effect<>?",
            (row["rule_id"], row["subject_id"], row["resource_id"], row["effect"]),
        ).fetchall()
        if conflicts:
            raise ConflictError("存在与其冲突的生效例外")

    def _approval_basis(self, connection, exception_id: str, activation_hash: str) -> dict[str, Any]:
        approvals = connection.execute(
            "SELECT tier, approver_id, decided_at FROM exception_approvals "
            "WHERE exception_id=? ORDER BY tier",
            (exception_id,),
        ).fetchall()
        return {
            "exception_id": exception_id,
            "approvals": [
                {"tier": item["tier"], "approver_id": item["approver_id"], "decided_at": item["decided_at"]}
                for item in approvals
            ],
            "activation_event_hash": activation_hash,
        }

    def submit_exception(self, *, request_id: str, actor_id: str, organization_id: str,
                         rule_id: str, subject_id: str, resource_id: str,
                         risk_level: str, reason: str, expires_at: str,
                         effect: str = "allow") -> WriteReceipt:
        """登记一条例外申请，到期时间必填且不得超过风险级别上限。"""

        payload = {"actor_id": actor_id, "organization_id": organization_id, "rule_id": rule_id,
                   "subject_id": subject_id, "resource_id": resource_id, "risk_level": risk_level,
                   "reason": reason, "expires_at": expires_at, "effect": effect}
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            self._domain._require(actor, "admin", "operator")
            organization_id = self._domain._identifier(organization_id, "organization_id")
            if actor.organization_id != organization_id and actor.role != "admin":
                raise PermissionDenied("不能为其他组织申请例外")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")
            rule_id = self._domain._identifier(rule_id, "rule_id")
            subject_id = self._domain._identifier(subject_id, "subject_id")
            resource_id = self._domain._identifier(resource_id, "resource_id")
            if risk_level not in RISK_ORDER:
                raise ValidationError("risk_level 不在允许范围内")
            if effect not in EFFECTS:
                raise ValidationError("effect 不在允许范围内")
            reason = self._domain._text(reason, "reason", 500)
            expires_value = self._parse_expiry(expires_at, risk_level)

            def create() -> tuple[str, str, dict[str, Any]]:
                exception_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO exception_requests(exception_id,organization_id,rule_id,subject_id,"
                    "resource_id,effect,risk_level,reason,status,requested_by,expires_at,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (exception_id, organization_id, rule_id, subject_id, resource_id, effect,
                     risk_level, reason, "pending", actor_id, expires_value, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="exception.submitted",
                             resource_type="exception", resource_id=exception_id,
                             detail={"organization_id": organization_id, "rule_id": rule_id,
                                     "subject_id": subject_id, "resource_id": resource_id,
                                     "effect": effect, "risk_level": risk_level,
                                     "expires_at": expires_value},
                             occurred_at=self._now())
                return "exception", exception_id, {"exception_id": exception_id, "status": "pending"}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="submit_exception", payload=payload, create=create)

    def register_approver_scope(self, *, request_id: str, actor_id: str, approver_id: str,
                                organization_id: str, max_risk_level: str, tier: int,
                                rule_id: str = "*", resource_id: str = "*") -> WriteReceipt:
        """由管理员登记审批人负责范围，审批只能发生在范围内。"""

        payload = {"actor_id": actor_id, "approver_id": approver_id, "organization_id": organization_id,
                   "max_risk_level": max_risk_level, "tier": tier,
                   "rule_id": rule_id, "resource_id": resource_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._domain._actor(connection, actor_id)
            self._domain._require(actor, "admin")
            approver = self._domain._actor(connection, approver_id)
            if approver.role not in ("reviewer", "admin"):
                raise ValidationError("审批人必须是 reviewer 或 admin 角色")
            organization_id = self._domain._identifier(organization_id, "organization_id")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")
            rule_id = self._wildcard(rule_id, "rule_id")
            resource_id = self._wildcard(resource_id, "resource_id")
            if max_risk_level not in RISK_ORDER:
                raise ValidationError("max_risk_level 不在允许范围内")
            if isinstance(tier, bool) or not isinstance(tier, int) or not 1 <= tier <= 3:
                raise ValidationError("tier 必须是 1 到 3 的整数")
            if tier == 3 and approver.role != "admin":
                raise ValidationError("第三级审批必须由 admin 角色承担")

            def create() -> tuple[str, str, dict[str, Any]]:
                scope_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO approver_scopes(scope_id,actor_id,organization_id,rule_id,resource_id,"
                    "max_risk_level,tier,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (scope_id, approver_id, organization_id, rule_id, resource_id,
                     max_risk_level, tier, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="approver_scope.registered",
                             resource_type="approver_scope", resource_id=scope_id,
                             detail={"approver_id": approver_id, "organization_id": organization_id,
                                     "rule_id": rule_id, "resource_id": resource_id,
                                     "max_risk_level": max_risk_level, "tier": tier},
                             occurred_at=self._now())
                return "approver_scope", scope_id, {"scope_id": scope_id}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="register_approver_scope", payload=payload, create=create)

    def decide_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                         decision: str, comment: str = "") -> WriteReceipt:
        """对当前审批层级作出决定，最终一级批准在事务内完成冲突检查并激活。"""

        payload = {"actor_id": actor_id, "exception_id": exception_id,
                   "decision": decision, "comment": comment}
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            row = self._load(connection, exception_id)
            if decision not in DECISIONS:
                raise ValidationError("decision 不在允许范围内")
            comment = self._comment(comment)

            def create() -> tuple[str, str, dict[str, Any]]:
                if row["status"] != "pending":
                    raise ConflictError("该申请已有最终结论")
                if self._moment(row["expires_at"]) <= self._domain.clock.now():
                    raise ConflictError("申请已超过有效期，无法审批")
                if actor.actor_id == row["requested_by"]:
                    raise PermissionDenied("不能审批自己提交的申请")
                approvals = connection.execute(
                    "SELECT approver_id FROM exception_approvals WHERE exception_id=?",
                    (exception_id,),
                ).fetchall()
                if any(item["approver_id"] == actor.actor_id for item in approvals):
                    raise PermissionDenied("同一审批人不能重复审批同一申请")
                tier = len(approvals) + 1
                if not self._scope_covers(connection, actor.actor_id, row, tier):
                    raise PermissionDenied("审批人负责范围不包含该例外")
                now = self._now()
                connection.execute(
                    "INSERT INTO exception_approvals(exception_id,tier,approver_id,decision,comment,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (exception_id, tier, actor.actor_id, decision, comment, now),
                )
                if decision == "rejected":
                    connection.execute(
                        "UPDATE exception_requests SET status='rejected', decided_at=? WHERE exception_id=?",
                        (now, exception_id),
                    )
                    append_event(connection, actor_id=actor.actor_id, action="exception.rejected",
                                 resource_type="exception", resource_id=exception_id,
                                 detail={"tier": tier, "comment": comment}, occurred_at=now)
                    return "exception", exception_id, {"exception_id": exception_id, "status": "rejected"}
                required = REQUIRED_TIERS[row["risk_level"]]
                if tier < required:
                    append_event(connection, actor_id=actor.actor_id, action="exception.approved",
                                 resource_type="exception", resource_id=exception_id,
                                 detail={"tier": tier, "required_tiers": required}, occurred_at=now)
                    return "exception", exception_id, {"exception_id": exception_id,
                                                       "status": "pending", "approved_tiers": tier}
                self._ensure_no_conflict(connection, row)
                connection.execute(
                    "UPDATE exception_requests SET status='active', decided_at=? WHERE exception_id=?",
                    (now, exception_id),
                )
                event = append_event(connection, actor_id=actor.actor_id, action="exception.activated",
                                     resource_type="exception", resource_id=exception_id,
                                     detail={"required_tiers": required, "effect": row["effect"],
                                             "expires_at": row["expires_at"]},
                                     occurred_at=now)
                basis = self._approval_basis(connection, exception_id, event["event_hash"])
                connection.execute(
                    "UPDATE exception_requests SET approval_basis_json=? WHERE exception_id=?",
                    (canonical_json(basis), exception_id),
                )
                return "exception", exception_id, {"exception_id": exception_id, "status": "active"}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="decide_exception", payload=payload, create=create)

    def revoke_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                         reason: str) -> WriteReceipt:
        """提前撤销生效例外，或取消仍在待审批的申请。"""

        payload = {"actor_id": actor_id, "exception_id": exception_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            row = self._load(connection, exception_id)
            reason = self._domain._text(reason, "reason", 500)

            def create() -> tuple[str, str, dict[str, Any]]:
                status = row["status"]
                if status == "pending":
                    if actor.actor_id != row["requested_by"] and actor.role != "admin":
                        raise PermissionDenied("只有申请人或管理员可以取消待审批申请")
                    new_status, action = "cancelled", "exception.cancelled"
                elif status == "active":
                    if actor.role != "admin" and not self._any_scope_covers(connection, actor.actor_id, row):
                        raise PermissionDenied("只有管理员或负责范围内的审批人可以撤销生效例外")
                    new_status, action = "revoked", "exception.revoked"
                else:
                    raise ConflictError("当前状态不能撤销")
                now = self._now()
                connection.execute(
                    "UPDATE exception_requests SET status=?, ended_at=?, end_reason=? WHERE exception_id=?",
                    (new_status, now, reason, exception_id),
                )
                append_event(connection, actor_id=actor.actor_id, action=action,
                             resource_type="exception", resource_id=exception_id,
                             detail={"reason": reason, "previous_status": status}, occurred_at=now)
                return "exception", exception_id, {"exception_id": exception_id, "status": new_status}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="revoke_exception", payload=payload, create=create)

    def record_exception_usage(self, *, request_id: str, actor_id: str, exception_id: str,
                               action: str, detail: dict[str, Any] | None = None) -> WriteReceipt:
        """记录一次例外使用，并把批准依据快照进使用记录与审计链。"""

        if detail is not None and not isinstance(detail, dict):
            raise ValidationError("detail 必须是对象")
        detail = detail or {}
        payload = {"actor_id": actor_id, "exception_id": exception_id,
                   "action": action, "detail": detail}
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            row = self._load(connection, exception_id)
            action = self._domain._text(action, "action", 120)

            def create() -> tuple[str, str, dict[str, Any]]:
                if row["status"] != "active":
                    raise ConflictError("例外不在生效状态，不能使用")
                if actor.actor_id != row["subject_id"]:
                    raise PermissionDenied("只有例外限定的主体可以使用该例外")
                basis = json.loads(row["approval_basis_json"])
                usage_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO exception_usages(usage_id,exception_id,actor_id,action,detail_json,"
                    "approval_basis_json,created_at) VALUES(?,?,?,?,?,?,?)",
                    (usage_id, exception_id, actor.actor_id, action, canonical_json(detail),
                     row["approval_basis_json"], now),
                )
                append_event(connection, actor_id=actor.actor_id, action="exception.used",
                             resource_type="exception", resource_id=exception_id,
                             detail={"usage_id": usage_id, "action": action,
                                     "basis_hash": digest(basis)},
                             occurred_at=now)
                return "exception_usage", usage_id, {"usage_id": usage_id, "exception_id": exception_id}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="record_exception_usage", payload=payload, create=create)

    def review_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                         outcome: str, notes: str) -> WriteReceipt:
        """对已结束的例外进行事后复盘，复盘后状态变为 closed。"""

        payload = {"actor_id": actor_id, "exception_id": exception_id,
                   "outcome": outcome, "notes": notes}
        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            self._domain._require(actor, "admin", "reviewer")
            row = self._load(connection, exception_id)
            if outcome not in REVIEW_OUTCOMES:
                raise ValidationError("outcome 不在允许范围内")
            notes = self._domain._text(notes, "notes", 500)

            def create() -> tuple[str, str, dict[str, Any]]:
                if row["status"] == "closed":
                    raise ConflictError("该例外已完成复盘")
                if row["status"] not in ("expired", "revoked") or row["decided_at"] is None:
                    raise ConflictError("例外尚未结束，不能复盘")
                usage_count = self._usage_count(connection, exception_id)
                now = self._now()
                connection.execute(
                    "INSERT INTO exception_reviews(exception_id,outcome,notes,reviewed_by,reviewed_at) "
                    "VALUES(?,?,?,?,?)",
                    (exception_id, outcome, notes, actor.actor_id, now),
                )
                connection.execute(
                    "UPDATE exception_requests SET status='closed' WHERE exception_id=?",
                    (exception_id,),
                )
                append_event(connection, actor_id=actor.actor_id, action="exception.reviewed",
                             resource_type="exception", resource_id=exception_id,
                             detail={"outcome": outcome, "usage_count": usage_count}, occurred_at=now)
                return "exception", exception_id, {"exception_id": exception_id, "status": "closed"}

            return self._domain._idempotent(connection, request_id=request_id,
                                            action="review_exception", payload=payload, create=create)

    def get_exception(self, *, actor_id: str, exception_id: str) -> dict[str, Any]:
        """返回例外详情、审批链、批准依据与复盘结果。"""

        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            row = self._load(connection, exception_id)
            if actor.role not in ("admin", "auditor", "reviewer") and actor.actor_id != row["requested_by"]:
                raise PermissionDenied("不能查看该例外")
            approvals = connection.execute(
                "SELECT tier, approver_id, decision, comment, decided_at FROM exception_approvals "
                "WHERE exception_id=? ORDER BY tier",
                (exception_id,),
            ).fetchall()
            review = connection.execute(
                "SELECT outcome, notes, reviewed_by, reviewed_at FROM exception_reviews "
                "WHERE exception_id=?",
                (exception_id,),
            ).fetchone()
            return {
                "exception_id": row["exception_id"],
                "organization_id": row["organization_id"],
                "rule_id": row["rule_id"],
                "subject_id": row["subject_id"],
                "resource_id": row["resource_id"],
                "effect": row["effect"],
                "risk_level": row["risk_level"],
                "reason": row["reason"],
                "status": row["status"],
                "requested_by": row["requested_by"],
                "expires_at": row["expires_at"],
                "created_at": row["created_at"],
                "decided_at": row["decided_at"],
                "ended_at": row["ended_at"],
                "end_reason": row["end_reason"],
                "approvals": [dict(item) for item in approvals],
                "approval_basis": json.loads(row["approval_basis_json"]) if row["approval_basis_json"] else None,
                "usage_count": self._usage_count(connection, exception_id),
                "review": dict(review) if review else None,
            }

    def list_active_exceptions(self, *, actor_id: str) -> list[dict[str, Any]]:
        """管理视图：列出当前生效的例外及其剩余风险。"""

        with self.database.transaction(immediate=True) as connection:
            self._sweep_expired(connection)
            actor = self._domain._actor(connection, actor_id)
            self._domain._require(actor, "admin", "auditor")
            rows = connection.execute(
                "SELECT * FROM exception_requests WHERE status='active' ORDER BY expires_at, exception_id"
            ).fetchall()
            now = self._domain.clock.now()
            items = []
            for row in rows:
                usage_count = self._usage_count(connection, row["exception_id"])
                seconds_remaining = max(0, int((self._moment(row["expires_at"]) - now).total_seconds()))
                items.append({
                    "exception_id": row["exception_id"],
                    "organization_id": row["organization_id"],
                    "rule_id": row["rule_id"],
                    "subject_id": row["subject_id"],
                    "resource_id": row["resource_id"],
                    "effect": row["effect"],
                    "risk_level": row["risk_level"],
                    "requested_by": row["requested_by"],
                    "expires_at": row["expires_at"],
                    "created_at": row["created_at"],
                    "residual_risk": {
                        "level": row["risk_level"],
                        "score": RISK_WEIGHT[row["risk_level"]] * (1 + usage_count),
                        "seconds_remaining": seconds_remaining,
                        "usage_count": usage_count,
                    },
                })
            return items

    def list_exception_usages(self, *, actor_id: str, exception_id: str) -> list[dict[str, Any]]:
        """列出例外的使用记录，每条都携带批准依据。"""

        with self.database.transaction(immediate=True) as connection:
            actor = self._domain._actor(connection, actor_id)
            self._domain._require(actor, "admin", "auditor", "reviewer")
            self._load(connection, exception_id)
            rows = connection.execute(
                "SELECT * FROM exception_usages WHERE exception_id=? ORDER BY created_at, usage_id",
                (exception_id,),
            ).fetchall()
            return [
                {"usage_id": row["usage_id"], "exception_id": row["exception_id"],
                 "actor_id": row["actor_id"], "action": row["action"],
                 "detail": json.loads(row["detail_json"]),
                 "approval_basis": json.loads(row["approval_basis_json"]),
                 "created_at": row["created_at"]}
                for row in rows
            ]
