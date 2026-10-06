"""治理规则例外的申请、分级审批、生效控制与复盘服务。"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .exceptions import (
    CLOSED_STATUSES,
    LEVELS_BY_RISK,
    MAX_TTL_SECONDS,
    ActiveExceptionReport,
    ApproverScope,
    ExceptionDecision,
    ExceptionRequest,
    ExceptionReview,
)
from .models import Actor
from .storage import Database

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
USE_ACTOR_ROLES = frozenset({"admin", "operator", "reviewer"})
REVIEW_ROLES = frozenset({"admin", "reviewer", "auditor"})


def risk_band(score: int) -> str:
    """把 0-100 的风险分归入固定等级。"""

    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _parse_ts(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是带时区的 ISO-8601 时间") from exc
    if dt.tzinfo is None:
        raise ValidationError(f"{field} 必须显式包含时区")
    return dt.astimezone(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ExceptionService:
    """协调例外审批的权限、分级、互斥、到期与可追溯规则。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    # ---- 基础辅助 -------------------------------------------------------

    def _now_dt(self) -> datetime:
        return self.clock.now().astimezone(timezone.utc)

    def _now(self) -> str:
        return _fmt(self._now_dt())

    def _identifier(self, value: Any, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: Any, field: str, limit: int = 500) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _id_set(self, value: Any, field: str, wildcard: bool = False) -> tuple[str, ...]:
        if not isinstance(value, list) or not value:
            raise ValidationError(f"{field} 必须是非空数组")
        items = []
        for item in value:
            item = str(item).strip()
            if wildcard and item == "*":
                items.append("*")
            elif not IDENTIFIER.fullmatch(item):
                raise ValidationError(f"{field} 格式无效")
            else:
                items.append(item)
        if len(set(items)) != len(items):
            raise ValidationError(f"{field} 不能包含重复项")
        return tuple(items)

    def _short_list(self, value: Any, field: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValidationError(f"{field} 必须是数组")
        items = [self._text(item, field, 300) for item in value]
        return tuple(items)

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"], row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _require(self, actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _replay(self, connection, *, request_id: str, action: str,
                payload: dict[str, Any]):
        """若 request_id 已处理则返回原回执；内容不一致则冲突；否则返回 None。"""

        from .models import WriteReceipt
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute("SELECT * FROM request_receipts WHERE request_id=?", (request_id,)).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return WriteReceipt(request_id, row["resource_type"], row["resource_id"], True,
                                json.loads(row["response_json"]))
        return None

    def _store_receipt(self, connection, *, request_id: str, action: str,
                       payload: dict[str, Any], resource_type: str, resource_id: str,
                       response: dict[str, Any]):
        from .models import WriteReceipt
        request_id = self._identifier(request_id, "request_id")
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, digest(payload), resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return WriteReceipt(request_id, resource_type, resource_id, False, response)

    def _load_exception(self, connection, exception_id: str):
        row = connection.execute(
            "SELECT * FROM exception_requests WHERE exception_id=?", (exception_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("例外不存在")
        return row

    def _request_from_row(self, row) -> ExceptionRequest:
        return ExceptionRequest(
            exception_id=row["exception_id"], rule_id=row["rule_id"],
            subject_ids=tuple(json.loads(row["subject_ids_json"])),
            resource_ids=tuple(json.loads(row["resource_ids_json"])),
            risk_level=row["risk_level"],
            risk_factors=tuple(json.loads(row["risk_factors_json"])),
            mitigations=tuple(json.loads(row["mitigations_json"])),
            risk_score=row["risk_score"], reason=row["reason"],
            requested_by=row["requested_by"], status=row["status"],
            effective_at=row["effective_at"], expires_at=row["expires_at"],
            created_at=row["created_at"], approved_at=row["approved_at"],
            revoked_by=row["revoked_by"], revoked_at=row["revoked_at"],
            revoke_reason=row["revoke_reason"], expired_at=row["expired_at"],
        )

    def _scope(self, connection, approver_id: str) -> ApproverScope:
        row = connection.execute("SELECT * FROM approver_scopes WHERE approver_id=?", (approver_id,)).fetchone()
        if row is None:
            raise PermissionDenied("该操作者没有登记审批范围，不能审批例外")
        return ApproverScope(
            approver_id=row["approver_id"], level=row["level"],
            rule_ids=frozenset(json.loads(row["rule_ids_json"])),
            resource_ids=frozenset(json.loads(row["resource_ids_json"])),
            subject_ids=frozenset(json.loads(row["subject_ids_json"])),
        )

    def _scope_gap(self, scope: ApproverScope, rule_id: str,
                   subject_ids: tuple[str, ...], resource_ids: tuple[str, ...]) -> str | None:
        """返回越权范围的人类可读说明；完全覆盖时返回 None。"""

        if "*" not in scope.rule_ids and rule_id not in scope.rule_ids:
            return f"规则 {rule_id} 不在审批范围"
        if "*" not in scope.resource_ids:
            missing = sorted(set(resource_ids) - scope.resource_ids)
            if missing:
                return f"资源 {','.join(missing)} 不在审批范围"
        if "*" not in scope.subject_ids:
            missing = sorted(set(subject_ids) - scope.subject_ids)
            if missing:
                return f"主体 {','.join(missing)} 不在审批范围"
        return None

    def _sweep(self, connection) -> int:
        """把已到期但仍是 approved 的例外落盘为 expired，返回处理数量。"""

        now_text = self._now()
        rows = connection.execute(
            "SELECT * FROM exception_requests WHERE status='approved' AND expires_at<=?",
            (now_text,),
        ).fetchall()
        for row in rows:
            connection.execute(
                "UPDATE exception_requests SET status='expired', expired_at=? WHERE exception_id=?",
                (now_text, row["exception_id"]),
            )
            append_event(connection, actor_id="system", action="exception.expired",
                         resource_type="exception", resource_id=row["exception_id"],
                         detail={"expires_at": row["expires_at"], "swept_at": now_text},
                         occurred_at=now_text)
        return len(rows)

    def sweep_expired(self) -> int:
        """供管理方主动触发的到期清扫。"""

        with self.database.transaction(immediate=True) as connection:
            return self._sweep(connection)

    # ---- 审批范围登记 ---------------------------------------------------

    def register_approver_scope(self, *, request_id: str, actor_id: str, approver_id: str,
                                level: int, rule_ids: list[str],
                                resource_ids: list[str] | None = None,
                                subject_ids: list[str] | None = None) -> Any:
        payload = {"actor_id": actor_id, "approver_id": approver_id, "level": level,
                   "rule_ids": rule_ids, "resource_ids": resource_ids or ["*"],
                   "subject_ids": subject_ids or ["*"]}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="register_approver_scope", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "admin")
            approver = self._actor(connection, approver_id)
            try:
                level = int(level)
            except (TypeError, ValueError) as exc:
                raise ValidationError("level 必须是 1-3 的整数") from exc
            if level not in (1, 2, 3):
                raise ValidationError("level 必须是 1-3 的整数")
            rules = tuple(self._id_set(rule_ids, "rule_ids", wildcard=True))
            resources = tuple(self._id_set(resource_ids or ["*"], "resource_ids", wildcard=True))
            subjects = tuple(self._id_set(subject_ids or ["*"], "subject_ids", wildcard=True))
            connection.execute(
                "INSERT INTO approver_scopes(approver_id,level,rule_ids_json,resource_ids_json,"
                "subject_ids_json,created_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(approver_id) DO UPDATE SET level=excluded.level,"
                "rule_ids_json=excluded.rule_ids_json,resource_ids_json=excluded.resource_ids_json,"
                "subject_ids_json=excluded.subject_ids_json",
                (approver_id, level, canonical_json(list(rules)), canonical_json(list(resources)),
                 canonical_json(list(subjects)), self._now()),
            )
            append_event(connection, actor_id=actor_id, action="approver_scope.registered",
                         resource_type="approver_scope", resource_id=approver_id,
                         detail={"level": level, "rule_ids": list(rules),
                                 "resource_ids": list(resources), "subject_ids": list(subjects)},
                         occurred_at=self._now())
            return self._store_receipt(connection, request_id=request_id,
                                       action="register_approver_scope", payload=payload,
                                       resource_type="approver_scope", resource_id=approver_id,
                                       response={"approver_id": approver_id, "level": level})

    # ---- 申请 -----------------------------------------------------------

    def apply_exception(self, *, request_id: str, actor_id: str, rule_id: str,
                        subject_ids: list[str], resource_ids: list[str], reason: str,
                        expires_at: Any, risk_score: int, effective_at: Any = None,
                        risk_factors: list[str] | None = None,
                        mitigations: list[str] | None = None) -> Any:
        rule_id_v = self._identifier(rule_id, "rule_id")
        subjects = self._id_set(subject_ids, "subject_ids")
        resources = self._id_set(resource_ids, "resource_ids")
        reason_v = self._text(reason, "reason")
        try:
            score = int(risk_score)
        except (TypeError, ValueError) as exc:
            raise ValidationError("risk_score 必须是 0-100 的整数") from exc
        if not 0 <= score <= 100:
            raise ValidationError("risk_score 必须在 0 到 100 之间")
        level_name = risk_band(score)
        start = _parse_ts(effective_at, "effective_at") if effective_at is not None else self._now_dt()
        end = _parse_ts(expires_at, "expires_at")
        if end <= start:
            raise ValidationError("expires_at 必须晚于 effective_at")
        ttl = int((end - start).total_seconds())
        max_ttl = MAX_TTL_SECONDS[level_name]
        if ttl > max_ttl:
            raise ValidationError(
                f"{level_name} 风险例外最长允许 {max_ttl} 秒，本次申请为 {ttl} 秒；到期时间必须显式且受限"
            )
        factors = self._short_list(risk_factors, "risk_factors")
        mitigates = self._short_list(mitigations, "mitigations")
        payload = {"actor_id": actor_id, "rule_id": rule_id_v, "subject_ids": list(subjects),
                   "resource_ids": list(resources), "reason": reason_v,
                   "expires_at": _fmt(end), "effective_at": _fmt(start),
                   "risk_score": score, "risk_factors": list(factors), "mitigations": list(mitigates)}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="apply_exception", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, "admin", "operator", "reviewer")
            exception_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO exception_requests(exception_id,rule_id,subject_ids_json,resource_ids_json,"
                "risk_level,risk_factors_json,mitigations_json,risk_score,reason,requested_by,status,"
                "effective_at,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', ?, ?, ?)",
                (exception_id, rule_id_v, canonical_json(list(subjects)),
                 canonical_json(list(resources)), level_name, canonical_json(list(factors)),
                 canonical_json(list(mitigates)), score, reason_v, actor_id,
                 _fmt(start), _fmt(end), self._now()),
            )
            append_event(connection, actor_id=actor_id, action="exception.applied",
                         resource_type="exception", resource_id=exception_id,
                         detail={"rule_id": rule_id_v, "subject_ids": list(subjects),
                                 "resource_ids": list(resources), "risk_level": level_name,
                                 "risk_score": score, "effective_at": _fmt(start),
                                 "expires_at": _fmt(end)},
                         occurred_at=self._now())
            return self._store_receipt(connection, request_id=request_id,
                                       action="apply_exception", payload=payload,
                                       resource_type="exception", resource_id=exception_id,
                                       response={"exception_id": exception_id,
                                                 "risk_level": level_name,
                                                 "required_levels": list(LEVELS_BY_RISK[level_name])})

    # ---- 分级审批 -------------------------------------------------------

    def decide_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                         level: int, decision: str, comment: str) -> Any:
        try:
            level = int(level)
        except (TypeError, ValueError) as exc:
            raise ValidationError("level 必须是 1-3 的整数") from exc
        if decision not in ("approved", "rejected"):
            raise ValidationError("decision 必须是 approved 或 rejected")
        comment_v = self._text(comment, "comment")
        exception_id = self._identifier(exception_id, "exception_id")
        payload = {"actor_id": actor_id, "exception_id": exception_id, "level": level,
                   "decision": decision, "comment": comment_v}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="decide_exception", payload=payload)
            if replay is not None:
                return replay
            self._sweep(connection)
            row = self._load_exception(connection, exception_id)
            scope = self._scope(connection, actor_id)
            if scope.level != level:
                raise PermissionDenied(f"该审批人登记的是第 {scope.level} 级，不能作出第 {level} 级决定")
            required = LEVELS_BY_RISK[row["risk_level"]]
            if level not in required:
                raise ValidationError(f"{row['risk_level']} 风险例外不需要第 {level} 级审批")
            if row["status"] != "pending":
                raise ConflictError(f"例外当前状态为 {row['status']}，不能再审批")
            prior = connection.execute(
                "SELECT * FROM exception_decisions WHERE exception_id=? ORDER BY level",
                (exception_id,),
            ).fetchall()
            prior_levels = {item["level"] for item in prior}
            if level in prior_levels:
                raise ConflictError(f"第 {level} 级已经作出决定，不能重复审批")
            for needed in required:
                if needed >= level:
                    break
                if needed not in prior_levels:
                    raise ValidationError(f"必须先完成第 {needed} 级审批，不能越级")
            if any(item["approver_id"] == actor_id for item in prior):
                raise PermissionDenied("同一审批人不能在多个层级重复审批同一例外")
            if row["requested_by"] == actor_id:
                raise PermissionDenied("申请人不能审批自己提交的例外")
            subjects = tuple(json.loads(row["subject_ids_json"]))
            resources = tuple(json.loads(row["resource_ids_json"]))
            gap = self._scope_gap(scope, row["rule_id"], subjects, resources)
            if gap:
                raise PermissionDenied(gap)
            now_text = self._now()
            if decision == "rejected":
                event = append_event(connection, actor_id=actor_id, action="exception.rejected",
                                     resource_type="exception", resource_id=exception_id,
                                     detail={"level": level, "comment": comment_v},
                                     occurred_at=now_text)
                connection.execute(
                    "INSERT INTO exception_decisions(exception_id,level,approver_id,decision,comment,"
                    "audit_event_hash,decided_at) VALUES(?,?,?,?,?,?,?)",
                    (exception_id, level, actor_id, "rejected", comment_v,
                     event["event_hash"], now_text),
                )
                connection.execute(
                    "UPDATE exception_requests SET status='rejected' WHERE exception_id=?",
                    (exception_id,),
                )
                return self._store_receipt(connection, request_id=request_id,
                                           action="decide_exception", payload=payload,
                                           resource_type="exception", resource_id=exception_id,
                                           response={"exception_id": exception_id, "status": "rejected"})

            event = append_event(connection, actor_id=actor_id, action="exception.approved",
                                 resource_type="exception", resource_id=exception_id,
                                 detail={"level": level, "comment": comment_v,
                                         "required_levels": list(required)},
                                 occurred_at=now_text)
            connection.execute(
                "INSERT INTO exception_decisions(exception_id,level,approver_id,decision,comment,"
                "audit_event_hash,decided_at) VALUES(?,?,?,?,?,?,?)",
                (exception_id, level, actor_id, "approved", comment_v,
                 event["event_hash"], now_text),
            )
            status = "pending_next_level"
            next_level: int | None = (required[required.index(level) + 1]
                                      if required.index(level) + 1 < len(required) else None)
            if level == required[-1]:
                if _parse_ts(row["expires_at"], "expires_at") <= self._now_dt():
                    raise ConflictError("例外有效期已经结束，不能完成最终批准")
                subject_set = set(subjects)
                resource_set = set(resources)
                others = connection.execute(
                    "SELECT * FROM exception_requests WHERE status='approved' AND rule_id=? "
                    "AND exception_id!=? AND effective_at < ? AND expires_at > ?",
                    (row["rule_id"], exception_id, row["expires_at"], row["effective_at"]),
                ).fetchall()
                conflicts = []
                for other in others:
                    if subject_set & set(json.loads(other["subject_ids_json"])) and \
                            resource_set & set(json.loads(other["resource_ids_json"])):
                        conflicts.append(other["exception_id"])
                if conflicts:
                    raise ConflictError(
                        "与已生效且时间窗重叠的例外冲突，不能同时生效: " + ",".join(sorted(conflicts))
                    )
                connection.execute(
                    "UPDATE exception_requests SET status='approved', approved_at=? WHERE exception_id=?",
                    (now_text, exception_id),
                )
                status = "approved"
                next_level = None
            return self._store_receipt(connection, request_id=request_id,
                                       action="decide_exception", payload=payload,
                                       resource_type="exception", resource_id=exception_id,
                                       response={"exception_id": exception_id, "status": status,
                                                 "next_level": next_level})

    # ---- 提前撤销 -------------------------------------------------------

    def revoke_exception(self, *, request_id: str, actor_id: str,
                         exception_id: str, reason: str) -> Any:
        reason_v = self._text(reason, "revoke_reason")
        exception_id = self._identifier(exception_id, "exception_id")
        payload = {"actor_id": actor_id, "exception_id": exception_id, "reason": reason_v}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="revoke_exception", payload=payload)
            if replay is not None:
                return replay
            self._sweep(connection)
            row = self._load_exception(connection, exception_id)
            if row["status"] != "approved":
                raise ConflictError(f"例外当前状态为 {row['status']}，只有生效中的例外可以撤销")
            authorized = actor.role == "admin"
            if not authorized:
                try:
                    scope = self._scope(connection, actor_id)
                except PermissionDenied:
                    scope = None
                if scope is not None and row["requested_by"] != actor_id:
                    gap = self._scope_gap(
                        scope, row["rule_id"],
                        tuple(json.loads(row["subject_ids_json"])),
                        tuple(json.loads(row["resource_ids_json"])),
                    )
                    authorized = gap is None
            if not authorized:
                raise PermissionDenied("只有管理员或覆盖该例外范围的审批人可以撤销")
            now_text = self._now()
            connection.execute(
                "UPDATE exception_requests SET status='revoked', revoked_by=?, revoked_at=?, "
                "revoke_reason=? WHERE exception_id=?",
                (actor_id, now_text, reason_v, exception_id),
            )
            append_event(connection, actor_id=actor_id, action="exception.revoked",
                         resource_type="exception", resource_id=exception_id,
                         detail={"reason": reason_v}, occurred_at=now_text)
            return self._store_receipt(connection, request_id=request_id,
                                       action="revoke_exception", payload=payload,
                                       resource_type="exception", resource_id=exception_id,
                                       response={"exception_id": exception_id, "status": "revoked"})

    # ---- 使用例外并留下批准依据 -----------------------------------------

    def use_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                      subject_id: str, resource_id: str, action: str, reference: str,
                      payload: dict[str, Any] | None = None) -> Any:
        exception_id = self._identifier(exception_id, "exception_id")
        subject_id = self._identifier(subject_id, "subject_id")
        resource_id = self._identifier(resource_id, "resource_id")
        action_v = self._identifier(action, "action")
        reference_v = self._text(reference, "reference", 300)
        if payload is not None and not isinstance(payload, dict):
            raise ValidationError("payload 必须是对象")
        payload_v: dict[str, Any] = payload or {}
        payload_inner = {"actor_id": actor_id, "exception_id": exception_id, "subject_id": subject_id,
                        "resource_id": resource_id, "action": action_v, "reference": reference_v,
                        "payload": payload_v}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="use_exception", payload=payload_inner)
            if replay is not None:
                return replay
            self._require(actor, *USE_ACTOR_ROLES)
            self._sweep(connection)
            row = self._load_exception(connection, exception_id)
            subjects = tuple(json.loads(row["subject_ids_json"]))
            resources = tuple(json.loads(row["resource_ids_json"]))
            now_dt = self._now_dt()
            if row["status"] != "approved":
                raise ConflictError(f"例外当前状态为 {row['status']}，不能作为放行依据")
            if _parse_ts(row["effective_at"], "effective_at") > now_dt:
                raise ConflictError("例外尚未到生效时间")
            if _parse_ts(row["expires_at"], "expires_at") < now_dt:
                raise ConflictError("例外已经到期")
            if subject_id not in subjects:
                raise PermissionDenied(f"主体 {subject_id} 不在例外授权范围内")
            if resource_id not in resources:
                raise PermissionDenied(f"资源 {resource_id} 不在例外授权范围内")
            now_text = self._now()
            decision_rows = connection.execute(
                "SELECT * FROM exception_decisions WHERE exception_id=? ORDER BY level",
                (exception_id,),
            ).fetchall()
            use_id = uuid.uuid4().hex
            basis: dict[str, Any] = {
                "exception_id": exception_id,
                "rule_id": row["rule_id"],
                "risk_level": row["risk_level"],
                "approved_at": row["approved_at"],
                "effective_at": row["effective_at"],
                "expires_at": row["expires_at"],
                "subject_ids": list(subjects),
                "resource_ids": list(resources),
                "decisions": [
                    {"level": item["level"], "approver_id": item["approver_id"],
                     "decision": item["decision"], "audit_event_hash": item["audit_event_hash"],
                     "decided_at": item["decided_at"]}
                    for item in decision_rows
                ],
                "verified_at": now_text,
            }
            event = append_event(connection, actor_id=actor_id, action="exception.used",
                                 resource_type="exception_use", resource_id=use_id,
                                 detail={"exception_id": exception_id, "subject_id": subject_id,
                                         "resource_id": resource_id, "action": action_v,
                                         "reference": reference_v, "basis": basis},
                                 occurred_at=now_text)
            basis["use_audit_event_hash"] = event["event_hash"]
            connection.execute(
                "INSERT INTO exception_uses(use_id,exception_id,subject_id,resource_id,action,"
                "reference,payload_json,basis_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (use_id, exception_id, subject_id, resource_id, action_v, reference_v,
                 canonical_json(payload_v), canonical_json(basis), now_text),
            )
            return self._store_receipt(connection, request_id=request_id,
                                       action="use_exception", payload=payload_inner,
                                       resource_type="exception_use", resource_id=use_id,
                                       response={"use_id": use_id, "exception_id": exception_id,
                                                 "basis": basis})

    def trace_use(self, use_id: str) -> dict[str, Any]:
        """回溯一次例外使用，逐条核验其引用的批准审计事件。"""

        row = self.database.connection.execute(
            "SELECT * FROM exception_uses WHERE use_id=?", (use_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("使用记录不存在")
        basis = json.loads(row["basis_json"])
        checks = []
        for item in basis.get("decisions", []):
            event_row = self.database.connection.execute(
                "SELECT * FROM audit_events WHERE event_hash=?", (item["audit_event_hash"],)
            ).fetchone()
            checks.append({
                "level": item["level"], "approver_id": item["approver_id"],
                "audit_event_hash": item["audit_event_hash"],
                "found": event_row is not None,
                "matches_exception": event_row is not None and event_row["resource_id"] == row["exception_id"],
            })
        used_event = self.database.connection.execute(
            "SELECT * FROM audit_events WHERE event_hash=?", (basis.get("use_audit_event_hash"),)
        ).fetchone()
        exception_row = self.database.connection.execute(
            "SELECT * FROM exception_requests WHERE exception_id=?", (row["exception_id"],)
        ).fetchone()
        return {
            "use": {"use_id": row["use_id"], "exception_id": row["exception_id"],
                    "subject_id": row["subject_id"], "resource_id": row["resource_id"],
                    "action": row["action"], "reference": row["reference"],
                    "payload": json.loads(row["payload_json"]), "created_at": row["created_at"]},
            "exception_status": exception_row["status"] if exception_row else None,
            "basis": basis,
            "basis_checks": checks,
            "basis_intact": all(c["found"] and c["matches_exception"] for c in checks) and used_event is not None,
        }

    # ---- 事后复盘 -------------------------------------------------------

    def record_review(self, *, request_id: str, actor_id: str, exception_id: str,
                      summary: str, findings: list[str], residual_risk_score: int) -> Any:
        exception_id = self._identifier(exception_id, "exception_id")
        summary_v = self._text(summary, "summary")
        findings_v = self._short_list(findings, "findings")
        try:
            score = int(residual_risk_score)
        except (TypeError, ValueError) as exc:
            raise ValidationError("residual_risk_score 必须是 0-100 的整数") from exc
        if not 0 <= score <= 100:
            raise ValidationError("residual_risk_score 必须在 0 到 100 之间")
        level_name = risk_band(score)
        payload = {"actor_id": actor_id, "exception_id": exception_id, "summary": summary_v,
                   "findings": list(findings_v), "residual_risk_level": level_name,
                   "residual_risk_score": score}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            replay = self._replay(connection, request_id=request_id,
                                  action="record_review", payload=payload)
            if replay is not None:
                return replay
            self._require(actor, *REVIEW_ROLES)
            self._sweep(connection)
            row = self._load_exception(connection, exception_id)
            if row["status"] not in CLOSED_STATUSES:
                raise ConflictError(
                    f"例外当前状态为 {row['status']}：只有已到期或已撤销的例外才能复盘"
                )
            review_id = uuid.uuid4().hex
            now_text = self._now()
            connection.execute(
                "INSERT INTO exception_reviews(review_id,exception_id,reviewer_id,summary,"
                "findings_json,residual_risk_level,residual_risk_score,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (review_id, exception_id, actor_id, summary_v,
                 canonical_json(list(findings_v)), level_name, score, now_text),
            )
            append_event(connection, actor_id=actor_id, action="exception.reviewed",
                         resource_type="exception_review", resource_id=review_id,
                         detail={"exception_id": exception_id, "summary": summary_v,
                                 "findings": list(findings_v),
                                 "residual_risk_level": level_name,
                                 "residual_risk_score": score},
                         occurred_at=now_text)
            return self._store_receipt(connection, request_id=request_id,
                                       action="record_review", payload=payload,
                                       resource_type="exception_review", resource_id=review_id,
                                       response={"review_id": review_id,
                                                 "exception_id": exception_id,
                                                 "residual_risk_level": level_name,
                                                 "residual_risk_score": score})

    # ---- 查询与管理报告 -------------------------------------------------

    def describe_exception(self, exception_id: str) -> dict[str, Any]:
        exception_id = self._identifier(exception_id, "exception_id")
        with self.database.transaction(immediate=True) as connection:
            self._sweep(connection)
            row = self._load_exception(connection, exception_id)
            decisions = [
                ExceptionDecision(item["exception_id"], item["level"], item["approver_id"],
                                  item["decision"], item["comment"], item["audit_event_hash"],
                                  item["decided_at"])
                for item in connection.execute(
                    "SELECT * FROM exception_decisions WHERE exception_id=? ORDER BY level",
                    (exception_id,)).fetchall()
            ]
            reviews = [
                ExceptionReview(item["review_id"], item["exception_id"], item["reviewer_id"],
                                item["summary"], tuple(json.loads(item["findings_json"])),
                                item["residual_risk_level"], item["residual_risk_score"],
                                item["created_at"])
                for item in connection.execute(
                    "SELECT * FROM exception_reviews WHERE exception_id=? ORDER BY created_at",
                    (exception_id,)).fetchall()
            ]
            request = self._request_from_row(row)
        return {"exception": asdict(request),
                "decisions": [asdict(item) for item in decisions],
                "reviews": [asdict(item) for item in reviews]}

    def list_active_exceptions(self) -> list[dict[str, Any]]:
        """列当前生效例外及剩余风险；读取时同步完成到期清扫并落审计。"""

        with self.database.transaction(immediate=True) as connection:
            self._sweep(connection)
            now_dt = self._now_dt()
            now_text = _fmt(now_dt)
            rows = connection.execute(
                "SELECT * FROM exception_requests WHERE status='approved' AND effective_at<=? "
                "AND expires_at>? ORDER BY expires_at",
                (now_text, now_text),
            ).fetchall()
            reports = []
            for row in rows:
                decisions = connection.execute(
                    "SELECT * FROM exception_decisions WHERE exception_id=? ORDER BY level",
                    (row["exception_id"],),
                ).fetchall()
                use_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM exception_uses WHERE exception_id=?",
                    (row["exception_id"],),
                ).fetchone()["count"]
                review_row = connection.execute(
                    "SELECT * FROM exception_reviews WHERE exception_id=? "
                    "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    (row["exception_id"],),
                ).fetchone()
                remaining = max(0, int((_parse_ts(row["expires_at"], "expires_at") - now_dt).total_seconds()))
                notes = ["尚未复盘，剩余风险沿用申请评分"] if review_row is None else []
                if remaining < 24 * 3600:
                    notes.append(f"将在 {remaining} 秒内到期")
                if use_count:
                    notes.append(f"已被使用 {use_count} 次")
                if not json.loads(row["mitigations_json"]):
                    notes.append("未登记缓解措施")
                request = self._request_from_row(row)
                approvals = tuple(
                    ExceptionDecision(item["exception_id"], item["level"], item["approver_id"],
                                      item["decision"], item["comment"], item["audit_event_hash"],
                                      item["decided_at"]) for item in decisions
                )
                report = ActiveExceptionReport(
                    exception=request,
                    required_levels=LEVELS_BY_RISK[row["risk_level"]],
                    approvals=approvals,
                    seconds_remaining=remaining,
                    expired=False,
                    uses=use_count,
                    residual_risk_level=review_row["residual_risk_level"] if review_row else row["risk_level"],
                    residual_risk_score=review_row["residual_risk_score"] if review_row else row["risk_score"],
                    notes=tuple(notes),
                )
                reports.append(self._report_dict(report))
            return reports

    def _report_dict(self, report: ActiveExceptionReport) -> dict[str, Any]:
        return {
            "exception": asdict(report.exception),
            "required_levels": list(report.required_levels),
            "approvals": [asdict(item) for item in report.approvals],
            "seconds_remaining": report.seconds_remaining,
            "expired": report.expired,
            "uses": report.uses,
            "residual_risk_level": report.residual_risk_level,
            "residual_risk_score": report.residual_risk_score,
            "notes": list(report.notes),
        }
