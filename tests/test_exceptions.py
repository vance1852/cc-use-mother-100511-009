import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_governance_foundation.api import route
from ai_governance_foundation.audit import digest
from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, PermissionDenied, ValidationError
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database

T0 = datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)
DEFAULT_EXPIRY = "2026-09-25T20:00:00Z"  # T0 之后 12 小时


class ExceptionServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database, FixedClock(T0))
        self.exceptions = self.service.exceptions
        self._counter = 0
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        for actor_id, name, role in [
            ("op1", "业务负责人一", "operator"),
            ("op2", "业务负责人二", "operator"),
            ("rv1", "安全审批一", "reviewer"),
            ("rv2", "安全审批二", "reviewer"),
            ("rv3", "安全审批三", "reviewer"),
            ("au1", "审计员", "auditor"),
        ]:
            self.service.register_actor(request_id=actor_id, actor_id="a1", new_actor_id=actor_id,
                                        display_name=name, role=role, organization_id="o1")
        self._scope("sc-rv1", "rv1", "medium", 1)
        self._scope("sc-rv2", "rv2", "high", 2)
        self._scope("sc-a1", "a1", "high", 3)

    def tearDown(self):
        self.database.close()

    def _scope(self, request_id, approver_id, max_risk_level, tier, **overrides):
        params = {"request_id": request_id, "actor_id": "a1", "approver_id": approver_id,
                  "organization_id": "o1", "max_risk_level": max_risk_level, "tier": tier}
        params.update(overrides)
        return self.exceptions.register_approver_scope(**params)

    def _submit(self, **overrides):
        self._counter += 1
        params = {"request_id": f"exc-{self._counter}", "actor_id": "op1", "organization_id": "o1",
                  "rule_id": "model-access", "subject_id": "op1", "resource_id": "model-x",
                  "risk_level": "low", "reason": "重要演示临时放宽", "expires_at": DEFAULT_EXPIRY}
        params.update(overrides)
        return self.exceptions.submit_exception(**params)

    def _approve(self, exception_id, actor_id):
        return self.exceptions.decide_exception(request_id=f"dec-{exception_id}-{actor_id}",
                                                actor_id=actor_id, exception_id=exception_id,
                                                decision="approved", comment="同意")

    def _activate(self, **overrides):
        risk = overrides.get("risk_level", "low")
        exception_id = self._submit(**overrides).resource_id
        if risk == "high":
            self._scope(f"sc-rv3-{exception_id[:16]}", "rv3", "high", 1)
        for actor_id in {"low": ["rv1"], "medium": ["rv1", "rv2"], "high": ["rv3", "rv2", "a1"]}[risk]:
            self._approve(exception_id, actor_id)
        return exception_id

    def _advance(self, hours):
        self.service.clock = FixedClock(T0 + timedelta(hours=hours))

    def test_submit_requires_explicit_bounded_expiry(self):
        with self.assertRaises(ValidationError):
            self._submit(expires_at="")
        with self.assertRaises(ValidationError):
            self._submit(expires_at="2026-09-25T07:00:00Z")  # 已经过期
        with self.assertRaises(ValidationError):
            self._submit(expires_at="2026-09-25T20:00:00")  # 缺少时区
        with self.assertRaises(ValidationError):
            self._submit(risk_level="high", expires_at="2026-09-26T10:00:00Z")  # 超过 24 小时
        with self.assertRaises(ValidationError):
            self._submit(expires_at="2026-10-26T08:00:00Z")  # low 超过 30 天
        with self.assertRaises(ValidationError):
            self._submit(risk_level="extreme")
        with self.assertRaises(ValidationError):
            self._submit(effect="maybe")

    def test_low_risk_lifecycle(self):
        exception_id = self._activate()
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("active", detail["status"])
        self.assertEqual(1, len(detail["approvals"]))
        self.assertIsNotNone(detail["approval_basis"])
        self.exceptions.record_exception_usage(request_id="use-1", actor_id="op1",
                                               exception_id=exception_id, action="invoke_model",
                                               detail={"purpose": "demo"})
        self._advance(13)  # 越过 12 小时有效期
        self.assertEqual([], self.exceptions.list_active_exceptions(actor_id="a1"))
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("expired", detail["status"])
        self.assertEqual(1, detail["usage_count"])
        self.exceptions.review_exception(request_id="review-1", actor_id="rv1",
                                         exception_id=exception_id, outcome="no_issue",
                                         notes="演示结束，无异常调用")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("closed", detail["status"])
        self.assertEqual("no_issue", detail["review"]["outcome"])
        valid, _ = self.service.verify_audit()
        self.assertTrue(valid)

    def test_medium_risk_requires_two_ordered_tiers(self):
        exception_id = self._submit(risk_level="medium").resource_id
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "rv2")  # rv2 只持有第二级范围
        self._approve(exception_id, "rv1")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("pending", detail["status"])
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="dec-again", actor_id="rv1",
                                             exception_id=exception_id, decision="approved")
        self._approve(exception_id, "rv2")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("active", detail["status"])

    def test_high_risk_requires_three_tiers_and_risk_coverage(self):
        exception_id = self._submit(risk_level="high").resource_id
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "rv1")  # rv1 的范围最高只到 medium
        self._scope("sc-rv3-high", "rv3", "high", 1)
        self._approve(exception_id, "rv3")
        self._approve(exception_id, "rv2")
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "rv1")  # 第三级需要 admin 范围
        self._approve(exception_id, "a1")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
        self.assertEqual("active", detail["status"])
        self.assertEqual(3, len(detail["approvals"]))

    def test_requester_cannot_approve_own_exception(self):
        exception_id = self._submit(actor_id="a1", risk_level="high").resource_id
        self._scope("sc-rv3-own", "rv3", "high", 1)
        self._approve(exception_id, "rv3")
        self._approve(exception_id, "rv2")
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "a1")

    def test_approver_scope_limits_decisions(self):
        exception_id = self._submit().resource_id
        self._scope("sc-rv3-other", "rv3", "high", 1, rule_id="other-rule")
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "rv3")  # 范围只覆盖 other-rule
        with self.assertRaises(PermissionDenied):
            self._approve(exception_id, "op1")  # 业务操作员没有审批范围
        with self.assertRaises(ValidationError):
            self._scope("sc-op", "op1", "low", 1)  # operator 不能成为审批人
        with self.assertRaises(ValidationError):
            self._scope("sc-rv3-t3", "rv3", "high", 3)  # 第三级必须由 admin 承担
        with self.assertRaises(PermissionDenied):
            self.exceptions.register_approver_scope(request_id="sc-bad", actor_id="rv1",
                                                    approver_id="rv3", organization_id="o1",
                                                    max_risk_level="low", tier=1)

    def test_conflicting_exceptions_cannot_be_active_together(self):
        allow_id = self._activate(effect="allow")
        deny_id = self._submit(effect="deny").resource_id
        with self.assertRaises(ConflictError):
            self._approve(deny_id, "rv1")
        self.exceptions.revoke_exception(request_id="revoke-allow", actor_id="a1",
                                         exception_id=allow_id, reason="演示提前结束")
        self._approve(deny_id, "rv1")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=deny_id)
        self.assertEqual("active", detail["status"])
        second_deny = self._submit(effect="deny").resource_id
        self._approve(second_deny, "rv1")  # 相同 effect 不构成冲突

    def test_duplicate_submission_returns_same_result(self):
        first = self._submit()
        second = self.exceptions.submit_exception(
            request_id="exc-1", actor_id="op1", organization_id="o1", rule_id="model-access",
            subject_id="op1", resource_id="model-x", risk_level="low",
            reason="重要演示临时放宽", expires_at=DEFAULT_EXPIRY)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)
        with self.assertRaises(ConflictError):
            self.exceptions.submit_exception(
                request_id="exc-1", actor_id="op1", organization_id="o1", rule_id="model-access",
                subject_id="op1", resource_id="model-x", risk_level="low",
                reason="被篡改的理由", expires_at=DEFAULT_EXPIRY)
        decided = self._approve(first.resource_id, "rv1")
        replay = self._approve(first.resource_id, "rv1")
        self.assertTrue(replay.replayed)
        self.assertEqual(decided.resource_id, replay.resource_id)
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=first.resource_id)
        self.assertEqual(1, len(detail["approvals"]))

    def test_usage_requires_active_exception_and_named_subject(self):
        exception_id = self._submit().resource_id
        with self.assertRaises(ConflictError):
            self.exceptions.record_exception_usage(request_id="use-pending", actor_id="op1",
                                                   exception_id=exception_id, action="invoke_model")
        self._approve(exception_id, "rv1")
        with self.assertRaises(PermissionDenied):
            self.exceptions.record_exception_usage(request_id="use-other", actor_id="op2",
                                                   exception_id=exception_id, action="invoke_model")
        receipt = self.exceptions.record_exception_usage(request_id="use-ok", actor_id="op1",
                                                         exception_id=exception_id, action="invoke_model")
        self.assertFalse(receipt.replayed)
        self._advance(13)
        with self.assertRaises(ConflictError):
            self.exceptions.record_exception_usage(request_id="use-late", actor_id="op1",
                                                   exception_id=exception_id, action="invoke_model")

    def test_revoke_and_cancel_paths(self):
        pending_id = self._submit().resource_id
        with self.assertRaises(PermissionDenied):
            self.exceptions.revoke_exception(request_id="cancel-other", actor_id="op2",
                                             exception_id=pending_id, reason="越权取消")
        self.exceptions.revoke_exception(request_id="cancel-own", actor_id="op1",
                                         exception_id=pending_id, reason="不再需要")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=pending_id)
        self.assertEqual("cancelled", detail["status"])

        active_id = self._activate()
        with self.assertRaises(PermissionDenied):
            self.exceptions.revoke_exception(request_id="revoke-other", actor_id="op2",
                                             exception_id=active_id, reason="越权撤销")
        self.exceptions.revoke_exception(request_id="revoke-scoped", actor_id="rv1",
                                         exception_id=active_id, reason="风险变化提前收回")
        detail = self.exceptions.get_exception(actor_id="a1", exception_id=active_id)
        self.assertEqual("revoked", detail["status"])
        with self.assertRaises(ConflictError):
            self.exceptions.record_exception_usage(request_id="use-revoked", actor_id="op1",
                                                   exception_id=active_id, action="invoke_model")

    def test_review_requires_ended_exception(self):
        active_id = self._activate()
        with self.assertRaises(ConflictError):
            self.exceptions.review_exception(request_id="review-early", actor_id="rv1",
                                             exception_id=active_id, outcome="no_issue", notes="尚未结束")
        self._advance(13)
        with self.assertRaises(ValidationError):
            self.exceptions.review_exception(request_id="review-bad", actor_id="rv1",
                                             exception_id=active_id, outcome="unknown", notes="无效结论")
        self.exceptions.review_exception(request_id="review-ok", actor_id="rv1",
                                         exception_id=active_id, outcome="process_gap",
                                         notes="演示类例外应默认更短期限")
        with self.assertRaises(ConflictError):
            self.exceptions.review_exception(request_id="review-again", actor_id="rv1",
                                             exception_id=active_id, outcome="no_issue", notes="重复复盘")

    def test_restart_does_not_reactivate_expired_exceptions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.sqlite3"
            first_db = Database(path)
            first = DomainService(first_db, FixedClock(T0))
            first.register_organization(request_id="org", actor_id="bootstrap",
                                        organization_id="o1", name="科研机构一")
            first.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="a1",
                                 display_name="管理员", role="admin", organization_id="o1")
            first.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                 display_name="业务负责人", role="operator", organization_id="o1")
            first.register_actor(request_id="rv1", actor_id="a1", new_actor_id="rv1",
                                 display_name="安全审批", role="reviewer", organization_id="o1")
            first.exceptions.register_approver_scope(request_id="sc1", actor_id="a1",
                                                     approver_id="rv1", organization_id="o1",
                                                     max_risk_level="low", tier=1)
            receipt = first.exceptions.submit_exception(
                request_id="exc", actor_id="op1", organization_id="o1", rule_id="model-access",
                subject_id="op1", resource_id="model-x", risk_level="low",
                reason="演示临时放宽", expires_at="2026-09-25T09:00:00Z")
            exception_id = receipt.resource_id
            first.exceptions.decide_exception(request_id="dec", actor_id="rv1",
                                              exception_id=exception_id, decision="approved")
            first_db.close()

            second_db = Database(path)
            second = DomainService(second_db, FixedClock(datetime(2026, 9, 26, 8, 0,
                                                                  tzinfo=timezone.utc)))
            detail = second.exceptions.get_exception(actor_id="a1", exception_id=exception_id)
            self.assertEqual("expired", detail["status"])
            self.assertEqual([], second.exceptions.list_active_exceptions(actor_id="a1"))
            with self.assertRaises(ConflictError):
                second.exceptions.record_exception_usage(request_id="use", actor_id="op1",
                                                         exception_id=exception_id, action="invoke_model")
            with self.assertRaises(ConflictError):
                second.exceptions.decide_exception(request_id="dec-again", actor_id="rv1",
                                                   exception_id=exception_id, decision="approved")
            actions = [event["action"] for event in second.audit_events()]
            self.assertIn("exception.expired", actions)
            valid, _ = second.verify_audit()
            self.assertTrue(valid)
            second_db.close()

    def test_active_listing_reports_residual_risk(self):
        exception_id = self._activate()
        self.exceptions.record_exception_usage(request_id="use-1", actor_id="op1",
                                               exception_id=exception_id, action="invoke_model")
        self.exceptions.record_exception_usage(request_id="use-2", actor_id="op1",
                                               exception_id=exception_id, action="invoke_model")
        items = self.exceptions.list_active_exceptions(actor_id="a1")
        self.assertEqual(1, len(items))
        risk = items[0]["residual_risk"]
        self.assertEqual("low", risk["level"])
        self.assertEqual(3, risk["score"])  # 权重 1 × (1 + 2 次使用)
        self.assertEqual(2, risk["usage_count"])
        self.assertGreater(risk["seconds_remaining"], 0)
        self.assertEqual(1, len(self.exceptions.list_active_exceptions(actor_id="au1")))
        with self.assertRaises(PermissionDenied):
            self.exceptions.list_active_exceptions(actor_id="op1")

    def test_usage_traces_back_to_approval_basis(self):
        exception_id = self._activate()
        self.exceptions.record_exception_usage(request_id="use-1", actor_id="op1",
                                               exception_id=exception_id, action="invoke_model")
        usages = self.exceptions.list_exception_usages(actor_id="au1", exception_id=exception_id)
        basis = usages[0]["approval_basis"]
        self.assertEqual(exception_id, basis["exception_id"])
        self.assertEqual("rv1", basis["approvals"][0]["approver_id"])
        events = self.service.audit_events()
        activated = next(event for event in events if event["action"] == "exception.activated")
        self.assertEqual(activated["event_hash"], basis["activation_event_hash"])
        used = next(event for event in events if event["action"] == "exception.used")
        self.assertEqual(digest(basis), used["detail"]["basis_hash"])

    def test_get_exception_visibility(self):
        exception_id = self._submit().resource_id
        detail = self.exceptions.get_exception(actor_id="op1", exception_id=exception_id)
        self.assertEqual("pending", detail["status"])
        with self.assertRaises(PermissionDenied):
            self.exceptions.get_exception(actor_id="op2", exception_id=exception_id)


class ExceptionApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database, FixedClock(T0))
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                    display_name="业务负责人", role="operator", organization_id="o1")
        self.service.register_actor(request_id="rv1", actor_id="a1", new_actor_id="rv1",
                                    display_name="安全审批", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="au1", actor_id="a1", new_actor_id="au1",
                                    display_name="审计员", role="auditor", organization_id="o1")
        self.service.exceptions.register_approver_scope(request_id="sc1", actor_id="a1",
                                                        approver_id="rv1", organization_id="o1",
                                                        max_risk_level="medium", tier=1)

    def tearDown(self):
        self.database.close()

    def _post(self, path, body, actor):
        return route(self.service, "POST", path, body, {"X-Actor-Id": actor})

    def test_exception_lifecycle_over_http(self):
        body = {"request_id": "api-exc", "organization_id": "o1", "rule_id": "model-access",
                "subject_id": "op1", "resource_id": "model-x", "risk_level": "low",
                "reason": "演示临时放宽", "expires_at": DEFAULT_EXPIRY}
        status, payload = self._post("/exception-requests", body, "op1")
        self.assertEqual(201, status)
        exception_id = payload["resource_id"]
        status, payload = self._post("/exception-requests", body, "op1")
        self.assertEqual(200, status)
        self.assertTrue(payload["replayed"])
        self.assertEqual(exception_id, payload["resource_id"])

        status, payload = self._post("/exception-decisions",
                                     {"request_id": "api-dec", "exception_id": exception_id,
                                      "decision": "approved", "comment": "确认"}, "rv1")
        self.assertEqual(201, status)

        status, payload = route(self.service, "GET", "/exceptions/active", None,
                                {"X-Actor-Id": "a1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))
        self.assertIn("residual_risk", payload["items"][0])
        status, _ = route(self.service, "GET", "/exceptions/active", None,
                          {"X-Actor-Id": "op1"})
        self.assertEqual(403, status)

        status, payload = self._post("/exception-usages",
                                     {"request_id": "api-use", "exception_id": exception_id,
                                      "action": "invoke_model"}, "op1")
        self.assertEqual(201, status)
        status, payload = route(self.service, "GET",
                                f"/exception-usages?exception_id={exception_id}", None,
                                {"X-Actor-Id": "au1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))
        self.assertEqual(exception_id, payload["items"][0]["approval_basis"]["exception_id"])

        status, payload = self._post("/exception-revocations",
                                     {"request_id": "api-rev", "exception_id": exception_id,
                                      "reason": "演示结束"}, "a1")
        self.assertEqual(201, status)
        status, payload = self._post("/exception-reviews",
                                     {"request_id": "api-review", "exception_id": exception_id,
                                      "outcome": "no_issue", "notes": "无异常"}, "rv1")
        self.assertEqual(201, status)
        status, payload = route(self.service, "GET",
                                f"/exception-requests?exception_id={exception_id}", None,
                                {"X-Actor-Id": "a1"})
        self.assertEqual(200, status)
        self.assertEqual("closed", payload["status"])
        self.assertEqual("no_issue", payload["review"]["outcome"])

    def test_submit_without_expiry_is_rejected(self):
        body = {"request_id": "api-no-expiry", "organization_id": "o1", "rule_id": "model-access",
                "subject_id": "op1", "resource_id": "model-x", "risk_level": "low",
                "reason": "缺少期限"}
        status, payload = self._post("/exception-requests", body, "op1")
        self.assertEqual(400, status)


if __name__ == "__main__":
    unittest.main()
