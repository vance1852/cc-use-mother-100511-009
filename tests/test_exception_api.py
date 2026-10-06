"""治理规则例外审批服务的 HTTP 边界测试。"""

import unittest
from datetime import datetime, timedelta, timezone

from ai_governance_foundation.api import route
from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.exception_service import ExceptionService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class ExceptionApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.t0 = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)
        self.clock = FixedClock(self.t0)
        self.service = DomainService(self.database, self.clock)
        self.exceptions = ExceptionService(self.database, self.clock)
        status, _ = route(self.service, "POST", "/organizations",
                          {"request_id": "org", "organization_id": "o1", "name": "机构"},
                          {"X-Actor-Id": "bootstrap"}, self.exceptions)
        self.assertEqual(201, status)
        for req, actor_id, role in (
            ("adm", "a1", "admin"), ("op", "op1", "operator"),
            ("l1", "l1", "reviewer"), ("l2", "l2", "reviewer"),
            ("l3", "l3", "reviewer"),
        ):
            status, _ = route(self.service, "POST", "/actors",
                              {"request_id": req, "new_actor_id": actor_id,
                               "display_name": actor_id, "role": role, "organization_id": "o1"},
                              {"X-Actor-Id": "bootstrap" if actor_id == "a1" else "a1"},
                              self.exceptions)
            self.assertEqual(201, status)
        for req, actor_id, level in (("s1", "l1", 1), ("s2", "l2", 2), ("s3", "l3", 3)):
            status, _ = route(self.service, "POST", "/approver-scopes",
                              {"request_id": req, "approver_id": actor_id, "level": level,
                               "rule_ids": ["rule.model_access"]},
                              {"X-Actor-Id": "a1"}, self.exceptions)
            self.assertEqual(201, status)

    def tearDown(self):
        self.database.close()

    def _call(self, method, path, actor, body=None):
        return route(self.service, method, path, body or {}, {"X-Actor-Id": actor}, self.exceptions)

    def _expires(self, hours):
        return (self.t0 + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")

    def _approved_exception(self, request_id="exc", score=80, hours=10):
        status, payload = self._call("POST", "/exceptions", "op1", {
            "request_id": request_id, "rule_id": "rule.model_access",
            "subject_ids": ["sub.team"], "resource_ids": ["res.model"],
            "reason": "重要演示临时放宽", "expires_at": self._expires(hours),
            "risk_score": score, "mitigations": ["限定范围"]})
        self.assertEqual(201, status)
        exception_id = payload["resource_id"]
        for req, actor, level in (("d1", "l1", 1), ("d2", "l2", 2), ("d3", "l3", 3)):
            status, payload = self._call("POST", "/exceptions/decisions", actor, {
                "request_id": req, "exception_id": exception_id, "level": level,
                "decision": "approved", "comment": "同意"})
            self.assertEqual(201, status)
        self.assertEqual("approved", payload["status"])
        return exception_id

    def test_full_approval_flow_and_active_listing(self):
        exception_id = self._approved_exception()
        status, payload = self._call("GET", "/exceptions/active", "a1")
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))
        item = payload["items"][0]
        self.assertEqual(exception_id, item["exception"]["exception_id"])
        self.assertEqual("high", item["residual_risk_level"])
        self.assertEqual(10 * 3600, item["seconds_remaining"])
        self.assertEqual(3, len(item["approvals"]))

    def test_replayed_apply_returns_same_idempotent_result(self):
        body = {"request_id": "exc-dup", "rule_id": "rule.model_access",
                "subject_ids": ["sub.team"], "resource_ids": ["res.model"],
                "reason": "重要演示临时放宽", "expires_at": self._expires(10), "risk_score": 80}
        status, first = self._call("POST", "/exceptions", "op1", body)
        status, second = self._call("POST", "/exceptions", "op1", body)
        self.assertEqual(first["resource_id"], second["resource_id"])
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])

    def test_out_of_scope_approval_is_403(self):
        status, payload = self._call("POST", "/exceptions", "op1", {
            "request_id": "exc-x", "rule_id": "rule.other_rule",
            "subject_ids": ["sub.team"], "resource_ids": ["res.model"],
            "reason": "x", "expires_at": self._expires(10), "risk_score": 80})
        exception_id = payload["resource_id"]
        status, payload = self._call("POST", "/exceptions/decisions", "l1", {
            "request_id": "dx", "exception_id": exception_id, "level": 1,
            "decision": "approved", "comment": "越权"})
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_use_returns_basis_and_trace_resolves(self):
        exception_id = self._approved_exception("exc-use")
        status, payload = self._call("POST", "/exceptions/use", "op1", {
            "request_id": "use-1", "exception_id": exception_id,
            "subject_id": "sub.team", "resource_id": "res.model",
            "action": "model.invoke", "reference": "演示工单", "payload": {"model": "demo"}})
        self.assertEqual(201, status)
        self.assertTrue(payload["basis_intact"])
        self.assertEqual(3, len(payload["basis"]["decisions"]))
        use_id = payload["resource_id"]
        # 重复提交得到同一使用结果。
        status, replay = self._call("POST", "/exceptions/use", "op1", {
            "request_id": "use-1", "exception_id": exception_id,
            "subject_id": "sub.team", "resource_id": "res.model",
            "action": "model.invoke", "reference": "演示工单", "payload": {"model": "demo"}})
        self.assertTrue(replay["replayed"])
        self.assertEqual(use_id, replay["resource_id"])
        status, trace = self._call("GET", f"/exceptions/{use_id}/trace", "a1")
        self.assertEqual(200, status)
        self.assertTrue(trace["basis_intact"])

    def test_expired_exception_drops_from_active_listing(self):
        exception_id = self._approved_exception("exc-exp", hours=1)
        self.clock._value = self.t0 + timedelta(hours=2)
        status, payload = self._call("GET", "/exceptions/active", "a1")
        self.assertEqual(200, status)
        self.assertEqual([], payload["items"])
        status, payload = self._call("GET", f"/exceptions/{exception_id}", "a1")
        self.assertEqual("expired", payload["exception"]["status"])

    def test_revoke_and_review_flow(self):
        exception_id = self._approved_exception("exc-rev")
        status, _ = self._call("POST", "/exceptions/revoke", "a1", {
            "request_id": "rev-1", "exception_id": exception_id, "reason": "演示取消"})
        self.assertEqual(201, status)
        # 生效中才可撤销的第二次尝试返回冲突。
        status, payload = self._call("POST", "/exceptions/revoke", "l2", {
            "request_id": "rev-2", "exception_id": exception_id, "reason": "再撤一次"})
        self.assertEqual(409, status)
        status, _ = self._call("POST", "/exceptions/reviews", "a1", {
            "request_id": "rv-1", "exception_id": exception_id,
            "summary": "演示前取消，未产生使用", "findings": ["无残留访问"],
            "residual_risk_score": 3})
        self.assertEqual(201, status)

    def test_missing_expiry_is_rejected(self):
        status, payload = self._call("POST", "/exceptions", "op1", {
            "request_id": "exc-noexp", "rule_id": "rule.model_access",
            "subject_ids": ["sub.team"], "resource_ids": ["res.model"],
            "reason": "无到期", "risk_score": 80})
        self.assertEqual(400, status)

    def test_route_works_without_exception_service(self):
        # 旧的调用方未注入例外服务时，原有健康检查仍然可用。
        status, payload = route(self.service, "GET", "/health", None)
        self.assertEqual(200, status)
        # 例外路由则不暴露。
        status, payload = route(self.service, "GET", "/exceptions/active", None)
        self.assertEqual(404, status)


if __name__ == "__main__":
    unittest.main()
