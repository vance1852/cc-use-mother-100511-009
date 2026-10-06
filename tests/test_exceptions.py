"""治理规则例外审批服务的领域测试。"""

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, PermissionDenied, ValidationError
from ai_governance_foundation.exception_service import ExceptionService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class ExceptionServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.t0 = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)
        self.clock = FixedClock(self.t0)
        self.service = DomainService(self.database, self.clock)
        self.exceptions = ExceptionService(self.database, self.clock)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="治理示范机构")
        for req, actor_id, role, name in (
            ("admin", "a1", "admin", "管理员"),
            ("op", "op1", "operator", "业务申请人"),
            ("au", "au1", "auditor", "审计员"),
            ("l1", "l1", "reviewer", "业务负责人"),
            ("l2", "l2", "reviewer", "安全负责人"),
            ("l3", "l3", "reviewer", "风险委员会代表"),
            ("l1x", "l1x", "reviewer", "其他业务负责人"),
        ):
            self.service.register_actor(request_id=req, actor_id="bootstrap" if actor_id == "a1" else "a1",
                                        new_actor_id=actor_id, display_name=name, role=role,
                                        organization_id="o1")
        # L1 只能审批本规则、限定资源、限定主体；L2/L3 全范围。
        self.exceptions.register_approver_scope(
            request_id="s1", actor_id="a1", approver_id="l1", level=1,
            rule_ids=["rule.model_access"],
            resource_ids=["res.model", "res.other"], subject_ids=["sub.team"])
        self.exceptions.register_approver_scope(request_id="s2", actor_id="a1",
                                                approver_id="l2", level=2, rule_ids=["*"])
        self.exceptions.register_approver_scope(request_id="s3", actor_id="a1",
                                                approver_id="l3", level=3, rule_ids=["*"])
        # 另一个 L1 只负责别的规则。
        self.exceptions.register_approver_scope(
            request_id="s1x", actor_id="a1", approver_id="l1x", level=1,
            rule_ids=["rule.other"], resource_ids=["*"], subject_ids=["*"])

    def tearDown(self):
        self.database.close()

    def _iso(self, hours: float) -> str:
        return (self.t0 + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")

    def _apply(self, request_id="exc-1", score=80, hours=10, *, rule="rule.model_access",
               subjects=("sub.team",), resources=("res.model",), actor="op1"):
        return self.exceptions.apply_exception(
            request_id=request_id, actor_id=actor, rule_id=rule,
            subject_ids=list(subjects), resource_ids=list(resources),
            reason="重要演示临时放宽模型访问", expires_at=self._iso(hours), risk_score=score,
            risk_factors=["放宽访问规则"], mitigations=["限定演示团队"])

    def _approve_all(self, exception_id, prefix="d", *, l1="l1", l2="l2", l3="l3"):
        self.exceptions.decide_exception(request_id=f"{prefix}-1", actor_id=l1,
                                         exception_id=exception_id, level=1,
                                         decision="approved", comment="业务同意")
        self.exceptions.decide_exception(request_id=f"{prefix}-2", actor_id=l2,
                                         exception_id=exception_id, level=2,
                                         decision="approved", comment="安全同意")
        self.exceptions.decide_exception(request_id=f"{prefix}-3", actor_id=l3,
                                         exception_id=exception_id, level=3,
                                         decision="approved", comment="风险委员会同意")

    # ---- 申请与定级 -----------------------------------------------------

    def test_risk_score_derives_level_and_required_approvals(self):
        from ai_governance_foundation.exceptions import LEVELS_BY_RISK
        low = self._apply("low", score=10, hours=1)
        medium = self._apply("med", score=50, hours=24)
        high = self._apply("high", score=80, hours=10)
        self.assertEqual("low", self.exceptions.describe_exception(low.resource_id)["exception"]["risk_level"])
        self.assertEqual((1,), LEVELS_BY_RISK["low"])
        self.assertEqual((1, 2), LEVELS_BY_RISK[
            self.exceptions.describe_exception(medium.resource_id)["exception"]["risk_level"]])
        self.assertEqual((1, 2, 3), LEVELS_BY_RISK[
            self.exceptions.describe_exception(high.resource_id)["exception"]["risk_level"]])

    def test_expiry_is_mandatory_and_capped_by_risk_level(self):
        # 必须显式到期。
        with self.assertRaises(ValidationError):
            self.exceptions.apply_exception(
                request_id="no-expiry", actor_id="op1", rule_id="rule.model_access",
                subject_ids=["sub.team"], resource_ids=["res.model"], reason="x",
                expires_at=None, risk_score=80)
        # high 最长 24 小时。
        with self.assertRaises(ValidationError):
            self._apply("too-long", score=80, hours=25)
        # medium 最长 7 天。
        with self.assertRaises(ValidationError):
            self._apply("med-long", score=50, hours=24 * 8)
        # low 最长 30 天。
        with self.assertRaises(ValidationError):
            self._apply("low-long", score=10, hours=24 * 31)
        # 到期不得早于生效。
        with self.assertRaises(ValidationError):
            self._apply("past", score=10, hours=-1)

    def test_apply_is_idempotent_with_same_result(self):
        first = self._apply("dup")
        second = self._apply("dup")
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)

    def test_same_request_id_with_changed_payload_conflicts(self):
        self._apply("dup")
        with self.assertRaises(ConflictError):
            self._apply("dup", hours=9)

    # ---- 审批人范围与分级 -----------------------------------------------

    def test_approver_out_of_scope_is_denied(self):
        exc = self._apply()
        # l1x 只负责 rule.other，不能审批本规则。
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="x1", actor_id="l1x",
                                             exception_id=exc.resource_id, level=1,
                                             decision="approved", comment="越权")

    def test_l1_cannot_approve_resource_outside_scope(self):
        exc = self._apply("wide", resources=("res.model", "res.secret"))
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="x2", actor_id="l1",
                                             exception_id=exc.resource_id, level=1,
                                             decision="approved", comment="资源越界")

    def test_level_cannot_skip_order(self):
        exc = self._apply()
        with self.assertRaises(ValidationError):
            self.exceptions.decide_exception(request_id="x3", actor_id="l2",
                                             exception_id=exc.resource_id, level=2,
                                             decision="approved", comment="越级")

    def test_approver_cannot_decide_wrong_level(self):
        exc = self._apply()
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="x4", actor_id="l2",
                                             exception_id=exc.resource_id, level=1,
                                             decision="approved", comment="层级不符")

    def test_requester_cannot_approve_own_exception(self):
        # 给申请人登记合法的 L1 审批范围，仍因职责分离被拒绝。
        self.exceptions.register_approver_scope(
            request_id="s-op", actor_id="a1", approver_id="op1", level=1,
            rule_ids=["rule.model_access"], resource_ids=["res.model"], subject_ids=["sub.team"])
        exc = self._apply("own", actor="op1")
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="x5", actor_id="op1",
                                             exception_id=exc.resource_id, level=1,
                                             decision="approved", comment="自审")

    def test_scope_binds_approver_to_single_level(self):
        exc = self._apply()
        # l1 先以 L1 身份完成一级审批。
        self.exceptions.decide_exception(request_id="d1", actor_id="l1",
                                         exception_id=exc.resource_id, level=1,
                                         decision="approved", comment="一级")
        # 之后即使把其登记层级提升为 L2，也不能在同一单上跨到二级（同一人不得多级会签）。
        self.exceptions.register_approver_scope(request_id="s-up", actor_id="a1",
                                                approver_id="l1", level=2, rule_ids=["*"])
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="d2", actor_id="l1",
                                             exception_id=exc.resource_id, level=2,
                                             decision="approved", comment="同人跨级")
        # 层级变更后不能再回作 L1 决定。
        other = self._apply("other-exc")
        with self.assertRaises(PermissionDenied):
            self.exceptions.decide_exception(request_id="d3", actor_id="l1",
                                             exception_id=other.resource_id, level=1,
                                             decision="approved", comment="层级已变更")

    def test_decision_replay_returns_same_result(self):
        exc = self._apply()
        kwargs = dict(actor_id="l1", exception_id=exc.resource_id, level=1,
                      decision="approved", comment="业务同意")
        first = self.exceptions.decide_exception(request_id="rd", **kwargs)
        second = self.exceptions.decide_exception(request_id="rd", **kwargs)
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)

    def test_decision_replay_after_full_approval_still_returns_original_result(self):
        exc = self._apply()
        l1_kwargs = dict(actor_id="l1", exception_id=exc.resource_id, level=1,
                         decision="approved", comment="业务同意")
        self.exceptions.decide_exception(request_id="rd-l1", **l1_kwargs)
        self.exceptions.decide_exception(request_id="rd-l2", actor_id="l2",
                                         exception_id=exc.resource_id, level=2,
                                         decision="approved", comment="安全同意")
        self.exceptions.decide_exception(request_id="rd-l3", actor_id="l3",
                                         exception_id=exc.resource_id, level=3,
                                         decision="approved", comment="委员会同意")
        self.assertEqual("approved", self.exceptions.describe_exception(exc.resource_id)["exception"]["status"])
        # 生效期间产生一次使用。
        use = self.exceptions.use_exception(
            request_id="rd-use", actor_id="op1", exception_id=exc.resource_id,
            subject_id="sub.team", resource_id="res.model", action="model.invoke",
            reference="工单")
        # 例外已生效后重放任意一级的审批请求，仍返回同一回执，而不是状态冲突。
        replay = self.exceptions.decide_exception(request_id="rd-l1", **l1_kwargs)
        self.assertTrue(replay.replayed)
        self.assertEqual(exc.resource_id, replay.resource_id)
        # 撤销后重放使用请求同样返回原使用记录，而不是重新放行。
        self.exceptions.revoke_exception(request_id="rd-rev", actor_id="a1",
                                         exception_id=exc.resource_id, reason="叫停")
        use_replay = self.exceptions.use_exception(
            request_id="rd-use", actor_id="op1", exception_id=exc.resource_id,
            subject_id="sub.team", resource_id="res.model", action="model.invoke",
            reference="工单")
        self.assertTrue(use_replay.replayed)
        self.assertEqual(use.resource_id, use_replay.resource_id)

    def test_rejection_is_terminal(self):
        exc = self._apply()
        self.exceptions.decide_exception(request_id="r1", actor_id="l1",
                                         exception_id=exc.resource_id, level=1,
                                         decision="rejected", comment="驳回")
        with self.assertRaises(ConflictError):
            self.exceptions.decide_exception(request_id="r2", actor_id="l2",
                                             exception_id=exc.resource_id, level=2,
                                             decision="approved", comment="试图补救")
        self.assertEqual("rejected", self.exceptions.describe_exception(exc.resource_id)["exception"]["status"])

    def test_medium_needs_two_levels_and_low_one(self):
        med = self._apply("med", score=50, hours=24, resources=("res.other",))
        self.exceptions.decide_exception(request_id="m1", actor_id="l1",
                                         exception_id=med.resource_id, level=1,
                                         decision="approved", comment="业务同意")
        self.assertEqual("pending", self.exceptions.describe_exception(med.resource_id)["exception"]["status"])
        self.exceptions.decide_exception(request_id="m2", actor_id="l2",
                                         exception_id=med.resource_id, level=2,
                                         decision="approved", comment="安全同意")
        self.assertEqual("approved", self.exceptions.describe_exception(med.resource_id)["exception"]["status"])
        low = self._apply("low", score=10, hours=1, resources=("res.low",))
        with self.assertRaises(PermissionDenied):
            # l1 的资源范围不包含 res.low，不能越权审批。
            self.exceptions.decide_exception(request_id="l1d", actor_id="l1",
                                             exception_id=low.resource_id, level=1,
                                             decision="approved", comment="越界资源")
        # 扩大范围后，一级批准即生效。
        self.exceptions.register_approver_scope(
            request_id="s1-wide", actor_id="a1", approver_id="l1", level=1,
            rule_ids=["rule.model_access"], resource_ids=["*"], subject_ids=["sub.team"])
        self.exceptions.decide_exception(request_id="l1d2", actor_id="l1",
                                         exception_id=low.resource_id, level=1,
                                         decision="approved", comment="一级即可")
        self.assertEqual("approved", self.exceptions.describe_exception(low.resource_id)["exception"]["status"])

    # ---- 冲突互斥 -------------------------------------------------------

    def test_overlapping_conflicting_exceptions_cannot_coexist(self):
        first = self._apply("c1")
        self._approve_all(first.resource_id, "c1")
        second = self._apply("c2")
        self.exceptions.decide_exception(request_id="c2-1", actor_id="l1",
                                         exception_id=second.resource_id, level=1,
                                         decision="approved", comment="业务同意")
        self.exceptions.decide_exception(request_id="c2-2", actor_id="l2",
                                         exception_id=second.resource_id, level=2,
                                         decision="approved", comment="安全同意")
        with self.assertRaises(ConflictError):
            self.exceptions.decide_exception(request_id="c2-3", actor_id="l3",
                                             exception_id=second.resource_id, level=3,
                                             decision="approved", comment="与首单冲突")

    def test_different_resource_is_not_conflicting(self):
        first = self._apply("n1", resources=("res.model",))
        self._approve_all(first.resource_id, "n1")
        second = self._apply("n2", resources=("res.other",))
        self._approve_all(second.resource_id, "n2")
        active = {item["exception"]["exception_id"] for item in self.exceptions.list_active_exceptions()}
        self.assertEqual({first.resource_id, second.resource_id}, active)

    def test_non_overlapping_windows_are_not_conflicting(self):
        first = self._apply("w1", hours=2)
        self._approve_all(first.resource_id, "w1")
        self.clock._value = self.t0 + timedelta(hours=3)
        second = self._apply("w2", hours=5)
        self._approve_all(second.resource_id, "w2")
        # 首单已过期，只剩次单。
        active = [item["exception"]["exception_id"] for item in self.exceptions.list_active_exceptions()]
        self.assertEqual([second.resource_id], active)
        self.assertEqual("expired", self.exceptions.describe_exception(first.resource_id)["exception"]["status"])

    # ---- 使用、依据与范围限定 -------------------------------------------

    def test_use_enforces_subject_and_resource_bounds(self):
        exc = self._apply()
        self._approve_all(exc.resource_id)
        with self.assertRaises(PermissionDenied):
            self.exceptions.use_exception(request_id="u-bad-subj", actor_id="op1",
                                          exception_id=exc.resource_id, subject_id="sub.outsider",
                                          resource_id="res.model", action="model.invoke",
                                          reference="工单-越界主体")
        with self.assertRaises(PermissionDenied):
            self.exceptions.use_exception(request_id="u-bad-res", actor_id="op1",
                                          exception_id=exc.resource_id, subject_id="sub.team",
                                          resource_id="res.other", action="model.invoke",
                                          reference="工单-越界资源")

    def test_use_records_traceable_basis_and_replays_identically(self):
        exc = self._apply()
        self._approve_all(exc.resource_id)
        kwargs = dict(actor_id="op1", exception_id=exc.resource_id, subject_id="sub.team",
                      resource_id="res.model", action="model.invoke",
                      reference="演示工单 demo-1", payload={"model": "demo"})
        first = self.exceptions.use_exception(request_id="u1", **kwargs)
        second = self.exceptions.use_exception(request_id="u1", **kwargs)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)
        trace = self.exceptions.trace_use(first.resource_id)
        self.assertTrue(trace["basis_intact"])
        self.assertEqual([1, 2, 3], [d["level"] for d in trace["basis"]["decisions"]])
        self.assertEqual(["l1", "l2", "l3"], [d["approver_id"] for d in trace["basis"]["decisions"]])
        # 重放没有产生第二条使用记录，审计链中 exception.used 仍只有一条。
        used_events = [e for e in self.service.audit_events() if e["action"] == "exception.used"]
        self.assertEqual(1, len(used_events))
        self.assertEqual(trace["basis"]["use_audit_event_hash"], used_events[0]["event_hash"])
        # 依据中的每个审批事件都能在审计链中找到并指向本例外。
        self.assertTrue(all(c["found"] and c["matches_exception"] for c in trace["basis_checks"]))

    def test_use_before_approval_is_rejected(self):
        exc = self._apply()
        with self.assertRaises(ConflictError):
            self.exceptions.use_exception(request_id="u2", actor_id="op1",
                                          exception_id=exc.resource_id, subject_id="sub.team",
                                          resource_id="res.model", action="model.invoke",
                                          reference="未批先用")

    # ---- 到期、撤销、重启 -----------------------------------------------

    def test_expired_exception_cannot_be_used(self):
        exc = self._apply(hours=1)
        self._approve_all(exc.resource_id)
        self.clock._value = self.t0 + timedelta(hours=2)
        with self.assertRaises(ConflictError):
            self.exceptions.use_exception(request_id="u3", actor_id="op1",
                                          exception_id=exc.resource_id, subject_id="sub.team",
                                          resource_id="res.model", action="model.invoke",
                                          reference="过期使用")
        self.assertEqual("expired", self.exceptions.describe_exception(exc.resource_id)["exception"]["status"])
        self.assertEqual([], self.exceptions.list_active_exceptions())

    def test_expired_exception_does_not_reactivate_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite3"
            database = Database(path)
            svc = DomainService(database, self.clock)
            exc_svc = ExceptionService(database, self.clock)
            svc.register_organization(request_id="org", actor_id="bootstrap",
                                      organization_id="o1", name="x")
            svc.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                               display_name="管理员", role="admin", organization_id="o1")
            svc.register_actor(request_id="op", actor_id="a1", new_actor_id="op1",
                               display_name="申请人", role="operator", organization_id="o1")
            for req, actor_id in (("l1", "l1"), ("l2", "l2"), ("l3", "l3")):
                svc.register_actor(request_id=req, actor_id="a1", new_actor_id=actor_id,
                                   display_name=actor_id, role="reviewer", organization_id="o1")
            for req, actor_id, level in (("s1", "l1", 1), ("s2", "l2", 2), ("s3", "l3", 3)):
                exc_svc.register_approver_scope(request_id=req, actor_id="a1",
                                                approver_id=actor_id, level=level, rule_ids=["*"])
            applied = exc_svc.apply_exception(
                request_id="exc-restart", actor_id="op1", rule_id="rule.model_access",
                subject_ids=["sub.team"], resource_ids=["res.model"], reason="演示",
                expires_at=self._iso(1), risk_score=80)
            exc_svc.decide_exception(request_id="d1", actor_id="l1", exception_id=applied.resource_id,
                                     level=1, decision="approved", comment="x")
            exc_svc.decide_exception(request_id="d2", actor_id="l2", exception_id=applied.resource_id,
                                     level=2, decision="approved", comment="x")
            exc_svc.decide_exception(request_id="d3", actor_id="l3", exception_id=applied.resource_id,
                                     level=3, decision="approved", comment="x")
            database.close()

            # 重启：时钟已经越过到期点。
            late_clock = FixedClock(self.t0 + timedelta(hours=2))
            database = Database(path)
            exc_svc = ExceptionService(database, late_clock)
            self.assertEqual([], exc_svc.list_active_exceptions())
            detail = exc_svc.describe_exception(applied.resource_id)
            self.assertEqual("expired", detail["exception"]["status"])
            self.assertIsNotNone(detail["exception"]["expired_at"])
            with self.assertRaises(ConflictError):
                exc_svc.use_exception(request_id="u4", actor_id="op1",
                                      exception_id=applied.resource_id, subject_id="sub.team",
                                      resource_id="res.model", action="model.invoke",
                                      reference="重启后尝试")
            # 重复 sweep 不会重复产生状态变化。
            self.assertEqual(0, exc_svc.sweep_expired())
            database.close()

    def test_early_revocation_blocks_use_and_is_audited(self):
        exc = self._apply()
        self._approve_all(exc.resource_id)
        # 申请人自己不能撤销。
        with self.assertRaises(PermissionDenied):
            self.exceptions.revoke_exception(request_id="v0", actor_id="op1",
                                             exception_id=exc.resource_id, reason="自撤")
        # 覆盖范围的审批人可以提前撤销。
        self.exceptions.revoke_exception(request_id="v1", actor_id="l2",
                                         exception_id=exc.resource_id, reason="演示提前结束")
        with self.assertRaises(ConflictError):
            self.exceptions.use_exception(request_id="u5", actor_id="op1",
                                          exception_id=exc.resource_id, subject_id="sub.team",
                                          resource_id="res.model", action="model.invoke",
                                          reference="撤销后使用")
        self.assertEqual("revoked", self.exceptions.describe_exception(exc.resource_id)["exception"]["status"])

    def test_admin_can_revoke_any_active_exception(self):
        exc = self._apply()
        self._approve_all(exc.resource_id)
        self.exceptions.revoke_exception(request_id="v2", actor_id="a1",
                                         exception_id=exc.resource_id, reason="管理员叫停")
        self.assertEqual("revoked", self.exceptions.describe_exception(exc.resource_id)["exception"]["status"])

    # ---- 复盘与管理视图 -------------------------------------------------

    def test_review_only_after_close_and_records_residual_risk(self):
        exc = self._apply(hours=1)
        self._approve_all(exc.resource_id)
        with self.assertRaises(ConflictError):
            self.exceptions.record_review(request_id="rv0", actor_id="au1",
                                          exception_id=exc.resource_id, summary="生效中不能复盘",
                                          findings=[], residual_risk_score=5)
        self.clock._value = self.t0 + timedelta(hours=2)
        self.exceptions.sweep_expired()
        review = self.exceptions.record_review(
            request_id="rv1", actor_id="au1", exception_id=exc.resource_id,
            summary="演示结束，使用均在授权范围内",
            findings=["未发现越权", "缓解措施有效"], residual_risk_score=8)
        self.assertFalse(review.replayed)
        detail = self.exceptions.describe_exception(exc.resource_id)
        self.assertEqual(1, len(detail["reviews"]))
        self.assertEqual("low", detail["reviews"][0]["residual_risk_level"])

    def test_active_listing_reports_remaining_time_and_residual_risk(self):
        exc = self._apply(hours=5)
        self._approve_all(exc.resource_id)
        self.exceptions.use_exception(request_id="u6", actor_id="op1",
                                      exception_id=exc.resource_id, subject_id="sub.team",
                                      resource_id="res.model", action="model.invoke",
                                      reference="工单-1")
        self.clock._value = self.t0 + timedelta(hours=1)
        items = self.exceptions.list_active_exceptions()
        self.assertEqual(1, len(items))
        item = items[0]
        self.assertEqual(exc.resource_id, item["exception"]["exception_id"])
        self.assertEqual(4 * 3600, item["seconds_remaining"])
        self.assertEqual("high", item["residual_risk_level"])
        self.assertEqual(80, item["residual_risk_score"])
        self.assertEqual(1, item["uses"])
        self.assertTrue(any("使用" in note for note in item["notes"]))


if __name__ == "__main__":
    unittest.main()
