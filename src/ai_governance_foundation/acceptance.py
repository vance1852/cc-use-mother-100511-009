"""运行基础服务与例外审批服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import FixedClock
from .exception_service import ExceptionService
from .service import DomainService
from .storage import Database


def run() -> dict[str, object]:
    """执行一条完整登记链与例外审批链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "acceptance.sqlite3"
        start = datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)
        database = Database(db_path)
        clock = FixedClock(start)
        service = DomainService(database, clock)
        exceptions = ExceptionService(database, clock)

        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})

        # 例外审批链：三级审批人，L1 的范围被限定在具体规则/资源/主体上。
        for req, actor_id, name in (
            ("req-auditor", "auditor-001", "安全审计员"),
            ("req-l1", "l1-001", "业务负责人"),
            ("req-l2", "l2-001", "安全负责人"),
            ("req-l3", "l3-001", "风险委员会代表"),
        ):
            service.register_actor(request_id=req, actor_id="admin-001", new_actor_id=actor_id,
                                   display_name=name, role="reviewer", organization_id="org-001")
        exceptions.register_approver_scope(request_id="scope-l1", actor_id="admin-001",
                                           approver_id="l1-001", level=1,
                                           rule_ids=["rule.model_access"],
                                           resource_ids=["res.demo_model"],
                                           subject_ids=["sub.demo_team"])
        exceptions.register_approver_scope(request_id="scope-l2", actor_id="admin-001",
                                           approver_id="l2-001", level=2, rule_ids=["*"])
        exceptions.register_approver_scope(request_id="scope-l3", actor_id="admin-001",
                                           approver_id="l3-001", level=3, rule_ids=["*"])

        expires = (start + timedelta(hours=10)).isoformat().replace("+00:00", "Z")
        applied = exceptions.apply_exception(
            request_id="exc-apply", actor_id="operator-001", rule_id="rule.model_access",
            subject_ids=["sub.demo_team"], resource_ids=["res.demo_model"],
            reason="重要演示需要临时放宽模型访问", expires_at=expires, risk_score=80,
            risk_factors=["放宽访问规则", "演示环境含真实数据"],
            mitigations=["限定演示团队", "演示后立即撤销并复盘"])
        exception_id = applied.resource_id
        applied_replay = exceptions.apply_exception(
            request_id="exc-apply", actor_id="operator-001", rule_id="rule.model_access",
            subject_ids=["sub.demo_team"], resource_ids=["res.demo_model"],
            reason="重要演示需要临时放宽模型访问", expires_at=expires, risk_score=80,
            risk_factors=["放宽访问规则", "演示环境含真实数据"],
            mitigations=["限定演示团队", "演示后立即撤销并复盘"])

        exceptions.decide_exception(request_id="dec-l1", actor_id="l1-001",
                                    exception_id=exception_id, level=1, decision="approved",
                                    comment="业务确认演示范围")
        exceptions.decide_exception(request_id="dec-l2", actor_id="l2-001",
                                    exception_id=exception_id, level=2, decision="approved",
                                    comment="安全确认缓解措施")
        exceptions.decide_exception(request_id="dec-l3", actor_id="l3-001",
                                    exception_id=exception_id, level=3, decision="approved",
                                    comment="风险委员会批准，限 10 小时")

        used = exceptions.use_exception(
            request_id="use-1", actor_id="operator-001", exception_id=exception_id,
            subject_id="sub.demo_team", resource_id="res.demo_model",
            action="model.invoke", reference="演示工单 demo-2026-0925",
            payload={"model": "demo"})
        used_replay = exceptions.use_exception(
            request_id="use-1", actor_id="operator-001", exception_id=exception_id,
            subject_id="sub.demo_team", resource_id="res.demo_model",
            action="model.invoke", reference="演示工单 demo-2026-0925",
            payload={"model": "demo"})
        trace = exceptions.trace_use(used.resource_id)

        active_before = exceptions.list_active_exceptions()
        database.close()

        # 模拟服务重启：时间推进到到期之后，重新打开同一个数据库文件。
        restart_clock = FixedClock(start + timedelta(hours=11))
        database = Database(db_path)
        service = DomainService(database, restart_clock)
        exceptions = ExceptionService(database, restart_clock)
        active_after = exceptions.list_active_exceptions()
        after_restart = exceptions.describe_exception(exception_id)
        restart_use_blocked = False
        try:
            exceptions.use_exception(
                request_id="use-after-expiry", actor_id="operator-001", exception_id=exception_id,
                subject_id="sub.demo_team", resource_id="res.demo_model",
                action="model.invoke", reference="逾期尝试")
        except Exception:
            restart_use_blocked = True

        reviewed = exceptions.record_review(
            request_id="review-1", actor_id="auditor-001", exception_id=exception_id,
            summary="演示按限定范围执行，到期自动失效，未发现越权使用",
            findings=["使用记录与批准依据一致", "缓解措施落实"], residual_risk_score=10)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {
            "status": "ok", "records": len(records), "audit_events": event_count,
            "audit_valid": valid, "first_replayed": first.replayed,
            "second_replayed": replay.replayed,
            "apply_replayed": applied_replay.replayed,
            "same_exception_on_replay": applied_replay.resource_id == exception_id,
            "risk_level": "high", "required_levels": 3,
            "use_replayed": used_replay.replayed,
            "basis_intact": trace["basis_intact"],
            "basis_levels": len(trace["basis"]["decisions"]),
            "active_before_restart": len(active_before),
            "active_after_restart": len(active_after),
            "status_after_restart": after_restart["exception"]["status"],
            "expired_at_persisted": after_restart["exception"]["expired_at"] is not None,
            "restart_use_blocked": restart_use_blocked,
            "review_id": reviewed.resource_id,
        }
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
