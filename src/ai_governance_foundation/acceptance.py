"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .service import DomainService
from .storage import Database


def run() -> dict[str, object]:
    """执行一条完整登记链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = DomainService(database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
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
        service.register_actor(request_id="req-reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                               display_name="安全审批人", role="reviewer", organization_id="org-001")
        exceptions = service.exceptions
        exceptions.register_approver_scope(request_id="req-scope", actor_id="admin-001",
                                           approver_id="reviewer-001", organization_id="org-001",
                                           max_risk_level="medium", tier=1)
        submitted = exceptions.submit_exception(request_id="req-exception", actor_id="operator-001",
                                                organization_id="org-001", rule_id="model-access",
                                                subject_id="operator-001", resource_id="model-demo-7",
                                                risk_level="low", reason="重要演示临时放宽模型访问",
                                                expires_at="2026-09-26T08:00:00Z")
        exception_id = submitted.resource_id
        exceptions.decide_exception(request_id="req-decision", actor_id="reviewer-001",
                                    exception_id=exception_id, decision="approved",
                                    comment="范围与期限确认")
        exceptions.record_exception_usage(request_id="req-usage", actor_id="operator-001",
                                          exception_id=exception_id, action="invoke_model",
                                          detail={"purpose": "demo"})
        # 演示结束后时间越过到期点，例外自动失效且重启后不会复活。
        service.clock = FixedClock(datetime(2026, 9, 27, 8, 0, tzinfo=timezone.utc))
        active_after_expiry = exceptions.list_active_exceptions(actor_id="admin-001")
        exceptions.review_exception(request_id="req-review", actor_id="reviewer-001",
                                    exception_id=exception_id, outcome="no_issue",
                                    notes="演示结束后例外自动失效，无异常调用")
        detail = exceptions.get_exception(actor_id="admin-001", exception_id=exception_id)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed,
                  "exception_status": detail["status"],
                  "exception_usages": detail["usage_count"],
                  "active_exceptions": len(active_after_expiry)}
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
