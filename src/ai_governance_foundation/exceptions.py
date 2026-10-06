"""治理规则例外审批服务的数据对象与等级规则。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 各风险等级对应的审批层级：等级越高，需要的独立审批越多。
LEVELS_BY_RISK: dict[str, tuple[int, ...]] = {
    "low": (1,),
    "medium": (1, 2),
    "high": (1, 2, 3),
}

RISK_ORDER = ("low", "medium", "high")

LEVEL_NAMES = {1: "business_owner", 2: "security", 3: "risk_committee"}

# 按风险等级强制的例外最长存活时间（秒），防止“临时例外永久化”。
MAX_TTL_SECONDS = {
    "low": 30 * 24 * 3600,
    "medium": 7 * 24 * 3600,
    "high": 24 * 3600,
}

TERMINAL_STATUSES = frozenset({"rejected", "revoked", "expired"})
CLOSED_STATUSES = frozenset({"revoked", "expired"})


@dataclass(frozen=True)
class ApproverScope:
    """审批人在某个层级负责的规则、资源与主体范围。"""

    approver_id: str
    level: int
    rule_ids: frozenset[str]
    resource_ids: frozenset[str]
    subject_ids: frozenset[str]


@dataclass(frozen=True)
class ExceptionRequest:
    """一次治理规则例外申请及其完整审批状态。"""

    exception_id: str
    rule_id: str
    subject_ids: tuple[str, ...]
    resource_ids: tuple[str, ...]
    risk_level: str
    risk_factors: tuple[str, ...]
    mitigations: tuple[str, ...]
    risk_score: int
    reason: str
    requested_by: str
    status: str
    effective_at: str
    expires_at: str
    created_at: str
    approved_at: str | None = None
    revoked_by: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None
    expired_at: str | None = None


@dataclass(frozen=True)
class ExceptionDecision:
    """例外在某一审批层级的决定。"""

    exception_id: str
    level: int
    approver_id: str
    decision: str
    comment: str
    audit_event_hash: str
    decided_at: str


@dataclass(frozen=True)
class ExceptionUse:
    """使用例外完成的一次动作，携带可回指的批准依据。"""

    use_id: str
    exception_id: str
    subject_id: str
    resource_id: str
    action: str
    reference: str
    payload: dict[str, Any]
    basis: dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class ExceptionReview:
    """例外关闭后的事后复盘记录。"""

    review_id: str
    exception_id: str
    reviewer_id: str
    summary: str
    findings: tuple[str, ...]
    residual_risk_level: str
    residual_risk_score: int
    created_at: str


@dataclass(frozen=True)
class ActiveExceptionReport:
    """管理视角下当前生效例外的剩余风险报告条目。"""

    exception: ExceptionRequest
    required_levels: tuple[int, ...]
    approvals: tuple[ExceptionDecision, ...]
    seconds_remaining: int
    expired: bool
    uses: int
    residual_risk_level: str
    residual_risk_score: int
    notes: tuple[str, ...] = field(default_factory=tuple)
