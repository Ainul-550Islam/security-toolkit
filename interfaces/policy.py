"""Policy decision contract with deny-by-default semantics.

Every authorization answer is an explicit :class:`PolicyDecision`. There is no
boolean shortcut, because ``if allowed:`` silently becomes "allow" whenever a
function returns ``None`` on an error path. Here the only way to produce an
allow is to construct one deliberately, and :func:`deny_by_default` is the
value every evaluator starts from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from core.errors import ValidationError

EFFECT_ALLOW: Final[str] = "allow"
EFFECT_DENY: Final[str] = "deny"
EFFECTS: Final[tuple[str, ...]] = (EFFECT_ALLOW, EFFECT_DENY)


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Who wants to do what to which resource."""

    subject: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> PolicyRequest:
        for name, value in (
            ("subject", self.subject),
            ("action", self.action),
            ("resource", self.resource),
        ):
            if not value or len(str(value)) > 512:
                raise ValidationError(f"{name} must be 1..512 characters")
        return self


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """An explicit authorization verdict."""

    effect: str = EFFECT_DENY
    reason: str = "no policy matched"
    rule_id: str = ""
    obligations: tuple[str, ...] = ()

    def validate(self) -> PolicyDecision:
        if self.effect not in EFFECTS:
            raise ValidationError("policy effect must be 'allow' or 'deny'")
        return self

    @property
    def allowed(self) -> bool:
        return self.effect == EFFECT_ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "obligations": list(self.obligations),
        }


def deny_by_default(reason: str = "no policy matched") -> PolicyDecision:
    """The starting verdict for any evaluation."""
    return PolicyDecision(effect=EFFECT_DENY, reason=reason)


def allow(reason: str, rule_id: str = "") -> PolicyDecision:
    """Construct an explicit allow. Always requires a stated reason."""
    if not reason:
        raise ValidationError("an allow decision must state a reason")
    return PolicyDecision(effect=EFFECT_ALLOW, reason=reason, rule_id=rule_id)


@runtime_checkable
class PolicyEngine(Protocol):
    """Evaluates policy requests."""

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Return a decision. On ANY internal error, return a deny."""
        ...


class DenyAllPolicyEngine:
    """Denies everything. The fail-closed default when no policy is loaded."""

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        return deny_by_default("no policy engine configured")


__all__ = [
    "PolicyRequest", "PolicyDecision", "PolicyEngine", "DenyAllPolicyEngine",
    "deny_by_default", "allow", "EFFECT_ALLOW", "EFFECT_DENY",
]
