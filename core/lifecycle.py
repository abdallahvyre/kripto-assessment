"""Finding lifecycle and status transitions.

``core.findings.Verification`` answers one question: how well was this proven at
the moment it was detected?  It is a statement about evidence, and it never
changes afterwards.  A finding also has a second, independent life: it is opened,
confirmed, retested after a fix, and eventually closed - and that is what this
module tracks.

Keeping the two apart matters.  A finding can be ``CONFIRMED`` evidence and still
be ``RESOLVED`` today, because the retest no longer reproduces it.  Collapsing
both into one field would destroy the history that makes a retest meaningful, so
a record carries its verification state *and* its workflow status *and* every
transition it went through.

Only the transitions listed below are allowed.  A caller that tries to move a
resolved finding straight back to open is refused rather than silently obeyed,
because that is how a report ends up claiming a fix worked when nothing was
re-tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from core import findings as finding_model


class Status(str, Enum):
    """Where a finding sits in the engagement workflow."""

    OPEN = "open"
    NEW = "new"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    RETESTED_PRESENT = "retested_present"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"

    @property
    def is_terminal(self) -> bool:
        return self in (Status.RESOLVED, Status.FALSE_POSITIVE)

    @property
    def is_live(self) -> bool:
        """Whether the weakness is still believed to be present."""
        return self in (Status.OPEN, Status.CONFIRMED,
                        Status.RETESTED_PRESENT, Status.ACCEPTED_RISK)



TRANSITIONS = {
    Status.NEW: frozenset({Status.CANDIDATE, Status.CONFIRMED, Status.INCONCLUSIVE,
                          Status.FALSE_POSITIVE}),
    Status.CANDIDATE: frozenset({Status.CONFIRMED, Status.INCONCLUSIVE,
                               Status.FALSE_POSITIVE, Status.ACCEPTED_RISK}),
    Status.OPEN: frozenset({Status.CONFIRMED, Status.INCONCLUSIVE,
                            Status.FALSE_POSITIVE, Status.ACCEPTED_RISK}),
    Status.CONFIRMED: frozenset({Status.RETESTED_PRESENT, Status.RESOLVED,
                                 Status.INCONCLUSIVE, Status.ACCEPTED_RISK}),
    Status.RETESTED_PRESENT: frozenset({Status.RESOLVED, Status.ACCEPTED_RISK,
                                      Status.INCONCLUSIVE}),
    Status.INCONCLUSIVE: frozenset({Status.CONFIRMED, Status.RESOLVED,
                                    Status.FALSE_POSITIVE, Status.ACCEPTED_RISK}),
    Status.ACCEPTED_RISK: frozenset({Status.RESOLVED, Status.RETESTED_PRESENT,
                                    Status.INCONCLUSIVE}),
    
    
    Status.RESOLVED: frozenset({Status.RETESTED_PRESENT, Status.INCONCLUSIVE}),
    Status.FALSE_POSITIVE: frozenset(),
}


class LifecycleError(ValueError):
    """Raised for a transition the state machine does not allow."""


def coerce_status(value, default: Status = Status.OPEN) -> Status:
    """Accept a Status, its name or its value; never raise."""
    if isinstance(value, Status):
        return value
    text = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    for status in Status:
        if text in (status.value, status.name.lower()):
            return status
    return default


def require_status(value) -> Status:
    if str(value).upper() == "RETESTED_FIXED":
        return Status.RESOLVED
    status = coerce_status(value, default=None)
    if status is None:
        raise LifecycleError(f"unknown lifecycle status: {value!r}")
    return status


def initial_status(verification) -> Status:
    """The status a finding opens with, derived from its verification state.

    A ``CONFIRMED`` finding starts confirmed; anything weaker opens and waits for
    a decision, because a potential finding has not earned a confirmed status.
    """
    state = finding_model.coerce(verification)
    if state is finding_model.Verification.CONFIRMED:
        return Status.CONFIRMED
    if state is finding_model.Verification.FALSE_POSITIVE:
        return Status.FALSE_POSITIVE
    if state is finding_model.Verification.INCONCLUSIVE:
        return Status.INCONCLUSIVE
    return Status.CANDIDATE


def _now(clock=None) -> str:
    moment = clock() if callable(clock) else datetime.now(timezone.utc)
    if isinstance(moment, str):
        return moment
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FindingRecord:
    """One finding's workflow record, with its full transition history."""

    fingerprint: str
    kind: str = ""
    title: str = ""
    status: Status = Status.OPEN
    verification: str = ""
    attempts: int = 0
    reproduced: int = 0
    history: list = field(default_factory=list)

    @property
    def reproducibility(self) -> dict:
        attempts = max(0, int(self.attempts))
        reproduced = max(0, min(int(self.reproduced), attempts or int(self.reproduced)))
        return {
            "attempts": attempts,
            "reproduced": reproduced,
            "rate": round(reproduced / attempts, 3) if attempts else None,
            "consistent": bool(attempts) and reproduced == attempts,
        }

    def allowed(self) -> tuple:
        return tuple(sorted(status.value for status in TRANSITIONS[self.status]))

    def transition(self, new_status, reason: str = "", clock=None) -> Status:
        """Move to a new status, or refuse and say why."""
        target = require_status(new_status)
        if target is self.status:
            return self.status
        if target not in TRANSITIONS[self.status]:
            raise LifecycleError(
                f"{self.fingerprint[:12]}: {self.status.value} -> {target.value} "
                f"is not an allowed transition (allowed: "
                f"{', '.join(self.allowed()) or 'none'})")
        self.history.append({
            "from": self.status.value,
            "to": target.value,
            "at": _now(clock),
            "reason": str(reason or "")[:300],
        })
        self.status = target
        return self.status

    def record_attempts(self, attempts: int, reproduced: int) -> None:
        self.attempts = max(0, int(attempts))
        self.reproduced = max(0, int(reproduced))

    def retest(self, reproduced: int, attempts: int,
               reason: str = "", clock=None, conclusive: bool = True) -> Status:
        """Close the loop after re-running the check against the target.

        Reproduction keeps the finding live; failure to reproduce resolves it.
        Both outcomes are recorded, so a report can show that a fix was
        *verified* rather than assumed.
        """
        attempts, reproduced = int(attempts), int(reproduced)
        if attempts < 0 or reproduced < 0 or reproduced > attempts:
            raise LifecycleError("invalid retest observation counts")
        if not attempts or not conclusive:
            target = Status.INCONCLUSIVE
            detail = reason or "no conclusive response; no fix established"
        elif reproduced == attempts:
            target = Status.RETESTED_PRESENT
            detail = reason or f"reproduced {reproduced}/{attempts} time(s)"
        elif reproduced:
            target = Status.INCONCLUSIVE
            detail = reason or "inconsistent retest responses"
        else:
            target = Status.RESOLVED
            detail = reason or f"not reproduced in {attempts} conclusive attempt(s)"
        
        if target not in TRANSITIONS[self.status] and target is not self.status:
            raise LifecycleError(f"cannot retest finding in {self.status.value}")
        self.record_attempts(attempts, reproduced)
        previous = self.status
        result = self.transition(target, detail, clock=clock)
        if previous is target:
            self.history.append({"from": previous.value, "to": target.value,
                                 "at": _now(clock), "reason": detail})
        self.history[-1]["reproducibility"] = self.reproducibility
        return result

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "title": self.title,
            "status": self.status.value,
            "live": self.status.is_live,
            "verification": self.verification,
            "reproducibility": self.reproducibility,
            "history": list(self.history),
        }


class LifecycleRegistry:
    """Every finding's workflow record for one engagement."""

    def __init__(self, clock=None):
        self.clock = clock
        self.records = {}

    def register(self, entry: dict) -> FindingRecord:
        """Add a finding, or return the record already held for it."""
        from core import fingerprint as fingerprint_model

        key = str(entry.get("fingerprint")
                  or fingerprint_model.fingerprint(entry))
        record = self.records.get(key)
        if record is not None:
            return record
        record = FindingRecord(
            fingerprint=key,
            kind=str(entry.get("kind") or ""),
            title=str(entry.get("title") or "")[:300],
            status=initial_status(entry.get("verification")),
            verification=str(entry.get("verification") or ""),
        )
        record.history.append({
            "from": "",
            "to": record.status.value,
            "at": _now(self.clock),
            "reason": f"opened from verification {record.verification or 'unknown'}",
        })
        self.records[key] = record
        return record

    def register_all(self, entries) -> list:
        return [self.register(entry) for entry in (entries or [])
                if isinstance(entry, dict)]

    def get(self, key: str):
        return self.records.get(str(key or ""))

    def transition(self, key: str, new_status, reason: str = "") -> Status:
        record = self.get(key)
        if record is None:
            raise LifecycleError(f"no finding record for {str(key)[:12]}")
        return record.transition(new_status, reason, clock=self.clock)

    def retest(self, key: str, reproduced: int, attempts: int,
               reason: str = "") -> Status:
        record = self.get(key)
        if record is None:
            raise LifecycleError(f"no finding record for {str(key)[:12]}")
        return record.retest(reproduced, attempts, reason, clock=self.clock)

    def annotate(self, entries) -> list:
        """Attach status, reproducibility and history to each finding dict."""
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            record = self.register(entry)
            entry["fingerprint"] = record.fingerprint
            entry["status"] = record.status.value
            entry["status_history"] = list(record.history)
            entry["reproducibility"] = record.reproducibility
        return entries

    def summary(self) -> dict:
        counts = {status.value: 0 for status in Status}
        for record in self.records.values():
            counts[record.status.value] += 1
        return {
            "findings": len(self.records),
            "by_status": counts,
            "live": sum(1 for record in self.records.values() if record.status.is_live),
            "retested": sum(1 for record in self.records.values()
                            if record.attempts > 0),
        }

    def as_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "records": [record.as_dict() for record in self.records.values()],
        }
