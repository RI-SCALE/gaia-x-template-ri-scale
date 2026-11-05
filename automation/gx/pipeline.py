"""The step runner shared by the automatic (cron) and interactive (CLI) modes.

Every step implements the Step protocol:
    plan(ctx) -> Decision   is it needed? Side-effect free, never needs the private key.
    run(ctx)  -> str        do it; returns a one-line summary, raises StepError on failure.

The only difference between the two modes is the Gate: AutoGate follows each
plan, InteractiveGate shows it and asks. The steps themselves are identical.
"""

import json
from abc import abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal, Protocol, TypeAlias

from gx.config import Config
from gx.errors import Aborted, StepError
from gx.gxdch import Gxdch
from gx.signers import Signer, make_signer

StepStatus: TypeAlias = Literal["done", "skipped", "failed"]


@dataclass
class Decision:
    run: bool
    reason: str


class Context:
    """State shared by the steps of one run."""

    def __init__(self, cfg: Config, http: Gxdch, force: bool = False) -> None:
        self.cfg = cfg
        self.http = http
        self.force = force
        self.staged: dict[str, str] = {}   # credential name -> JWT produced in this run
        self.scratch: dict[str, str] = {}  # values a plan() hands to its run()
        self._signer: Signer | None = None

    @property
    def signer(self) -> Signer:
        # Created on first use, so runs with nothing to sign never touch the key.
        if self._signer is None:
            self._signer = make_signer(self.cfg.signer, self.cfg.alg)
        return self._signer


class Step(Protocol):
    """One pipeline step. The steps in steps.py subclass it explicitly."""

    name: str   # CLI name, used by --from / --until
    title: str  # one line shown before the plan

    @abstractmethod
    def plan(self, ctx: Context) -> Decision:
        """Is the step needed? Side-effect free, never needs the private key."""

    @abstractmethod
    def run(self, ctx: Context) -> str:
        """Do it; return a one-line summary, raise StepError on failure."""


class Gate(Protocol):
    """Decides whether a planned step runs: the only difference between the two modes."""

    interactive: bool

    @abstractmethod
    def confirm(self, step: Step, decision: Decision) -> bool:
        """True to run the step; raise Aborted to stop the whole run."""


class AutoGate(Gate):
    interactive = False

    def confirm(self, step: Step, decision: Decision) -> bool:
        return decision.run


class InteractiveGate(Gate):
    interactive = True

    def __init__(self, ask: Callable[[str], str] = input) -> None:
        self.ask = ask

    def confirm(self, step: Step, decision: Decision) -> bool:
        prompt = "   Run it? [Y/n/q] " if decision.run else "   Run anyway? [y/N/q] "
        answer = self.ask(prompt).strip().lower()
        if answer in ("q", "quit"):
            raise Aborted
        return answer in ("y", "yes") or (decision.run and answer == "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Outcome:
    step: str
    status: StepStatus
    detail: str


@dataclass
class RunReport:
    env: str
    started: str = field(default_factory=_now)
    finished: str = ""
    outcomes: list[Outcome] = field(default_factory=list)
    aborted: bool = False

    @property
    def ok(self) -> bool:
        return not self.aborted and all(o.status != "failed" for o in self.outcomes)

    @property
    def renewed(self) -> bool:
        return any(o.step == "publish" and o.status == "done" for o in self.outcomes)

    def to_json(self) -> str:
        return json.dumps({**asdict(self), "ok": self.ok, "renewed": self.renewed}, indent=2)


def run_steps(ctx: Context, steps: Sequence[Step], gate: Gate, out: Callable[[str], None] = print) -> RunReport:
    report = RunReport(env=ctx.cfg.env)
    for step in steps:
        out(f"\n[{step.name}] {step.title}")
        try:
            decision = step.plan(ctx)
            out(f"   {'needed' if decision.run else 'nothing to do'}: {decision.reason}")
            if not gate.confirm(step, decision):
                report.outcomes.append(Outcome(step.name, "skipped", decision.reason))
                continue
            detail = step.run(ctx)
            report.outcomes.append(Outcome(step.name, "done", detail))
            out(f"   done: {detail}")
        except StepError as e:
            report.outcomes.append(Outcome(step.name, "failed", str(e)))
            out(f"   FAILED: {e}")
            break
        except Aborted:
            report.aborted = True
            out("   aborted by the operator")
            break
    report.finished = _now()
    return report
