import json
from dataclasses import dataclass, field

import pytest

from gx.errors import Aborted, StepError
from gx.pipeline import AutoGate, Context, Decision, Gate, InteractiveGate, Step, run_steps

from .conftest import Deployment, FakeGxdch


@dataclass
class Recorder(Step):
    name: str
    needed: bool = True
    fail: bool = False
    title: str = "test step"
    ran: list[str] = field(default_factory=list)

    def plan(self, ctx: Context) -> Decision:
        return Decision(self.needed, f"{self.name} plan")

    def run(self, ctx: Context) -> str:
        if self.fail:
            raise StepError(f"{self.name} broke")
        self.ran.append(self.name)
        return f"{self.name} done"


def answers(*replies: str):
    queue = list(replies)
    return lambda prompt: queue.pop(0)


def test_auto_gate_follows_the_plan() -> None:
    gate = AutoGate()
    assert gate.confirm(Recorder("a"), Decision(True, "")) is True
    assert gate.confirm(Recorder("a"), Decision(False, "")) is False


@pytest.mark.parametrize("needed, reply, expected", [
    (True, "", True), (True, "n", False), (True, "yes", True),
    (False, "", False), (False, "y", True),
])
def test_interactive_gate(needed: bool, reply: str, expected: bool) -> None:
    assert InteractiveGate(answers(reply)).confirm(Recorder("a"), Decision(needed, "")) is expected


def test_interactive_gate_quit() -> None:
    with pytest.raises(Aborted):
        InteractiveGate(answers("q")).confirm(Recorder("a"), Decision(True, ""))


def test_gates_implement_the_protocol() -> None:
    assert Gate in AutoGate.__mro__ and Gate in InteractiveGate.__mro__


def run(fake_gxdch: FakeGxdch, steps, gate=None):
    return run_steps(Context(fake_gxdch.cfg, fake_gxdch), steps, gate or AutoGate(), out=lambda line: None)


def test_run_stops_at_the_first_failure(fake_gxdch: FakeGxdch) -> None:
    steps = [Recorder("a"), Recorder("b", needed=False), Recorder("c", fail=True), Recorder("d")]
    report = run(fake_gxdch, steps)
    assert [(o.step, o.status) for o in report.outcomes] == [("a", "done"), ("b", "skipped"), ("c", "failed")]
    assert not report.ok and not report.aborted and steps[3].ran == []
    assert json.loads(report.to_json())["outcomes"][2]["detail"] == "c broke"


def test_operator_abort(fake_gxdch: FakeGxdch) -> None:
    report = run(fake_gxdch, [Recorder("a"), Recorder("b")], InteractiveGate(answers("", "q")))
    assert report.aborted and not report.ok and [o.step for o in report.outcomes] == ["a"]


def test_renewed_means_publish_ran(fake_gxdch: FakeGxdch) -> None:
    assert run(fake_gxdch, [Recorder("publish")]).renewed
    assert not run(fake_gxdch, [Recorder("publish", needed=False)]).renewed


def test_signer_is_created_lazily(deployment: Deployment, fake_gxdch: FakeGxdch) -> None:
    deployment.key_file.unlink()
    ctx = Context(deployment.config(), fake_gxdch)   # no error: nothing touched the key yet
    with pytest.raises(Exception, match="signing key not found"):
        _ = ctx.signer
