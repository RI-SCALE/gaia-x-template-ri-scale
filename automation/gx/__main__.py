"""gx command line. Run `python -m gx --help` (or `docker compose run --rm gx --help`).

Exit codes: see ExitCode.
"""

import argparse
import sys
from enum import IntEnum
from pathlib import Path
from typing import Final

from gx import __version__
from gx.config import Config, load_config
from gx.constants import ENVS
from gx.errors import ConfigError, StepError
from gx.gxdch import Gxdch
from gx.pipeline import AutoGate, Context, Gate, InteractiveGate, Step, run_steps
from gx.steps import STATUS_STEPS, STEPS, check_signer, import_wizard_zip


class ExitCode(IntEnum):
    OK = 0        # including "nothing to do"
    FAILED = 1    # a step failed, or `status` found something to do
    CONFIG = 2    # configuration error
    ABORTED = 3   # aborted by the operator


STEP_NAMES: Final[list[str]] = [s.name for s in STEPS]


def _select(start: str | None, stop: str | None) -> tuple[Step, ...]:
    first = STEP_NAMES.index(start) if start else 0
    last = STEP_NAMES.index(stop) if stop else len(STEPS) - 1
    return STEPS[first:last + 1]


def cmd_run(cfg: Config, args: argparse.Namespace) -> ExitCode:
    gate: Gate = InteractiveGate() if args.interactive else AutoGate()
    ctx = Context(cfg, Gxdch(cfg), force=args.force)
    mode = "interactive" if gate.interactive else "automatic"
    print(f"gx {__version__}: env={cfg.env} domain={cfg.domain} ({mode})")
    report = run_steps(ctx, _select(args.start, args.stop), gate)
    if args.report:
        Path(args.report).write_text(report.to_json(), encoding="utf-8")
    verdict = "renewed" if report.renewed else "OK" if report.ok else "aborted" if report.aborted else "FAILED"
    print(f"\nResult: {verdict}")
    return ExitCode.OK if report.ok else ExitCode.ABORTED if report.aborted else ExitCode.FAILED


def cmd_status(cfg: Config, args: argparse.Namespace) -> ExitCode:
    """Plans only: what a run would do now. Never signs, never writes, never needs the key."""
    ctx = Context(cfg, Gxdch(cfg))
    needed = False
    print(f"env={cfg.env} domain={cfg.domain} identity={cfg.source}")
    try:
        print(f"  {'key':<6} ok       {check_signer(ctx)}")
    except StepError as e:
        print(f"  {'key':<6} PROBLEM  {e}")
        needed = True
    for step in STATUS_STEPS:
        try:
            decision = step.plan(ctx)
        except StepError as e:
            print(f"  {step.name:<6} PROBLEM  {e}")
            needed = True
            continue
        needed |= decision.run
        print(f"  {step.name:<6} {'ACTION ' if decision.run else 'ok     '}  {decision.reason}")
    print("\nRun `gx run` to bring everything up to date." if needed else "\nEverything is up to date.")
    return ExitCode.FAILED if needed else ExitCode.OK


def cmd_import_zip(cfg: Config, args: argparse.Namespace) -> ExitCode:
    try:
        lines = import_wizard_zip(cfg, Path(args.zip))
    except StepError as e:
        print(f"FAILED: {e}")
        return ExitCode.FAILED
    print("\n".join(lines))
    return ExitCode.OK


def main(argv: list[str] | None = None) -> ExitCode:
    parser = argparse.ArgumentParser(prog="gx", description="Gaia-X identity automation for gaia-x-hosting")
    parser.add_argument("--env", choices=ENVS, help="environment (default: $GX_ENV or dev)")
    parser.add_argument("--config-dir", help="directory with base.toml / <env>.toml / site.toml")
    parser.add_argument("--version", action="version", version=f"gx {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="bring the published identity up to date (cron-safe: does nothing if current)")
    run.add_argument("-i", "--interactive", action="store_true", help="show each step's plan and ask before running it")
    run.add_argument("--force", action="store_true", help="re-issue the credentials even if they are still valid")
    run.add_argument("--from", dest="start", choices=STEP_NAMES, help="start at this step")
    run.add_argument("--until", dest="stop", choices=STEP_NAMES,
                     help="stop after this step (e.g. --until issue: sign into staging, submit nothing)")
    run.add_argument("--report", help="also write the run report as JSON to this file")
    run.set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="show what is current and what a run would do (read-only)")
    status.set_defaults(func=cmd_status)

    imp = sub.add_parser("import-zip", help="place credentials from a Wizard credentials.zip by their id URL")
    imp.add_argument("zip", help="path to credentials.zip")
    imp.set_defaults(func=cmd_import_zip)

    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.env, Path(args.config_dir) if args.config_dir else None)
    except (ConfigError, OSError) as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return ExitCode.CONFIG
    return args.func(cfg, args)


if __name__ == "__main__":
    sys.exit(main())
