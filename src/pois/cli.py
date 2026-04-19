from __future__ import annotations

import argparse
import json

from .workflow import TeamWorkflow


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="POIS team workflow wrapper")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create workflow/state.json if missing")
    sub.add_parser("status", help="Print workflow status")

    next_cmd = sub.add_parser("next", help="Claim next task for a team member")
    next_cmd.add_argument(
        "--member",
        required=True,
        help="Diganta | Kushal | Nilkanta | Rohit | Srinjoy",
    )

    done_cmd = sub.add_parser("complete", help="Mark a claimed task complete")
    done_cmd.add_argument(
        "--member",
        required=True,
        help="Diganta | Kushal | Nilkanta | Rohit | Srinjoy",
    )
    done_cmd.add_argument("--task", required=True, help="PAxx")

    return parser


def main() -> None:
    args = _build_parser().parse_args()
    workflow = TeamWorkflow()

    def _print_member_help(member: str) -> None:
        summary = workflow.member_status(member)
        print(json.dumps(summary, indent=2))
        if summary["ready"]:
            print(
                "Tip: run `python -m pois.cli next --member "
                f"{member}` to claim {summary['ready'][0]}."
            )
            return
        if summary["in_progress"]:
            print(
                "Tip: run `python -m pois.cli complete --member "
                f"{member} --task <PAxx>` once your claimed task is done."
            )
            return
        print(
            "Tip: no task is claimable yet for this member. Complete missing dependencies first."
        )

    if args.command == "init":
        state = workflow.init_state()
        print(json.dumps(state, indent=2))
        return

    if args.command == "status":
        print(json.dumps(workflow.status(), indent=2))
        return

    if args.command == "next":
        try:
            task = workflow.claim_next(args.member)
            print(f"Claimed {task.task_id}: {task.title}")
        except ValueError as exc:
            print(f"Error: {exc}")
            _print_member_help(args.member)
        return

    if args.command == "complete":
        try:
            workflow.complete(args.member, args.task)
            print(f"Completed {args.task}")
        except ValueError as exc:
            print(f"Error: {exc}")
            _print_member_help(args.member)
        return

if __name__ == "__main__":
    main()
