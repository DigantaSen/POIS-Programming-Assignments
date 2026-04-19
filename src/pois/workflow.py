from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TASK_FILE = ROOT / "workflow" / "tasks.json"
STATE_FILE = ROOT / "workflow" / "state.json"


@dataclass
class WorkflowTask:
    task_id: str
    title: str
    owner: str
    deps: list[str]


class TeamWorkflow:
    def __init__(self, task_file: Path = TASK_FILE, state_file: Path = STATE_FILE) -> None:
        self.task_file = task_file
        self.state_file = state_file
        self.tasks = self._load_tasks()

    def init_state(self) -> dict[str, Any]:
        if self.state_file.exists():
            return self._load_state()
        initial = {
            "claimed": {},
            "completed": [],
            "history": [],
        }
        self._save_state(initial)
        return initial

    def status(self) -> dict[str, Any]:
        state = self.init_state()
        completed = set(state["completed"])
        claimed = state["claimed"]

        ready: list[str] = []
        blocked: list[str] = []
        in_progress: list[str] = []

        for t in self.tasks:
            if t.task_id in completed:
                continue
            if t.task_id in claimed:
                in_progress.append(t.task_id)
                continue
            if all(dep in completed for dep in t.deps):
                ready.append(t.task_id)
            else:
                blocked.append(t.task_id)

        return {
            "completed": sorted(completed),
            "in_progress": in_progress,
            "ready": ready,
            "blocked": blocked,
            "claimed": claimed,
        }

    def claim_next(self, member: str) -> WorkflowTask:
        state = self.init_state()
        completed = set(state["completed"])

        for t in self.tasks:
            if t.owner != member:
                continue
            if t.task_id in completed or t.task_id in state["claimed"]:
                continue
            if not all(dep in completed for dep in t.deps):
                continue

            state["claimed"][t.task_id] = member
            state["history"].append({"event": "claim", "member": member, "task_id": t.task_id})
            self._save_state(state)
            return t

        summary = self.member_status(member)
        if summary["in_progress"]:
            raise ValueError(
                f"Member '{member}' already has claimed task(s): {', '.join(summary['in_progress'])}."
            )
        if summary["ready"]:
            # Defensive fallback; this branch should normally not be reachable.
            raise ValueError(
                f"Member '{member}' has ready task(s) but none could be claimed: {', '.join(summary['ready'])}."
            )

        blocked_details = ", ".join(
            f"{item['task_id']} (needs: {', '.join(item['missing_deps'])})"
            for item in summary["blocked"]
        )
        raise ValueError(
            f"No claimable task for member '{member}'. Blocked tasks: {blocked_details if blocked_details else 'none'}"
        )

    def complete(self, member: str, task_id: str) -> None:
        state = self.init_state()
        owner = state["claimed"].get(task_id)
        if owner != member:
            raise ValueError(f"Task {task_id} is not claimed by {member}.")

        del state["claimed"][task_id]
        if task_id not in state["completed"]:
            state["completed"].append(task_id)
        state["history"].append({"event": "complete", "member": member, "task_id": task_id})
        self._save_state(state)

    def member_status(self, member: str) -> dict[str, Any]:
        state = self.init_state()
        completed = set(state["completed"])
        claimed = state["claimed"]

        in_progress: list[str] = []
        ready: list[str] = []
        blocked: list[dict[str, Any]] = []

        for t in self.tasks:
            if t.owner != member:
                continue
            if t.task_id in completed:
                continue
            if t.task_id in claimed:
                in_progress.append(t.task_id)
                continue

            missing = [dep for dep in t.deps if dep not in completed]
            if not missing:
                ready.append(t.task_id)
            else:
                blocked.append({"task_id": t.task_id, "missing_deps": missing})

        return {
            "member": member,
            "in_progress": in_progress,
            "ready": ready,
            "blocked": blocked,
        }

    def _task_by_id(self, task_id: str) -> WorkflowTask:
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        raise ValueError(f"Unknown task id: {task_id}")

    def _load_tasks(self) -> list[WorkflowTask]:
        data = json.loads(self.task_file.read_text())
        return [WorkflowTask(**item) for item in data["tasks"]]

    def _load_state(self) -> dict[str, Any]:
        return json.loads(self.state_file.read_text())

    def _save_state(self, state: dict[str, Any]) -> None:
        self.state_file.write_text(json.dumps(state, indent=2))
