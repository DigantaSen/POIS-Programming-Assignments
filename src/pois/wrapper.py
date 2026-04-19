from __future__ import annotations

from .runner import run_assignment
from .workflow import TeamWorkflow


def teammate_wrapper(member: str, action: str, task_id: str | None = None) -> str:
    """Single wrapper entrypoint for sequential team workflow.

    Supported actions:
    - init: initialize workflow state
    - next: claim next dependency-ready task for member
    - complete: mark claimed task complete (task_id required)
    - demo: run assignment demo by task_id
    """

    workflow = TeamWorkflow()

    if action == "init":
        workflow.init_state()
        return "Workflow initialized"

    if action == "next":
        task = workflow.claim_next(member)
        return f"Claimed {task.task_id}: {task.title}"

    if action == "complete":
        if task_id is None:
            raise ValueError("task_id is required for complete action")
        workflow.complete(member, task_id)
        return f"Completed {task_id}"

    if action == "demo":
        if task_id is None:
            raise ValueError("task_id is required for demo action")
        return run_assignment(task_id)

    raise ValueError(f"Unknown action: {action}")
