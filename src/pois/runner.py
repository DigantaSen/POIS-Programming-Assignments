from __future__ import annotations

from importlib import import_module

from .registry import ASSIGNMENT_ROUTES


def run_assignment(task_id: str) -> str:
    route = ASSIGNMENT_ROUTES.get(task_id)
    if route is None:
        raise ValueError(f"Unknown task_id: {task_id}")

    module = import_module(route.module_path)
    cls = getattr(module, route.class_name)
    assignment = cls()
    return assignment.run_demo()
