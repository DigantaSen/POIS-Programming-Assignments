from __future__ import annotations

from .base import AssignmentInfo, AssignmentModule


class PA14(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA14",
            title="TODO: implement assignment details",
            part="TODO",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement core algorithms",
            "Provide demo hooks",
            "Keep interfaces stable for dependent PAs",
        ]

    def run_demo(self) -> str:
        raise NotImplementedError("PA14 is not implemented yet.")
