from __future__ import annotations

from .base import AssignmentInfo, AssignmentModule


class PA04(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA04",
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
        raise NotImplementedError("PA04 is not implemented yet.")
