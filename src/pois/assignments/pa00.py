from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .base import AssignmentInfo, AssignmentModule


class Foundation(str, Enum):
    AES = "AES"
    DLP = "DLP"


@dataclass(frozen=True)
class PrimitivePlaceholder:
    name: str
    description: str
    status: str = "UNIMPLEMENTED"


class PA00(AssignmentModule):
    def __init__(self) -> None:
        self._foundation: Foundation = Foundation.AES

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA00",
            title="PA00 scaffold: UI structure and primitive placeholders",
            part="Part A",
        )

    def deliverables(self) -> list[str]:
        return [
            "Foundation toggle scaffold (AES/DLP)",
            "Two-column Build/Reduce panel scaffold",
            "Proof summary panel scaffold",
            "Placeholder primitives for unimplemented crypto steps",
        ]

    def set_foundation(self, value: Foundation) -> None:
        self._foundation = value

    def current_foundation(self) -> Foundation:
        return self._foundation

    def columns(self) -> tuple[str, str]:
        return ("Build", "Reduce")

    def proof_summary(self) -> dict[str, str]:
        return {
            "status": "STUB",
            "headline": "Proof summary panel placeholder",
            "details": "No theorem or reduction proof implemented yet.",
        }

    def primitive_placeholders(self) -> list[PrimitivePlaceholder]:
        return [
            PrimitivePlaceholder(
                name="build_instance",
                description="Construct challenge instance from selected foundation.",
            ),
            PrimitivePlaceholder(
                name="reduce_instance",
                description="Apply reduction pipeline from source problem.",
            ),
            PrimitivePlaceholder(
                name="verify_witness",
                description="Check witness correctness for generated instance.",
            ),
            PrimitivePlaceholder(
                name="derive_proof_summary",
                description="Collect assumptions and reduction guarantees.",
            ),
        ]

    def run_primitive(self, primitive_name: str) -> str:
        raise NotImplementedError(f"Primitive '{primitive_name}' is not implemented in PA00.")

    def run_demo(self) -> str:
        left, right = self.columns()
        placeholders = ", ".join(p.name for p in self.primitive_placeholders())
        return (
            "PA00 scaffold active\n"
            f"- foundation toggle: {self.current_foundation().value}\n"
            f"- columns: {left} | {right}\n"
            "- proof summary panel: stub\n"
            f"- primitive placeholders: {placeholders}"
        )
