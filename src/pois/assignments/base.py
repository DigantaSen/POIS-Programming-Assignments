from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AssignmentInfo:
    task_id: str
    title: str
    part: str


class AssignmentModule(ABC):
    @abstractmethod
    def info(self) -> AssignmentInfo:
        raise NotImplementedError

    @abstractmethod
    def deliverables(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def run_demo(self) -> str:
        raise NotImplementedError
