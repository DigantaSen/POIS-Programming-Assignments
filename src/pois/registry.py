from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AssignmentRoute:
    task_id: str
    module_path: str
    class_name: str


ASSIGNMENT_ROUTES: dict[str, AssignmentRoute] = {
    "PA00": AssignmentRoute("PA00", "pois.assignments.pa00", "PA00"),
    "PA01": AssignmentRoute("PA01", "pois.assignments.pa01", "PA01"),
    "PA02": AssignmentRoute("PA02", "pois.assignments.pa02", "PA02"),
    "PA03": AssignmentRoute("PA03", "pois.assignments.pa03", "PA03"),
    "PA04": AssignmentRoute("PA04", "pois.assignments.pa04", "PA04"),
    "PA05": AssignmentRoute("PA05", "pois.assignments.pa05", "PA05"),
    "PA06": AssignmentRoute("PA06", "pois.assignments.pa06", "PA06"),
    "PA07": AssignmentRoute("PA07", "pois.assignments.pa07", "PA07"),
    "PA08": AssignmentRoute("PA08", "pois.assignments.pa08", "PA08"),
    "PA09": AssignmentRoute("PA09", "pois.assignments.pa09", "PA09"),
    "PA10": AssignmentRoute("PA10", "pois.assignments.pa10", "PA10"),
    "PA11": AssignmentRoute("PA11", "pois.assignments.pa11", "PA11"),
    "PA12": AssignmentRoute("PA12", "pois.assignments.pa12", "PA12"),
    "PA13": AssignmentRoute("PA13", "pois.assignments.pa13", "PA13"),
    "PA14": AssignmentRoute("PA14", "pois.assignments.pa14", "PA14"),
    "PA15": AssignmentRoute("PA15", "pois.assignments.pa15", "PA15"),
    "PA16": AssignmentRoute("PA16", "pois.assignments.pa16", "PA16"),
    "PA17": AssignmentRoute("PA17", "pois.assignments.pa17", "PA17"),
    "PA18": AssignmentRoute("PA18", "pois.assignments.pa18", "PA18"),
    "PA19": AssignmentRoute("PA19", "pois.assignments.pa19", "PA19"),
    "PA20": AssignmentRoute("PA20", "pois.assignments.pa20", "PA20"),
}
