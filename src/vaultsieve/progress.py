from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


@dataclass(frozen=True)
class StepRecord:
    phase: str
    detail: str
    elapsed: float


class AuditProgress:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.records: list[StepRecord] = []
        self._current_phase: str | None = None
        self._current_detail = ""
        self._phase_started = perf_counter()
        self._progress: Progress | None = None
        self._task_id: int | None = None

    def __enter__(self) -> AuditProgress:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
        )
        self._progress.__enter__()
        self._task_id = self._progress.add_task("Starting audit", total=None)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        self.finish_current()
        if self._progress is not None:
            self._progress.__exit__(exc_type, exc, traceback)

    def update(self, phase: str, completed: int | None = None) -> None:
        detail = f"{completed} checked" if completed is not None else ""
        if phase != self._current_phase:
            self.finish_current()
            self._current_phase = phase
            self._phase_started = perf_counter()
        self._current_detail = detail
        if self._progress is not None and self._task_id is not None:
            suffix = f" ({detail})" if detail else ""
            self._progress.update(self._task_id, description=f"{phase}{suffix}")

    def finish_current(self) -> None:
        if self._current_phase is None:
            return
        elapsed = perf_counter() - self._phase_started
        self.records.append(
            StepRecord(
                phase=self._current_phase,
                detail=self._current_detail,
                elapsed=elapsed,
            )
        )
        self._current_phase = None
        self._current_detail = ""

    def print_summary(self) -> None:
        if not self.records:
            return
        table = Table(title="Execution steps")
        table.add_column("Step")
        table.add_column("Detail")
        table.add_column("Time", justify="right")
        for record in self.records:
            table.add_row(record.phase, record.detail or "-", f"{record.elapsed:.2f}s")
        self.console.print(table)
