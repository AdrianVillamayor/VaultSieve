from __future__ import annotations

import re
from types import TracebackType

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, Task, TextColumn, TimeElapsedColumn

PROGRESS_COUNTER_RE = re.compile(r" \(\d+/\d+ unique (?:passwords|domains)\)$")


class DoneAwareSpinnerColumn(SpinnerColumn):
    def render(self, task: Task) -> str:
        if task.fields.get("done"):
            return "✓"
        return super().render(task)


class AuditProgress:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._current_phase: str | None = None
        self._progress: Progress | None = None
        self._task_ids: dict[str, int] = {}

    def __enter__(self) -> AuditProgress:
        self._progress = Progress(
            DoneAwareSpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
        )
        self._progress.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.__exit__(exc_type, exc, traceback)

    def update(self, phase: str, completed: int | None = None) -> None:
        detail = f"{completed} checked" if completed is not None else ""
        if self._progress is None:
            return
        task_key = PROGRESS_COUNTER_RE.sub("", phase)
        if task_key != self._current_phase:
            if self._current_phase is not None:
                previous_task_id = self._task_ids[self._current_phase]
                self._progress.update(
                    previous_task_id,
                    description=f"{self._current_phase} done",
                    done=True,
                )
                self._progress.stop_task(previous_task_id)
            self._current_phase = task_key
            self._task_ids[task_key] = self._progress.add_task(
                phase, total=None)
        suffix = f" ({detail})" if detail else ""
        self._progress.update(
            self._task_ids[task_key], description=f"{phase}{suffix}")
