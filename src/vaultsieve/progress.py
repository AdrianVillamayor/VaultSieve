from __future__ import annotations

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


class AuditProgress:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._current_phase: str | None = None
        self._progress: Progress | None = None
        self._task_ids: dict[str, int] = {}

    def __enter__(self) -> AuditProgress:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
        )
        self._progress.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        if self._progress is not None:
            self._progress.__exit__(exc_type, exc, traceback)

    def update(self, phase: str, completed: int | None = None) -> None:
        detail = f"{completed} checked" if completed is not None else ""
        if self._progress is None:
            return
        if phase != self._current_phase:
            self._current_phase = phase
            self._task_ids[phase] = self._progress.add_task(phase, total=None)
        suffix = f" ({detail})" if detail else ""
        self._progress.update(self._task_ids[phase], description=f"{phase}{suffix}")
