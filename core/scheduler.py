from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class TaskControl:
    cancellation: asyncio.Event = field(default_factory=asyncio.Event)
    active_task: asyncio.Task | None = None

    def cancel(self) -> None:
        self.cancellation.set()
        if self.active_task is not None:
            self.active_task.cancel()
