from __future__ import annotations

import shutil
import sys
from datetime import datetime
from pathlib import Path


class ConsoleProgress:
    """Human-readable progress on stderr; stdout remains the task result."""

    def __init__(self) -> None:
        self._thinking_active = False
        self._buf = ""  # full text of the current thinking block
        self._tty = sys.stderr.isatty()
        self._expanded = False  # collapsed by default; toggled live with the space key

    def __call__(self, message: str) -> None:
        stamp = datetime.now().astimezone().strftime("%H:%M:%S")
        print(f"[system-agent {stamp}] {message}", file=sys.stderr, flush=True)

    @staticmethod
    def _sanitize(chunk: str) -> str:
        return "".join(ch for ch in chunk if ch in "\n\t" or (ord(ch) >= 32 and ord(ch) != 127))

    def thinking(self, chunk: str) -> None:
        if not self._thinking_active:
            self("Ollama thinking 시작" + (self._hint() if self._collapsing() else ""))
            self._thinking_active = True
            self._buf = ""
        safe = self._sanitize(chunk)
        self._buf += safe
        if self._collapsing():
            # Interactive & collapsed: show only the latest line, updated in place.
            self._render_live(self._buf.rsplit("\n", 1)[-1])
        else:
            # Non-interactive, or expanded by the user: stream the full text.
            print(safe, end="", file=sys.stderr, flush=True)

    def _collapsing(self) -> bool:
        return self._tty and not self._expanded

    @staticmethod
    def _hint() -> str:
        return "  (space=생각 과정 펼치기/접기)"

    def toggle_thinking(self) -> None:
        """Flip between collapsed one-line and full thinking view (interactive only)."""
        if not self._tty:
            return
        self._expanded = not self._expanded
        if not self._thinking_active:
            return
        if self._expanded:
            # Reprint the whole block captured so far, then keep streaming in full.
            print("\r\x1b[K  [생각 과정 펼침 ▼]", file=sys.stderr, flush=True)
            print(self._buf, end="", file=sys.stderr, flush=True)
        else:
            print("\n  [생각 과정 접힘 ▲ — space로 펼치기]", file=sys.stderr, flush=True)
            self._render_live(self._buf.rsplit("\n", 1)[-1])

    def _render_live(self, text: str) -> None:
        text = text.replace("\t", " ")
        width = shutil.get_terminal_size((80, 24)).columns
        prefix = "  > "
        avail = max(8, width - len(prefix) - 1)
        shown = text if len(text) <= avail else "…" + text[-(avail - 1):]
        print("\r\x1b[K" + prefix + shown, end="", file=sys.stderr, flush=True)

    def thinking_end(self) -> None:
        if self._thinking_active:
            if self._collapsing():
                print("\r\x1b[K", end="", file=sys.stderr, flush=True)  # erase the live line
            else:
                print(file=sys.stderr, flush=True)
            self._thinking_active = False
            self._buf = ""
            self("Ollama thinking 종료")


class FileProgress:
    """Wraps a progress callable and mirrors every event to a timestamped log file.

    Records the full research process start-to-finish — skill calls, model
    requests/responses and the reasoning stream (via thinking/thinking_end) —
    plus anything written with log(), such as the task and the final result.
    The inner progress still drives the console; this only tees to the file.
    """

    def __init__(self, inner, log_path) -> None:
        self._inner = inner
        self._path = Path(log_path)
        self._think: list[str] = []
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self._path.open("a", encoding="utf-8")
        except OSError:
            self._fh = None  # Logging must never break the run.
        self._raw(f"\n===== research 시작 {self._stamp()} =====\n")

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def _stamp() -> str:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    def _raw(self, text: str) -> None:
        if self._fh is None:
            return
        try:
            self._fh.write(ConsoleProgress._sanitize(text))
            self._fh.flush()
        except (OSError, ValueError):
            self._fh = None

    def __call__(self, message: str) -> None:
        if self._inner:
            self._inner(message)
        self._raw(f"[{self._stamp()}] {message}\n")

    def thinking(self, chunk: str) -> None:
        fn = getattr(self._inner, "thinking", None)
        if fn:
            fn(chunk)
        self._think.append(chunk)

    def thinking_end(self) -> None:
        fn = getattr(self._inner, "thinking_end", None)
        if fn:
            fn()
        text = "".join(self._think).strip()
        self._think.clear()
        if text:
            self._raw("--- thinking ---\n" + text + "\n--- /thinking ---\n")

    def toggle_thinking(self) -> None:
        fn = getattr(self._inner, "toggle_thinking", None)
        if fn:
            fn()

    def log(self, message: str) -> None:
        """Write to the log file only (not the console)."""
        self._raw(message if message.endswith("\n") else message + "\n")

    def close(self, *, status: str = "완료") -> None:
        self._raw(f"===== research {status} {self._stamp()} =====\n")
        if self._fh is not None:
            try:
                self._fh.close()
            except (OSError, ValueError):
                pass
            self._fh = None
