#!/usr/bin/env python3
"""Failure-isolated GitHub Actions annotations and step summaries.

The test/build verdict is the primary evidence.  Rendering that evidence for
GitHub is secondary and must never replace the verdict with an encoding or I/O
exception.  This adapter therefore:

* escapes workflow-command data according to the Actions command protocol;
* writes UTF-8 bytes when a non-UTF-8 text wrapper exposes a binary buffer;
* falls back to a representable, backslash-escaped command when it does not;
* reports every lossy or failed delivery as ``CI evidence degraded``; and
* never raises for an annotation or job-summary delivery failure.

Callers may inspect ``degradations`` or the boolean return values, but must not
use reporting success to change their primary pass/fail decision.
"""

from __future__ import annotations

import codecs
import os
import sys
from typing import TextIO


_DYNAMIC = object()
_ANNOTATION_KINDS = frozenset({"debug", "error", "notice", "warning"})
MAX_EVIDENCE_DEGRADATIONS = 16
MAX_EVIDENCE_DEGRADATION_CHARS = 512


def escape_workflow_command_data(value: object) -> str:
    """Escape a workflow-command payload without changing ordinary Unicode."""

    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _is_utf8(encoding: str | None) -> bool:
    if not encoding:
        return False
    try:
        return codecs.lookup(encoding).name == "utf-8"
    except LookupError:
        return False


class GitHubOutput:
    """Best-effort GitHub output with explicit evidence-degradation signals."""

    def __init__(
        self,
        *,
        command_stream: TextIO | object = _DYNAMIC,
        diagnostic_stream: TextIO | object = _DYNAMIC,
        summary_path: str | None | object = _DYNAMIC,
        github_actions: bool | None = None,
    ) -> None:
        self._command_stream = command_stream
        self._diagnostic_stream = diagnostic_stream
        self._summary_path = summary_path
        self._github_actions = github_actions
        self._degradations: list[str] = []
        self._degradation_count = 0

    @property
    def degradations(self) -> tuple[str, ...]:
        return tuple(self._degradations)

    @property
    def degradation_count(self) -> int:
        return self._degradation_count

    @property
    def evidence_complete(self) -> bool:
        return self._degradation_count == 0

    def _commands(self) -> TextIO:
        if self._command_stream is _DYNAMIC:
            return sys.stdout
        return self._command_stream  # type: ignore[return-value]

    def _diagnostics(self) -> TextIO:
        if self._diagnostic_stream is _DYNAMIC:
            return sys.stderr
        return self._diagnostic_stream  # type: ignore[return-value]

    def _summary(self) -> str | None:
        if self._summary_path is _DYNAMIC:
            return os.environ.get("GITHUB_STEP_SUMMARY")
        return self._summary_path  # type: ignore[return-value]

    def _in_github_actions(self) -> bool:
        if self._github_actions is not None:
            return self._github_actions
        return os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    @staticmethod
    def _write_ascii(stream: TextIO, text: str) -> bool:
        """Write an ASCII diagnostic without allowing another output failure."""

        try:
            stream.write(text)
            stream.flush()
            return True
        except Exception:  # noqa: BLE001 - evidence delivery never owns verdict semantics
            return False

    def _record_degradation(self, reason: str) -> None:
        # Keep the diagnostic itself ASCII so it can survive legacy Windows
        # console encodings.  repr/backslashreplace also prevents a second
        # unencodable test name from hiding the first failure.
        safe_reason = reason.encode("ascii", errors="backslashreplace").decode("ascii")
        safe_reason = safe_reason[:MAX_EVIDENCE_DEGRADATION_CHARS]
        self._degradation_count += 1
        if len(self._degradations) < MAX_EVIDENCE_DEGRADATIONS:
            self._degradations.append(safe_reason)
        elif self._degradation_count == MAX_EVIDENCE_DEGRADATIONS + 1:
            self._degradations[-1] = (
                f"additional evidence degradations omitted "
                f"(more than {MAX_EVIDENCE_DEGRADATIONS})"
            )
        warning = (
            "::warning::"
            + escape_workflow_command_data(f"CI evidence degraded: {safe_reason}")
            + "\n"
        )
        if self._write_ascii(self._commands(), warning):
            return
        self._write_ascii(
            self._diagnostics(),
            f"[CI evidence degraded] {safe_reason}\n",
        )

    def _write_command(self, command: str) -> bool:
        """Write one UTF-8 command; return False only for lossy/failed output."""

        stream = None
        encoding = None
        try:
            stream = self._commands()
            encoding = getattr(stream, "encoding", None)
            if encoding and not _is_utf8(encoding) and hasattr(stream, "buffer"):
                # GitHub's workflow-command protocol requires UTF-8.  Bypass a
                # CP1252 (or other legacy) TextIOWrapper rather than asking it
                # to encode a Unicode Catch2 name it cannot represent.
                stream.flush()
                stream.buffer.write(command.encode("utf-8"))  # type: ignore[attr-defined]
                stream.buffer.flush()  # type: ignore[attr-defined]
            else:
                stream.write(command)
                stream.flush()
            return True
        except UnicodeError as ex:
            # A synthetic/injected stream may enforce a legacy encoding but
            # expose no binary buffer.  Preserve an ASCII-readable command and
            # make the loss visible; never let it replace the test verdict.
            fallback_encoding = encoding or "ascii"
            try:
                safe = command.encode(fallback_encoding, errors="backslashreplace").decode(
                    fallback_encoding
                )
            except LookupError:
                safe = command.encode("ascii", errors="backslashreplace").decode("ascii")
            if stream is not None and self._write_ascii(stream, safe):
                self._record_degradation(
                    f"workflow annotation used a lossy {fallback_encoding} fallback ({type(ex).__name__})"
                )
            else:
                self._record_degradation(
                    f"workflow annotation could not be written ({type(ex).__name__})"
                )
            return False
        except Exception as ex:  # noqa: BLE001 - evidence delivery never owns verdict semantics
            self._record_degradation(
                f"workflow annotation could not be written ({type(ex).__name__})"
            )
            return False

    def annotation(self, kind: str, message: object) -> bool:
        """Emit one annotation.  Delivery failure is returned, never raised."""

        try:
            normalized = str(kind).lower()
        except Exception as ex:  # noqa: BLE001 - rendering cannot own the verdict
            self._record_degradation(
                f"annotation kind could not be rendered ({type(ex).__name__})"
            )
            return False
        if normalized not in _ANNOTATION_KINDS:
            self._record_degradation(f"unsupported annotation kind {normalized!r}")
            return False
        try:
            data = escape_workflow_command_data(message)
        except Exception as ex:  # noqa: BLE001 - rendering cannot own the verdict
            self._record_degradation(
                f"annotation message could not be rendered ({type(ex).__name__})"
            )
            return False
        command = f"::{normalized}::{data}\n"
        return self._write_command(command)

    def job_summary(self, markdown: object) -> bool:
        """Append UTF-8 Markdown when Actions provides a summary file."""

        path = self._summary()
        if not path:
            if self._in_github_actions():
                self._record_degradation(
                    "GITHUB_STEP_SUMMARY is absent or empty in GitHub Actions"
                )
                return False
            return True
        try:
            with open(path, "a", encoding="utf-8", newline="\n") as summary_file:
                summary_file.write(str(markdown) + "\n")
            return True
        except Exception as ex:  # noqa: BLE001 - evidence delivery never owns verdict semantics
            self._record_degradation(
                f"job summary could not be written ({type(ex).__name__})"
            )
            return False
