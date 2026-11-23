"""Python client for the stackprint scanner.

Runs ``stackprint scan`` as a long-lived subprocess and exchanges one JSON
line per page. The binary answers in input order and flushes every line, so
a request/response loop over the pipe is safe::

    from stackprint import Scanner

    with Scanner() as sc:
        result = sc.scan({"url": "https://example.test/", "html": html, "headers": [["Server", "nginx"]]})
        for d in result["detections"]:
            print(d["tech_id"], d.get("version"))

A Scanner is not thread-safe; use one per worker thread or process.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Iterable, Iterator

__all__ = ["Scanner", "ScannerError"]


class ScannerError(RuntimeError):
    pass


class Scanner:
    def __init__(
        self,
        binary: str | None = None,
        rules: str | None = None,
        knowledge: str | None = None,
        extra_args: Iterable[str] = (),
    ):
        binary = binary or os.environ.get("STACKPRINT_BIN") or shutil.which("stackprint")
        if not binary:
            raise ScannerError("stackprint binary not found (set STACKPRINT_BIN or put it on PATH)")
        args = [binary, "scan", "-c", "1"]
        if rules:
            args += ["-rules", rules]
        if knowledge:
            args += ["-knowledge", knowledge]
        args += list(extra_args)
        self._proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def scan(self, document: dict[str, Any]) -> dict[str, Any]:
        """Scan one page document and return the result."""
        return next(self.scan_many([document]))

    def scan_many(self, documents: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        """Scan documents one at a time, yielding results in order."""
        proc = self._proc
        if proc.poll() is not None:
            raise ScannerError(f"scanner exited: {proc.stderr.read()}")
        for doc in documents:
            proc.stdin.write(json.dumps(doc, ensure_ascii=False) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise ScannerError(f"scanner closed its output: {proc.stderr.read()}")
            yield json.loads(line)

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.stdin.close()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
