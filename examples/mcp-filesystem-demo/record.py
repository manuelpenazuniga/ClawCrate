#!/usr/bin/env python3
"""Record `demo.sh --live` as an asciinema v2 cast.

The asset committed next to this script is a real capture of a real run, not a
mock-up, and this is how it was produced — so anyone can regenerate it and
compare rather than take the recording on trust:

    ./record.py

Writes `demo.cast`, playable with `asciinema play demo.cast`, or on the web with
the asciinema player. The demo runs under a pty so the output is what a terminal
would show, including any colour.

Timings are the real ones, with long gaps clamped: the live run waits several
seconds for Node to start and for the Replica to materialize, and a recording
that faithfully reproduces an eight-second pause is a recording nobody watches.
The clamp only shortens waiting; it never reorders or invents output.
"""

from __future__ import annotations

import json
import os
import pty
import select
import shlex
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAST_PATH = HERE / "demo.cast"

COLUMNS = 100
ROWS = 32

# Longest pause reproduced in the recording, in seconds. Long enough that the
# sections still read as separate steps rather than one flash of text, short
# enough that nobody waits out the Replica materializing.
MAX_GAP_SECONDS = 2.5


def record(command: list[str], env: dict[str, str]) -> list[tuple[float, str]]:
    """Runs `command` under a pty, returning (timestamp, output) chunks."""
    events: list[tuple[float, str]] = []
    started = time.monotonic()

    pid, master_fd = pty.fork()
    if pid == 0:
        # Child: become the recorded process.
        os.environ.update(env)
        os.environ["COLUMNS"] = str(COLUMNS)
        os.environ["LINES"] = str(ROWS)
        os.execvp(command[0], command)
        raise SystemExit(127)

    try:
        while True:
            ready, _, _ = select.select([master_fd], [], [], 30)
            if not ready:
                break
            try:
                chunk = os.read(master_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            events.append(
                (time.monotonic() - started, chunk.decode("utf-8", errors="replace"))
            )
            # Mirror to this terminal so a human running the recorder sees the
            # same thing the cast will show.
            sys.stdout.write(chunk.decode("utf-8", errors="replace"))
            sys.stdout.flush()
    finally:
        os.close(master_fd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    return events


def clamp_gaps(events: list[tuple[float, str]]) -> list[tuple[float, str]]:
    """Shortens dead air without reordering or dropping any output."""
    clamped: list[tuple[float, str]] = []
    previous_source = 0.0
    elapsed = 0.0
    for timestamp, data in events:
        gap = min(timestamp - previous_source, MAX_GAP_SECONDS)
        elapsed += max(gap, 0.0)
        clamped.append((elapsed, data))
        previous_source = timestamp
    return clamped


def redact(data: str, home: str, repo: str) -> str:
    """Replaces the recording machine's paths with portable placeholders.

    A committed cast is published, so it must not carry whoever recorded it: the
    home directory holds their username, and the checkout path holds wherever
    they keep their work. This is a display substitution and nothing else — no
    output is added, removed or reordered, and the paths it replaces are exactly
    the two the recorder already knows.
    """
    if repo:
        data = data.replace(repo, "/path/to/ClawCrate")
    if home:
        data = data.replace(home, "~")
    return data


def write_cast(events: list[tuple[float, str]], path: Path) -> None:
    header = {
        "version": 2,
        "width": COLUMNS,
        "height": ROWS,
        "title": "ClawCrate — sandboxing an MCP filesystem server",
        "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
    }
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(header) + "\n")
        home = os.path.expanduser("~").rstrip("/")
        repo = str(HERE.parent.parent)
        for timestamp, data in events:
            handle.write(
                json.dumps([round(timestamp, 3), "o", redact(data, home, repo)]) + "\n"
            )


def main() -> int:
    demo = HERE / "demo.sh"
    if not demo.is_file():
        print(f"error: {demo} not found", file=sys.stderr)
        return 1

    command = [str(demo), "--live"]
    env = {
        # Both are opt-in enrichments; the demo is about showing what the audit
        # trail can hold, so it asks for everything available.
        "CLAWCRATE_AUDIT_HASHCHAIN": "1",
        "CLAWCRATE_SEATBELT_VIOLATIONS": "1",
        # Colour would otherwise be stripped, since the demo's stdout is a pipe
        # in normal use but a pty here.
        "TERM": "xterm-256color",
    }

    print(f"Recording: {shlex.join(command)}\n", file=sys.stderr)
    events = record(command, env)
    if not events:
        print("error: the demo produced no output", file=sys.stderr)
        return 1

    write_cast(clamp_gaps(events), CAST_PATH)
    print(f"\nWrote {CAST_PATH} ({len(events)} frames)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
