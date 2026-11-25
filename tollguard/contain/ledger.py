"""The ordered ledger that makes undo safe.

Every containment action is appended to one JSON-lines file: a sequence number,
the time, who did it (from their identity, never from an argument), how they
came in, and each value before and after. Undo reads ONLY from here:

  * a user restore writes back the permission the ledger recorded before the
    lock, so nobody can type "allow everything" into an undo;
  * a repeat lock keeps the FIRST recorded value, the pre-incident one;
  * an unlock only reopens a domain THIS tool locked. Tenants are locked for
    other reasons too (cancelled, migrated, unpaid) and none of those may be
    reopened from here.

A corrupt line is skipped loudly and never stops the rest loading. A failed
append raises: a change that is not in the ledger cannot be undone by the tool,
and the caller must say so.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("tollguard.ledger")


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.corrupt_lines: list[int] = []

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events, bad = [], []
        with self.path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    bad.append(n)
                    logger.error("ledger line %d is not valid JSON; skipped", n)
        self.corrupt_lines = bad
        return sorted(events, key=lambda e: int(e.get("seq", 0)))

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            seq = max((int(e.get("seq", 0)) for e in self.read()), default=0) + 1
            entry = {"seq": seq,
                     "at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                     **event}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def _for(self, domain: str | None) -> list[dict[str, Any]]:
        want = (domain or "").strip().lower()
        return [e for e in self.read()
                if not want or str(e.get("domain", "")).strip().lower() == want]

    def open_user_locks(self, domain: str | None = None) -> dict[tuple[str, str, str], dict[str, Any]]:
        """User locks not yet restored, keyed (pbx, domain, user)."""
        state: dict[tuple[str, str, str], dict[str, Any]] = {}
        for e in self._for(domain):
            if e.get("action") not in ("lock_users", "restore_users"):
                continue
            dom = str(e.get("domain", "")).lower()
            for c in e.get("changes") or []:
                if not c.get("ok"):
                    continue
                key = (str(c["pbx"]), dom, str(c["user"]))
                if e["action"] == "lock_users" and key not in state:
                    state[key] = {"restore_to": c.get("old") or "", "seq": e["seq"],
                                  "by": e.get("by"), "at_utc": e.get("at_utc")}
                elif e["action"] == "restore_users":
                    state.pop(key, None)
        return state

    def open_domain_locks(self, domain: str | None = None) -> dict[tuple[str, str], dict[str, Any]]:
        """Domain locks this tool made and has not undone, keyed (pbx, domain)."""
        state: dict[tuple[str, str], dict[str, Any]] = {}
        for e in self._for(domain):
            if e.get("action") not in ("lock_domain", "unlock_domain"):
                continue
            dom = str(e.get("domain", "")).lower()
            for c in e.get("changes") or []:
                if not c.get("ok"):
                    continue
                key = (str(c["pbx"]), dom)
                if e["action"] == "lock_domain" and key not in state:
                    state[key] = {"was": c.get("old") or "", "seq": e["seq"],
                                  "by": e.get("by"), "at_utc": e.get("at_utc")}
                elif e["action"] == "unlock_domain":
                    state.pop(key, None)
        return state

    def history(self, domain: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return self._for(domain)[-max(1, min(int(limit), 500)):]
