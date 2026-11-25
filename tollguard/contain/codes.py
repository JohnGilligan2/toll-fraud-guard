"""One-time codes: the step a prompt injection cannot supply.

The first version of these tools acted on a bare confirm=true. That was a hole:
text in a ticket or an email the model was reading could say "confirm=true"
and the model would pass it along. Now a write needs a six-digit code sent to
the signed-in person, out of the model's sight. The person reads it and types
it. The model never sees it, so nothing the model reads can contain it.

A code is single use, expires, allows a few wrong guesses, and is bound to the
exact request: caller, action, domain, and a scope string naming the users and
switches. A code issued to lock user 204 cannot lock 205, or lock 204 on a
different switch, or lock the whole domain.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

TTL_SECONDS = 600
MAX_ATTEMPTS = 3


class Notifier(Protocol):
    def send_code(self, to: str, code: str, action: str, domain: str, detail: str) -> None:
        """Deliver the code to `to` (an email address, normally). Raise on failure."""


@dataclass
class _Pending:
    code: str
    expires: float
    attempts: int = 0


class CodeBook:
    def __init__(self, notifier: Notifier, ttl_s: int = TTL_SECONDS,
                 max_attempts: int = MAX_ATTEMPTS, clock: Callable[[], float] = time.monotonic):
        self.notifier, self.ttl_s, self.max_attempts, self.clock = notifier, ttl_s, max_attempts, clock
        self._pending: dict[tuple[str, str, str, str], _Pending] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(caller: str, action: str, domain: str, scope: str) -> tuple[str, str, str, str]:
        return caller.strip().lower(), action, domain.strip().lower(), scope

    def issue(self, caller: str, action: str, domain: str, scope: str, detail: str) -> tuple[bool, str]:
        """Send a fresh code (replacing any earlier one for the same request)."""
        code = f"{secrets.randbelow(1_000_000):06d}"
        key = self._key(caller, action, domain, scope)
        try:
            self.notifier.send_code(caller, code, action, domain, detail)
        except Exception as e:  # noqa: BLE001 - any delivery failure means no code, said plainly
            return False, f"the code could not be sent ({str(e)[:160]})."
        with self._lock:
            self._pending[key] = _Pending(code, self.clock() + self.ttl_s)
        return True, caller

    def redeem(self, caller: str, action: str, domain: str, scope: str,
               code: str | None) -> tuple[bool, str]:
        key = self._key(caller, action, domain, scope)
        with self._lock:
            p = self._pending.get(key)
            if p is None:
                return False, ("no code is waiting for exactly this request (same person, "
                               "action, domain, users and switches). Request a new one.")
            if self.clock() > p.expires:
                del self._pending[key]
                return False, "the code expired. Request a new one."
            if p.attempts >= self.max_attempts:
                del self._pending[key]
                return False, "too many wrong codes; this one is cancelled. Request a new one."
            if not secrets.compare_digest(str(code or "").strip(), p.code):
                p.attempts += 1
                left = self.max_attempts - p.attempts
                if left <= 0:
                    del self._pending[key]
                return False, f"wrong code ({max(left, 0)} attempt(s) left)."
            del self._pending[key]
            return True, "verified"


class ConsoleNotifier:
    """For the demo: prints the code as if it had arrived by email."""

    def send_code(self, to: str, code: str, action: str, domain: str, detail: str) -> None:
        print(f"    [email to {to}] Your code to {action} in {domain} ({detail}): {code}")


class MemoryNotifier:
    """For tests: keeps the last code per recipient."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str, str]] = []
        self.fail = False

    def send_code(self, to: str, code: str, action: str, domain: str, detail: str) -> None:
        if self.fail:
            raise OSError("mail relay refused the message")
        self.sent.append((to, code, action, domain))

    def last(self, to: str) -> str:
        return next(c for t, c, _, _ in reversed(self.sent) if t == to)
