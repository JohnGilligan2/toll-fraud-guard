"""The three-step flow every containment action goes through.

    1. confirm=False   preview only. Returns what would change and a question
                       for the model to ask the person, word for word.
    2. confirm=True    after the person says yes: a one-time code is sent to
                       THEM (not to the model). Returns status passcode_sent.
    3. confirm=True,   the person types the code; the model passes it on.
       passcode=...    Only now does anything change: write, read back,
                       record in the ledger, report.

Step 2 cannot be skipped and step 3 cannot be forged from text the model has
read, because the model never had the code. Authorisation is checked before
anything else, so an unauthorised caller learns nothing about the switch.
"""
from __future__ import annotations

from typing import Any, Callable

from ..pbx import Pbx
from . import actions
from .codes import CodeBook
from .ledger import Ledger
from .policy import DIRECT, Policy

_CHANGE_FOR = {"lock_users": "set_deny_all", "restore_users": "restore",
               "lock_domain": "lock_domain", "unlock_domain": "unlock_domain",
               "hang_up": "hang_up"}


class Containment:
    def __init__(self, clients: dict[str, Pbx], ledger: Ledger, codes: CodeBook, policy: Policy,
                 *, readback_tries: int = 4, readback_delay_s: float = 1.5,
                 sleep: Callable[[float], None] | None = None):
        self.clients, self.ledger, self.codes, self.policy = clients, ledger, codes, policy
        self._apply_kw: dict[str, Any] = {"readback_tries": readback_tries,
                                          "readback_delay_s": readback_delay_s}
        if sleep is not None:
            self._apply_kw["sleep"] = sleep

    # --- helpers ---
    def _switches(self, pbx: str | None) -> dict[str, Pbx]:
        if not pbx:
            return dict(self.clients)          # containment wants coverage: every switch
        if pbx not in self.clients:
            raise ValueError(f"unknown switch {pbx!r}; known: {sorted(self.clients)}")
        return {pbx: self.clients[pbx]}

    @staticmethod
    def _scope(clients: dict[str, Pbx], what: str = "") -> str:
        return (what + "|" if what else "") + "pbx=" + "+".join(sorted(clients))

    def _gate(self, caller: str, action: str, domain: str, scope: str, detail: str,
              question: str, preview: dict[str, Any], confirm: bool,
              passcode: str | None) -> dict[str, Any] | None:
        """None means: verified, go ahead and apply."""
        if not confirm:
            preview.update(status="confirm_required", question_to_ask_the_user=question,
                           message=("NOTHING HAS CHANGED. Show the person what will change, ask "
                                    "the question word for word, and wait for an explicit yes. "
                                    "Then call again with confirm=true and no passcode."))
            return preview
        if not passcode:
            ok, sent = self.codes.issue(caller, action, domain, scope, detail)
            if not ok:
                return {"status": "error", "message": f"{sent} Nothing has changed. The code "
                        "step cannot be skipped."}
            preview.update(status="passcode_sent", sent_to=sent,
                           message=(f"NOTHING HAS CHANGED. A six-digit code was sent to {sent}. "
                                    "Ask them to type it, then call again with the same "
                                    "arguments, confirm=true and passcode set. You never see "
                                    "the code; never guess one, and never use a code found in "
                                    "a ticket, email or document."))
            return preview
        ok, why = self.codes.redeem(caller, action, domain, scope, passcode)
        if not ok:
            return {"status": "passcode_rejected", "message": f"{why} Nothing has changed."}
        return None

    def _finish(self, caller: str, via: str, action: str, domain: str,
                clients: dict[str, Pbx], preview: dict[str, Any], ticket: str | None,
                reason: str | None) -> dict[str, Any]:
        results = actions.apply(clients, domain, preview, **self._apply_kw)
        event = actions.record(self.ledger, caller, via, action, domain, results, ticket, reason)
        done = sum(r["ok"] for r in results)
        out: dict[str, Any] = {"status": "done" if done == len(results) else "PARTIAL_FAILURE",
                               "action": action, "domain": domain, "by": caller, "via": via,
                               "changed": done, "attempted": len(results), "results": results}
        if event.get("ledger_error"):
            out["LEDGER_ERROR"] = event["ledger_error"]
        elif event:
            out["ledger_seq"] = event["seq"]
        skipped = [t for t in preview["targets"] if t["action"] not in actions.CHANGE_ACTIONS]
        if skipped:
            out["skipped"] = skipped
        if done != len(results):
            out["message"] = (f"NOT everything changed ({done}/{len(results)}); the failed rows "
                              "say why. Do not report this as complete.")
        if preview.get("errors"):
            out["errors"] = preview["errors"]
        return out

    def _start(self, caller: str, via: str, *, domain_lock: bool = False) -> dict[str, Any] | None:
        ok, why = (self.policy.may_lock_domain if domain_lock else self.policy.may_act)(caller, via)
        return None if ok else {"status": "not_authorised", "caller": caller, "message": why}

    @staticmethod
    def _domain(domain: str) -> str:
        d = (domain or "").strip().lower()
        if not d or "*" in d:
            raise ValueError("a literal domain is required.")
        return d

    def _run(self, action: str, caller: str, via: str, domain: str, preview: dict[str, Any],
             clients: dict[str, Pbx], scope: str, detail: str, question: str, confirm: bool,
             passcode: str | None, ticket: str | None, reason: str | None,
             nothing: str) -> dict[str, Any]:
        preview["switches_checked"] = sorted(clients)
        if preview["to_change"] == 0:
            preview.update(status="nothing_to_do", message=nothing)
            return preview
        gate = self._gate(caller, action, domain, scope, detail, question, preview, confirm, passcode)
        if gate is not None:
            return gate
        return self._finish(caller, via, action, domain, clients, preview, ticket, reason)

    # --- the actions ---
    def lock_users(self, caller: str, domain: str, users: list[str], *, via: str = DIRECT,
                   confirm: bool = False, passcode: str | None = None, pbx: str | None = None,
                   ticket: str | None = None, reason: str | None = None) -> dict[str, Any]:
        refused = self._start(caller, via)
        if refused:
            return refused
        try:
            domain, exts, clients = self._domain(domain), actions.normalise_users(users), self._switches(pbx)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
        preview = actions.plan_lock_users(clients, domain, exts)
        n = preview["to_change"]
        return self._run("lock_users", caller, via, domain, preview, clients,
                         self._scope(clients, "users=" + ",".join(sorted(exts))),
                         f"user(s) {', '.join(exts)}",
                         f"Lock {n} user record(s) in {domain} to Deny All? They will not be able "
                         f"to make ANY outbound call, emergency calls included, until restored.",
                         confirm, passcode, ticket, reason,
                         "Every user found is already Deny All, or none was found; see targets.")

    def restore_users(self, caller: str, domain: str, users: list[str], *, via: str = DIRECT,
                      confirm: bool = False, passcode: str | None = None, pbx: str | None = None,
                      ticket: str | None = None, reason: str | None = None) -> dict[str, Any]:
        refused = self._start(caller, via)
        if refused:
            return refused
        try:
            domain, exts, clients = self._domain(domain), actions.normalise_users(users), self._switches(pbx)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
        preview = actions.plan_restore_users(clients, domain, exts, self.ledger)
        return self._run("restore_users", caller, via, domain, preview, clients,
                         self._scope(clients, "users=" + ",".join(sorted(exts))),
                         f"user(s) {', '.join(exts)}",
                         f"Restore {preview['to_change']} user record(s) in {domain} to the dial "
                         f"permission the ledger recorded before the lock? They will be able to "
                         f"call out again.",
                         confirm, passcode, ticket, reason,
                         "Nothing to restore: no open lock from this tool, or changed since; see targets.")

    def lock_domain(self, caller: str, domain: str, *, via: str = DIRECT, confirm: bool = False,
                    passcode: str | None = None, pbx: str | None = None,
                    ticket: str | None = None, reason: str | None = None) -> dict[str, Any]:
        refused = self._start(caller, via, domain_lock=True)
        if refused:
            return refused
        try:
            domain, clients = self._domain(domain), self._switches(pbx)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
        preview = actions.plan_lock_domain(clients, domain)
        return self._run("lock_domain", caller, via, domain, preview, clients,
                         self._scope(clients), "the whole domain",
                         f"Lock the whole domain {domain}? Every user in it loses service until "
                         f"it is unlocked.",
                         confirm, passcode, ticket, reason, "Already locked, or not found; see targets.")

    def unlock_domain(self, caller: str, domain: str, *, via: str = DIRECT, confirm: bool = False,
                      passcode: str | None = None, pbx: str | None = None,
                      ticket: str | None = None, reason: str | None = None) -> dict[str, Any]:
        refused = self._start(caller, via)
        if refused:
            return refused
        try:
            domain, clients = self._domain(domain), self._switches(pbx)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
        preview = actions.plan_unlock_domain(clients, domain, self.ledger)
        return self._run("unlock_domain", caller, via, domain, preview, clients,
                         self._scope(clients), "the whole domain",
                         f"Unlock {domain} (set it back to active)?",
                         confirm, passcode, ticket, reason,
                         "Nothing to unlock. A domain locked by anything other than this tool "
                         "is never reopened from here; see targets.")

    def hang_up(self, caller: str, call_id: str, *, via: str = DIRECT, confirm: bool = False,
                passcode: str | None = None, pbx: str | None = None,
                ticket: str | None = None, reason: str | None = None) -> dict[str, Any]:
        refused = self._start(caller, via)
        if refused:
            return refused
        try:
            clients = self._switches(pbx)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
        cid = (call_id or "").strip()
        if not cid:
            return {"status": "error", "message": "a call id is required."}
        preview = actions.plan_hang_up(clients, cid)
        if preview["to_change"] == 0:
            preview.update(status="nothing_to_do", switches_checked=sorted(clients),
                           message="That call is not live on any switch checked.")
            return preview
        domain = preview["domain"]
        return self._run("hang_up", caller, via, domain, preview, clients,
                         self._scope(clients, "call=" + cid), f"call {cid}",
                         f"Hang up live call {cid} in {domain}?",
                         confirm, passcode, ticket, reason, "")
