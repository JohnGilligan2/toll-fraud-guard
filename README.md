# toll-fraud-guard

Detect toll fraud on a hosted PBX, and contain it with an agent doing the legwork and a person approving every change.

## The problem

Toll fraud on a hosted phone system starts with one stolen SIP password and ends with a bill for hundreds of international calls placed overnight. By the time the carrier's fraud desk calls you, the money is gone. Two things have to get faster: noticing, and stopping it.

Noticing has two sides. A stolen password usually shows up first as a phone registering from somewhere the customer has never been: a datacenter, a VPN, a country with no staff in it. But attackers increasingly skip registration and send calls straight at the switch on the stolen credentials, so those calls only ever appear in the call records.

Stopping it is where it gets risky. The fix is a write to a live phone switch: set a user to Deny All, lock a whole tenant, hang up a call in progress. An agent can do that legwork fast, but the same agent reads tickets and email, and anything it reads can try to tell it what to do.

## Where it came from

I run detection and containment like this for an MSP's hosted voice platform. The registration scan runs hourly and the call scan every few minutes. The containment tools were added after a carrier toll-fraud alert in October 2026, and they're exposed over MCP so the NOC can run them from Claude.

The first version of the write tools acted on preview, then `confirm=true`. A few days in, I closed that path, because text inside a ticket could supply the `confirm=true` just as well as a person could. Now every write ends in a six-digit code sent to the signed-in person, and the model never sees it. This repo is that design, rebuilt without any customer, carrier or vendor specifics.

## Detection

**Registrations** (`registrations.py`). Live registrations are grouped by source IP, and each IP is classified:

- A softphone push relay on trusted cloud infrastructure is legitimate. Push relays register from the cloud on the app's behalf, so many devices share one datacenter IP and that's normal.
- A push user agent from any other datacenter is flagged as a spoofed user agent.
- A provider on the watchlist is flagged outright. A datacenter, a proxy or VPN, or a high-risk country is flagged too.
- An allowlisted org keeps its reasons, marked, and isn't flagged. Your own SBCs, carrier ranges and known travelers are never evaluated.

Liveness comes from the registration's expiry, not its mode field. The mode can be wrong both ways: a device that's actively re-registering can report as unregistered, and a long-dead one can still report as registered.

**Devices, not IPs** (`state.py`). The unit that matters is the device, because the fix is per device: change its SIP password. A device is cleared only when its password was reset during the current episode *and* it has stopped registering. If it stopped but was never reset, it stays open, because the attacker will be back. If it was reset but is still registering, the reset didn't take. A device that comes back after being cleared is a repeat offender, which means the leak is upstream of the phone.

**Calls** (`calls.py`). A short window of connected outbound calls is classified relative to the *caller's* state (from their caller ID, or a per-tenant override): in state, out of state, international, toll-free, internal. A tenant is flagged when its suspicious count beats both a floor and the count of a known, legitimate heavy caller, which acts as the baseline. For each flagged tenant, the calls are broken down by user. Any call that arrived from a bare IP address is checked against that user's registered addresses and against the IPs the registration scan flagged. On-net calls carry the domain there instead, so a bare IP means the call came from off the switch.

If a switch can't be read or an IP gets no geo answer, the scan says it's incomplete and lists the gaps. Missing data is never reported as clean.

## From finding to proposal

`bridge.py` turns findings into proposals and never acts on them. Each proposal names the exact first call to make, with `confirm=false`:

- `lock_users` for each compromised device's user, and for the users a flagged call pattern points at;
- `hang_up_call` for a live call by one of those users that's leaving the state or the country;
- `lock_domain` only when one tenant has more compromised users than a user lock can sensibly cover.

## Containment

Every write goes through the same three steps (`contain/flow.py`):

1. `confirm=false` changes nothing. It shows each target's current value and what it would become, plus a question for the model to ask the person, word for word.
2. After the person says yes, `confirm=true` with no passcode sends a six-digit code to *them*, at the address in their access token.
3. The person types the code, and the model passes it on. Only now does anything change: write, read back, record in the ledger, report.

A code works once, expires in ten minutes, allows three wrong guesses, and is bound to the exact request: who, which action, which domain, which users, which switches. A code issued to lock extension 102 won't lock 103, or 102 on a different switch, or the whole tenant.

**Read back, not trust** (`contain/actions.py`). Every write is read back from the switch, with retries, because some switches lag after a write. A write the switch accepted but didn't keep is reported as a failure. A failed switch read is reported as unknown, never as "not found". A wall-clock budget can stop a long batch, and anything it didn't reach comes back as NOT ATTEMPTED.

**Undo from a ledger** (`contain/ledger.py`). Every action is appended in order to one JSON-lines file: who did it, how they came in, and each value before and after. Undo reads only from the ledger:

- A restore writes back the permission the ledger recorded before the lock, so nobody can type "allow everything" into an undo.
- A repeat lock keeps the first recorded value, which is the pre-incident one.
- A user someone changed by hand since the lock is skipped and reported, not overwritten.
- An unlock only reopens a tenant this tool locked. In production, hundreds of tenants were already locked for other reasons, such as cancellation, migration or non-payment, and none of those may be reopened from here.

**Who may do what** (`contain/policy.py`). Locking users, restoring them, unlocking a tenant and hanging up a call are open to an allowlist, or to anyone arriving through a trusted team gateway, whose own group membership is that team's access list. Locking a whole tenant has its own allowlist and is refused through any gateway. That way a gateway profile that lists the tool by mistake still can't run it. With no readable identity, a caller can read findings and change nothing.

**Two switches.** A tenant in the middle of a migration exists on the old switch and the new one. Containment checks every configured switch unless told otherwise, and locks every copy it finds.

## Run it

```
python -m pytest
python example/demo.py
python -m tollguard.mcp_server --demo
```

The detection and containment code is stdlib only (Python 3.10 or later). The tests need pytest, and the MCP server needs fastmcp (`requirements.txt` pins both). The demo runs offline in about a second against `example/world.py`. That's two in-memory switches with one incident: a device registering from a watchlisted datacenter, nine international calls from the same IP, and one of them still live.

The demo then runs the whole flow:

1. Detect and propose.
2. Lock the user. A planted code from ticket text is refused, a wrong code is refused, and the right one locks both copies.
3. Hang up the live call.
4. Mark the device resolved after its password is reset.
5. Restore the user from the ledger.
6. Show three refusals.

## What's tested, and what isn't

The 77 tests and the demo run against `FakePbx`, an in-memory switch that can lag on reads, drop writes or stop answering. There's no adapter for a real switch in this repo. The production version runs against a hosted PBX's API, and an adapter here would implement the eight methods of `Pbx` in `pbx.py`.

The ip-api.com geo adapter is tested with a stubbed transport. The MCP server is boot-tested in process, but it doesn't configure authentication: put it behind your OAuth resource server and it reads identity from the token. `config.example.json` uses documentation IP ranges and ISO's user-assigned country codes (XA to XC), so no real allowlist or country list ships with the repo. Bring your own.

## Files

| Path | What it does |
|---|---|
| `tollguard/registrations.py` | source IP grouping, liveness, classification and scores |
| `tollguard/state.py` | flagged IPs and per-device compromise episodes across scans |
| `tollguard/calls.py` | caller-relative call classification and tenant flags |
| `tollguard/bridge.py` | findings to proposals; never acts |
| `tollguard/watch.py` | one detection pass over every switch |
| `tollguard/contain/` | flow, codes, ledger, policy, plan/apply/read-back |
| `tollguard/pbx.py` | the `Pbx` protocol and `FakePbx` |
| `tollguard/geo_ipapi.py` | optional geo lookup over ip-api.com |
| `tollguard/mcp_server.py` | the MCP tools |
| `example/` | the synthetic estate and the demo |

## License

MIT
