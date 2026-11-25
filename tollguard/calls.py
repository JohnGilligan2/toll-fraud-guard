"""The second detection surface: what is being dialed.

Attackers increasingly skip REGISTER entirely and send INVITEs straight at the
switch on stolen credentials. Those calls never appear in registration data,
only in call records. This module reads a short window of connected outbound
calls and flags tenants making an abnormal number of calls that leave the
CALLER's own state, or the country.

"Abnormal" is relative: a known, legitimate heavy caller (config
call_baseline_domain) sets the ceiling, and a floor stops a quiet hour from
flagging a tenant for six calls. A tenant is flagged when its count is above
max(baseline count, floor).

For each flagged tenant the calls are broken down by user and dialed number,
and the INVITE's source host is checked: on-net calls carry the domain there,
so a bare IP means the INVITE came from off the switch. That IP is compared
with the user's registered IPs and with the IPs the registration scan flagged.
Flag only: nothing here changes anything.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .config import Config
from .pbx import Cdr
from .registrations import is_infra

# NANP area code -> US state or territory (public numbering-plan data).
_STATE_AREAS = {
    "AL": "205 251 256 334 938", "AK": "907",
    "AZ": "480 520 602 623 928", "AR": "479 501 870",
    "CA": ("209 213 279 310 323 341 350 408 415 424 442 510 530 559 562 619 626 "
           "628 650 657 661 669 707 714 738 747 760 805 818 820 831 840 858 909 "
           "916 925 949 951"),
    "CO": "303 719 720 970 983", "CT": "203 475 860 959", "DE": "302", "DC": "202",
    "FL": ("239 305 321 352 386 407 448 561 645 656 689 727 754 772 786 813 850 "
           "904 941 954"),
    "GA": "229 404 470 478 678 706 762 770 912 943", "HI": "808", "ID": "208 986",
    "IL": "217 224 309 312 331 447 464 618 630 708 730 773 779 815 847 861 872",
    "IN": "219 260 317 463 574 765 812 930", "IA": "319 515 563 641 712",
    "KS": "316 620 785 913", "KY": "270 364 502 606 859",
    "LA": "225 318 337 504 985", "ME": "207",
    "MD": "227 240 301 410 443 667", "MA": "339 351 413 508 617 774 781 857 978",
    "MI": "231 248 269 313 517 586 616 679 734 810 906 947 989",
    "MN": "218 320 507 612 651 763 924 952", "MS": "228 601 662 769",
    "MO": "314 417 557 573 636 660 816 975", "MT": "406",
    "NE": "308 402 531", "NV": "702 725 775", "NH": "603",
    "NJ": "201 551 609 640 732 848 856 862 908 973",
    "NM": "505 575", "NY": ("212 315 332 347 363 516 518 585 607 631 646 680 716 "
                            "718 838 845 914 917 929 934"),
    "NC": "252 336 472 704 743 828 910 919 980 984", "ND": "701",
    "OH": "216 220 234 283 326 330 380 419 436 440 513 567 614 740 937",
    "OK": "405 539 572 580 918", "OR": "458 503 541 971",
    "PA": "215 223 267 272 412 445 484 570 582 610 717 724 814 835 878",
    "RI": "401", "SC": "803 821 839 843 854 864", "SD": "605",
    "TN": "423 615 629 731 865 901 931",
    "TX": ("210 214 254 281 325 346 361 409 430 432 469 512 682 713 726 737 806 "
           "817 830 832 903 915 936 940 945 956 972 979"),
    "UT": "385 435 801", "VT": "802",
    "VA": "276 434 540 571 686 703 757 804 826 948",
    "WA": "206 253 360 425 509 564", "WV": "304 681",
    "WI": "262 274 353 414 534 608 715 920", "WY": "307",
    "PR": "787 939", "VI": "340", "GU": "671", "AS": "684", "MP": "670",
}
STATE_BY_AREA = {a: st for st, areas in _STATE_AREAS.items() for a in areas.split()}
TOLLFREE = {"800", "888", "877", "866", "855", "844", "833", "822"}


def _digits(raw: str) -> tuple[str, bool]:
    s = str(raw or "").strip()
    return "".join(c for c in s if c.isdigit()), s.startswith("+")


def us_area_code(number: str) -> str | None:
    d, plus = _digits(number)
    if not d or d.startswith("011") or (plus and not d.startswith("1")):
        return None
    if len(d) == 11 and d.startswith("1"):
        return d[1:4]
    if len(d) == 10:
        return d[:3]
    return None


def area_state(area: str | None) -> str | None:
    return STATE_BY_AREA.get((area or "").strip())


def caller_home_state(caller_id: str, override: str | None, default: str) -> str:
    """The tenant override, else the caller ID's state, else the default."""
    if override:
        return override.upper()
    return area_state(us_area_code(caller_id)) or default.upper()


def classify_call(dialed: str, home_state: str) -> str:
    """in_state | out_of_state | intl | tollfree | internal | unknown.
    Only out_of_state and intl are suspicious."""
    d, plus = _digits(dialed)
    if not d:
        return "internal"
    if d.startswith("011") or (plus and not d.startswith("1")):
        return "intl"
    if len(d) <= 6:
        return "internal"                  # extension, feature code, short code
    area = us_area_code(dialed)
    if area is None:
        return "intl" if len(d) >= 11 else "unknown"
    if area in TOLLFREE:
        return "tollfree"
    st = area_state(area)
    if st is None:
        return "unknown"
    return "in_state" if st == home_state.upper() else "out_of_state"


def _ipv4(host: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return None


@dataclass
class UserCalls:
    user: str
    calls: int = 0
    numbers: list[dict] = field(default_factory=list)
    source_ips: set[str] = field(default_factory=set)
    registered_ips: set[str] = field(default_factory=set)

    @property
    def off_switch(self) -> bool:
        """An INVITE from a bare IP that is not one of this user's registrations."""
        return any(ip not in self.registered_ips for ip in self.source_ips)


@dataclass
class DomainFlag:
    domain: str
    count: int = 0
    intl: int = 0
    out_of_state: int = 0
    users: dict[str, UserCalls] = field(default_factory=dict)
    linked_fraud_ips: set[str] = field(default_factory=set)

    @property
    def callers(self) -> list[str]:
        return sorted((u for u in self.users if u and u != "(unknown)"),
                      key=lambda u: -self.users[u].calls)


@dataclass
class CallScan:
    analysed: int
    skipped_inbound: int
    baseline_count: int
    threshold: int
    flagged: list[DomainFlag]


def scan_calls(cdrs: Iterable[Cdr], cfg: Config,
               registered_ips: dict[tuple[str, str], set[str]] | None = None,
               fraud_ips: set[str] | None = None) -> CallScan:
    registered_ips = registered_ips or {}
    fraud_ips = fraud_ips or set()
    suspicious = {"out_of_state"} | ({"intl"} if cfg.call_include_international else set())
    baseline = cfg.call_baseline_domain.lower()
    per: dict[str, DomainFlag] = {}
    analysed = skipped = baseline_count = 0
    for c in cdrs:
        if c.talk_seconds <= 0:
            continue                                  # connected calls only
        src = _ipv4(c.source_host)
        if src and is_infra(src, cfg):
            skipped += 1                              # inbound from our own carriers
            continue
        analysed += 1
        dom = c.domain.lower()
        if not dom:
            continue
        home = caller_home_state(c.caller_id, cfg.call_home_state_by_domain.get(dom),
                                 cfg.call_default_home_state)
        cls = classify_call(c.dialed, home)
        if cls not in suspicious:
            continue
        if dom == baseline:
            baseline_count += 1
            continue
        f = per.setdefault(dom, DomainFlag(dom))
        f.count += 1
        f.intl += cls == "intl"
        f.out_of_state += cls == "out_of_state"
        u = f.users.setdefault(c.calling_user or "(unknown)", UserCalls(c.calling_user or "(unknown)"))
        u.calls += 1
        u.numbers.append({"dialed": c.dialed, "class": cls, "home_state": home,
                          "talk_seconds": c.talk_seconds, "source_ip": src})
        if src:
            u.source_ips.add(src)
            if src in fraud_ips:
                f.linked_fraud_ips.add(src)
    threshold = max(baseline_count, cfg.call_flag_floor)
    flagged = sorted((f for d, f in per.items()
                      if f.count > threshold and d not in cfg.call_exclude_domains),
                     key=lambda f: -f.count)
    for f in flagged:
        for name, u in f.users.items():
            u.registered_ips = set(registered_ips.get((f.domain, name), set()))
    return CallScan(analysed, skipped, baseline_count, threshold, flagged)
