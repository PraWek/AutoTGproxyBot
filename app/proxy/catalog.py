"""Общий каталог, сортировка и защита от единичных ложных жалоб."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable


def secret_type(secret: str) -> str:
    value = (secret or "").lower()
    if value.startswith("ee"):
        return "FakeTLS"
    if value.startswith("dd"):
        return "RandPad"
    return "Plain"


@dataclass
class ProxyFeedback:
    """Жалоба скрывает адрес сразу для автора, но глобально — только по кворуму."""

    quorum: int = 3
    personal_ttl: int = 2 * 3600
    global_ttl: int = 30 * 60
    report_window: int = 20 * 60
    _personal: dict[tuple[int, str], float] = field(default_factory=dict)
    _votes: dict[str, dict[int, tuple[bool, float]]] = field(default_factory=lambda: defaultdict(dict))
    _global: dict[str, float] = field(default_factory=dict)

    def _purge(self, now: float) -> None:
        self._personal = {key: until for key, until in self._personal.items() if until > now}
        self._global = {pid: until for pid, until in self._global.items() if until > now}
        for pid, users in list(self._votes.items()):
            fresh = {uid: vote for uid, vote in users.items() if vote[1] + self.report_window > now}
            if fresh:
                self._votes[pid] = fresh
            else:
                self._votes.pop(pid, None)

    def _refresh_global(self, proxy_id: str, current: float) -> bool:
        votes = self._votes.get(proxy_id, {})
        failures = sum(1 for outcome, _ in votes.values() if not outcome)
        successes = sum(1 for outcome, _ in votes.values() if outcome)
        if failures - successes >= self.quorum:
            self._global[proxy_id] = current + self.global_ttl
            return True
        self._global.pop(proxy_id, None)
        return False

    def report_failure(self, proxy_id: str, user_id: int, *, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        self._purge(current)
        self._personal[(user_id, proxy_id)] = current + self.personal_ttl
        self._votes[proxy_id][user_id] = (False, current)
        return self._refresh_global(proxy_id, current)

    def report_success(self, proxy_id: str, user_id: int, *, now: float | None = None) -> None:
        current = now if now is not None else time.time()
        self._purge(current)
        self._personal.pop((user_id, proxy_id), None)
        self._votes[proxy_id][user_id] = (True, current)
        self._refresh_global(proxy_id, current)

    def is_blocked(self, proxy_id: str, user_id: int | None = None, *, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        self._purge(current)
        return (
            self._global.get(proxy_id, 0) > current
            or (user_id is not None and self._personal.get((user_id, proxy_id), 0) > current)
        )


feedback = ProxyFeedback()


def russian_reachability_score(successes: int, failures: int) -> int:
    """Байесовская оценка: малое число голосов не даёт экстремальных 0/100."""
    successes = max(0, int(successes))
    failures = max(0, int(failures))
    return round((successes + 2) / (successes + failures + 4) * 100)


def available_proxies(
    cache: Iterable[dict],
    automated_bans: dict[str, float],
    *,
    user_id: int | None = None,
    now: float | None = None,
) -> list[dict]:
    current = now if now is not None else time.time()
    return [
        proxy for proxy in cache
        if automated_bans.get(proxy.get("id", ""), 0) <= current
        and not feedback.is_blocked(proxy.get("id", ""), user_id, now=current)
    ]


def filter_proxies(
    proxies: Iterable[dict],
    *,
    region: str = "all",
    proxy_type: str = "all",
    sort_by: str = "recommended",
    limit: int = 10,
) -> list[dict]:
    result = list(proxies)
    if region in {"RU", "EU"}:
        result = [proxy for proxy in result if proxy.get("category", "EU") == region]
    if proxy_type in {"FakeTLS", "RandPad", "Plain"}:
        result = [proxy for proxy in result if secret_type(proxy.get("secret", "")) == proxy_type]

    if sort_by in {"recommended", "russia", "ru", "user_rating"}:
        result.sort(key=lambda proxy: (
            -int(bool(proxy.get("admin_recommended", False))),
            -int(proxy.get("ru_reachability_score", 50) or 0),
            -int(proxy.get("ru_feedback_total", 0) or 0),
            int(proxy.get("rank", 9999) or 9999),
        ))
    elif sort_by in {"quality", "transport", "tspu", "server_rating"}:
        result.sort(key=lambda proxy: (
            -int(bool(proxy.get("admin_recommended", False))),
            -int(proxy.get("transport_score", proxy.get("tspu_score", 0)) or 0),
        ))
    elif sort_by == "stability":
        result.sort(key=lambda proxy: (
            -int(bool(proxy.get("admin_recommended", False))),
            -int(proxy.get("stability", 0) or 0),
        ))
    else:
        result.sort(key=lambda proxy: (
            -int(bool(proxy.get("admin_recommended", False))),
            int(proxy.get("ping_ms", proxy.get("ping", 9999)) or 9999),
        ))
    return result[: max(1, min(limit, 300))]
