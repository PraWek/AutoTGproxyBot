"""Персональное ранжирование прокси по безопасному техническому профилю клиента."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Mapping

from app.proxy.catalog import secret_type


_EFFECTIVE_TYPES = {"slow-2g", "2g", "3g", "4g", "unknown"}
_NETWORK_TYPES = {"cellular", "wifi", "ethernet", "unknown"}
_DEVICE_TYPES = {"mobile", "tablet", "desktop", "unknown"}


@dataclass(frozen=True, slots=True)
class ClientProfile:
    """Нечувствительные характеристики соединения без содержимого трафика."""

    device: str = "unknown"
    network: str = "unknown"
    effective_type: str = "unknown"
    rtt_ms: int = 0
    downlink_mbps: float = 0.0
    save_data: bool = False
    platform: str = "unknown"

    @property
    def is_constrained(self) -> bool:
        return (
            self.save_data
            or self.effective_type in {"slow-2g", "2g", "3g"}
            or self.rtt_ms >= 250
            or (0 < self.downlink_mbps < 2.0)
        )

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "network": self.network,
            "effective_type": self.effective_type,
            "rtt_ms": self.rtt_ms,
            "downlink_mbps": self.downlink_mbps,
            "save_data": self.save_data,
            "platform": self.platform,
        }

    def summary(self) -> str:
        device = {
            "mobile": "телефон",
            "tablet": "планшет",
            "desktop": "компьютер",
        }.get(self.device, "устройство")
        network = {
            "cellular": "мобильная сеть",
            "wifi": "Wi-Fi",
            "ethernet": "кабельная сеть",
        }.get(self.network, "тип сети не определён")
        quality = "экономный профиль" if self.is_constrained else "обычный профиль"
        return f"{device}, {network}, {quality}"


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(float(value or 0))))
    except (TypeError, ValueError):
        return 0


def _bounded_float(value: object, minimum: float, maximum: float) -> float:
    try:
        return max(minimum, min(maximum, float(value or 0)))
    except (TypeError, ValueError):
        return 0.0


def normalize_client_profile(raw: Mapping[str, object] | None) -> ClientProfile:
    data = raw or {}
    device = str(data.get("device", "unknown")).lower()
    network = str(data.get("network", "unknown")).lower()
    effective_type = str(data.get("effective_type", "unknown")).lower()
    platform = str(data.get("platform", "unknown")).lower()[:32]
    return ClientProfile(
        device=device if device in _DEVICE_TYPES else "unknown",
        network=network if network in _NETWORK_TYPES else "unknown",
        effective_type=effective_type if effective_type in _EFFECTIVE_TYPES else "unknown",
        rtt_ms=_bounded_int(data.get("rtt_ms"), 0, 5000),
        downlink_mbps=_bounded_float(data.get("downlink_mbps"), 0.0, 1000.0),
        save_data=bool(data.get("save_data", False)),
        platform=platform or "unknown",
    )


def _stable_jitter(user_id: int | None, proxy_id: str) -> float:
    """Небольшая стабильная развязка ничьих, персональная для пользователя."""
    seed = f"{user_id or 0}:{proxy_id}".encode("utf-8", errors="ignore")
    return int.from_bytes(hashlib.blake2s(seed, digest_size=2).digest(), "big") / 65535


def personalize_proxies(
    proxies: Iterable[dict],
    profile: ClientProfile,
    *,
    user_id: int | None = None,
) -> list[dict]:
    """Возвращает копии кандидатов в порядке соответствия профилю клиента."""
    ranked: list[tuple[float, dict]] = []
    for position, original in enumerate(proxies):
        proxy = dict(original)
        transport = int(proxy.get("transport_score", proxy.get("tspu_score", 0)) or 0)
        reachability = int(proxy.get("ru_reachability_score", 50) or 50)
        feedback_total = min(20, int(proxy.get("ru_feedback_total", 0) or 0))
        stability = int(proxy.get("stability", 0) or 0)
        ping = int(proxy.get("ping_ms", proxy.get("ping", 9999)) or 9999)
        sources = min(5, int(proxy.get("source_count", 1) or 1))
        kind = secret_type(str(proxy.get("secret", "")))

        score = (
            reachability * 0.42
            + transport * 0.30
            + stability * 0.14
            + feedback_total * 0.45
            + sources * 0.7
            - min(ping, 1200) * 0.018
            - position * 0.025
        )
        reasons: list[str] = []

        if proxy.get("admin_recommended"):
            score += 18
            reasons.append("рекомендован сервисом")
        if reachability >= 65:
            reasons.append("хорошие свежие отзывы")
        if stability >= 90:
            reasons.append("стабильный сервер")

        if profile.network == "cellular":
            score += reachability * 0.10
            if kind == "FakeTLS":
                score += 9
                reasons.append("подходит для мобильной сети")
            if ping <= 180:
                score += 4
        elif profile.network in {"wifi", "ethernet"}:
            score += transport * 0.05
            if ping <= 120:
                score += 5
                reasons.append("быстрый ответ сервера")

        if profile.device in {"mobile", "tablet"} and kind == "FakeTLS":
            score += 5
        if profile.device == "desktop" and kind in {"FakeTLS", "RandPad"}:
            score += 2

        if profile.is_constrained:
            score += stability * 0.08
            score -= min(ping, 1200) * 0.02
            if kind == "FakeTLS":
                score += 6
            reasons.append("учтена нестабильная или экономная сеть")

        score += _stable_jitter(user_id, str(proxy.get("id", "")))
        proxy["personal_score"] = round(score, 2)
        proxy["match_reasons"] = reasons[:3] or ["лучший баланс доступности и качества"]
        ranked.append((score, proxy))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [proxy for _, proxy in ranked]
