"""Валидация MTProto-ссылок и нейтральная классификация SNI-профиля.

Модуль намеренно не содержит «вечных белых списков»: правила операторов меняются,
а имя SNI само по себе не доказывает доступность адреса из сети пользователя.
"""

from __future__ import annotations

import logging
import re
from typing import Literal

from app.proxy.decoder import DecodedSecret, decode_secret
from app.proxy.harvester import RawProxy

logger = logging.getLogger(__name__)
ProxyCategory = Literal["RU", "EU"]

# Используется только для понятной группировки в интерфейсе, не как бонус к рангу.
RU_DOMAIN_SUFFIXES: frozenset[str] = frozenset({
    "ru", "рф", "su",
})

# Экспорт оставлен для обратной совместимости старых импортов.
BLACKLIST: frozenset[str] = frozenset()
RU_DOMAINS: frozenset[str] = frozenset()
PREFERRED_CDN: frozenset[str] = frozenset()


def _valid_domain(domain: str) -> bool:
    value = domain.strip().lower().rstrip(".")
    if not value or len(value) > 253 or ".." in value:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9-]+", label) is not None
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    )


def _domain_in_set(domain: str, domain_set: frozenset[str]) -> bool:
    value = domain.lower().strip().rstrip(".")
    return any(value == item or value.endswith("." + item) for item in domain_set)


def is_preferred_cdn(domain: str) -> bool:
    """Устаревший API: статическое имя домена больше не считается доказательством."""
    return False


def classify_domain(domain: str) -> ProxyCategory | None:
    """Классифицирует только доменную зону для UI; None означает неверный SNI."""
    if not domain:
        return "EU"
    value = domain.strip().lower().rstrip(".")
    if not _valid_domain(value):
        return None
    try:
        unicode_tld = value.rsplit(".", 1)[-1].encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        unicode_tld = value.rsplit(".", 1)[-1]
    return "RU" if unicode_tld in RU_DOMAIN_SUFFIXES else "EU"


def filter_proxy(proxy: RawProxy) -> tuple[RawProxy, DecodedSecret, ProxyCategory] | None:
    if proxy.kind != "mtproto" or not proxy.secret:
        return None
    decoded = decode_secret(proxy.secret)
    if not decoded.is_valid:
        logger.debug("filter: неверный секрет для %s:%s", proxy.host, proxy.port)
        return None
    category = classify_domain(decoded.sni_domain)
    if category is None:
        logger.debug("filter: неверный SNI %r", decoded.sni_domain)
        return None
    return proxy, decoded, category


def filter_proxies(
    proxies: list[RawProxy],
) -> list[tuple[RawProxy, DecodedSecret, ProxyCategory]]:
    result = [outcome for proxy in proxies if (outcome := filter_proxy(proxy)) is not None]
    ru_count = sum(1 for _, _, category in result if category == "RU")
    logger.info(
        "filter_proxies: всего=%d | валидных=%d | RU-профиль=%d | прочие=%d",
        len(proxies), len(result), ru_count, len(result) - ru_count,
    )
    return result
