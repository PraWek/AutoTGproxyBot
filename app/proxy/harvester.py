"""
proxy_harvester.py — Модуль сбора прокси.

Параллельно скачивает HTML/текст из списка URL и извлекает
прокси в форматах:
  1. tg://proxy?server=...&port=...&secret=...
  2. https://t.me/proxy?server=...&port=...&secret=...
  3. tg://socks?server=...&port=...&user=...&pass=...
  4. host:port:secret  (plain-text)
  5. base64-encoded MTProto links
"""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import logging
import os
import re
import json
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qs, unquote, urlsplit

import aiohttp
from aiohttp import ClientSession, TCPConnector

logger = logging.getLogger(__name__)

ProxyKind = Literal["mtproto", "socks5"]


@dataclass(frozen=True)
class RawProxy:
    host: str
    port: int
    secret: str
    username: str = ""
    password: str = ""
    kind: ProxyKind = "mtproto"
    source_url: str = ""


_RE_MTPROTO_LINK = re.compile(
    r"((?:tg://proxy|https?://t\.me/proxy)\?[^\"'\s<>]{10,})",
    re.IGNORECASE,
)
_RE_SOCKS_LINK = re.compile(
    r"(tg://socks\?[^\"'\s<>]{10,})",
    re.IGNORECASE,
)
_RE_SERVER = re.compile(r"(?:server|host)=([^&\"'\s<>]+)", re.IGNORECASE)
_RE_PORT   = re.compile(r"port=([0-9]{1,5})",              re.IGNORECASE)
_RE_SECRET = re.compile(r"secret=([0-9a-fA-Fde]{32,})",   re.IGNORECASE)
_RE_USER   = re.compile(r"user=([^&\"'\s<>]*)",            re.IGNORECASE)
_RE_PASS   = re.compile(r"pass=([^&\"'\s<>]*)",            re.IGNORECASE)

_RE_PLAIN_TRIPLET = re.compile(
    r"(?<![/\w])"
    r"((?:\d{1,3}\.){3}\d{1,3}|"
    r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)"
    r":([0-9]{1,5})"
    r":([0-9a-fA-Fde]{32,})",
    re.IGNORECASE,
)

_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

MAX_RESPONSE_BYTES = 3 * 1024 * 1024


def _normalize_html_entities(text: str) -> str:
    return html.unescape(text).replace("%26", "&")


def _normalize_host(raw: str) -> str | None:
    """Возвращает публичный IP/домен или None для локальных и неверных адресов."""
    value = unquote(raw).strip().strip("[]").rstrip(".").lower()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return None
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            return None
        return address.compressed
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return None
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return None
    return ascii_host


def _valid_secret(raw: str) -> str | None:
    value = unquote(raw).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32,512}", value):
        return None
    return value


def _parse_port(raw: str) -> int | None:
    try:
        p = int(raw)
        return p if 1 <= p <= 65535 else None
    except ValueError:
        return None


def _try_decode_base64_block(text: str) -> str:
    """
    Пробует декодировать каждую строку текста как base64.
    Возвращает конкатенацию всех успешно декодированных строк.
    """
    decoded_parts: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 20:
            continue
        for candidate in [line, line + "==", line + "="]:
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                raw = base64.urlsafe_b64decode(padded)
                decoded = raw.decode("utf-8", errors="replace")
                if "tg://proxy" in decoded or "t.me/proxy" in decoded:
                    decoded_parts.append(decoded)
                    break
            except Exception:
                pass
    return "\n".join(decoded_parts)


def _parse_structured_records(text: str, source_url: str) -> list[RawProxy]:
    """Извлекает записи из JSON и простых YAML-подобных блоков."""
    records: list[dict] = []
    try:
        value = json.loads(text)
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                records.append(item)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    except (json.JSONDecodeError, TypeError):
        # Многие публичные списки — невалидный JSON, но используют понятные
        # пары server/port/secret. Разбираем ограниченный локальный блок.
        block_re = re.compile(
            r"(?:server|host)\s*[:=]\s*['\"]?([^\s,'\"}]+)['\"]?.{0,160}?"
            r"port\s*[:=]\s*['\"]?(\d{1,5})['\"]?.{0,240}?"
            r"secret\s*[:=]\s*['\"]?([0-9a-fA-F]{32,512})",
            re.IGNORECASE | re.DOTALL,
        )
        for match in block_re.finditer(text):
            records.append({"server": match.group(1), "port": match.group(2), "secret": match.group(3)})

    result: list[RawProxy] = []
    for record in records:
        host = _normalize_host(str(record.get("server") or record.get("host") or ""))
        port = _parse_port(str(record.get("port") or ""))
        secret = _valid_secret(str(record.get("secret") or ""))
        if host and port is not None and secret:
            result.append(RawProxy(host=host, port=port, secret=secret, source_url=source_url))
    return result


def parse_raw_text(text: str, source_url: str = "") -> list[RawProxy]:
    """
    Основной парсер: принимает сырой HTML/текст, возвращает список RawProxy.

    Порядок:
      1. MTProto-ссылки (tg://proxy / t.me/proxy)
      2. SOCKS5-ссылки (tg://socks)
      3. Голые триплеты host:port:secret
      4. base64-блоки (если обнаружены)
    """
    text = _normalize_html_entities(text)
    result: list[RawProxy] = []
    seen: set[tuple[str, str, int, str, str, str]] = set()

    def _add(proxy: RawProxy) -> None:
        key = (proxy.kind, proxy.host, proxy.port, proxy.secret, proxy.username, proxy.password)
        if key not in seen:
            seen.add(key)
            result.append(proxy)

    def _parse_mtproto_link(link: str, src: str) -> None:
        link = link.rstrip(".,;)]}")
        query = parse_qs(urlsplit(link).query, keep_blank_values=True)
        host = _normalize_host((query.get("server") or query.get("host") or [""])[0])
        port = _parse_port((query.get("port") or [""])[0])
        secret = _valid_secret((query.get("secret") or [""])[0])
        if not host or port is None or not secret:
            return
        _add(RawProxy(
            host=host,
            port=port,
            secret=secret,
            kind="mtproto",
            source_url=src,
        ))

    def _parse_socks_link(link: str, src: str) -> None:
        link = link.rstrip(".,;)]}")
        query = parse_qs(urlsplit(link).query, keep_blank_values=True)
        host = _normalize_host((query.get("server") or query.get("host") or [""])[0])
        port = _parse_port((query.get("port") or [""])[0])
        if not host or port is None:
            return
        _add(RawProxy(
            host=host,
            port=port,
            secret="",
            username=(query.get("user") or [""])[0],
            password=(query.get("pass") or [""])[0],
            kind="socks5",
            source_url=src,
        ))

    for m in _RE_MTPROTO_LINK.finditer(text):
        _parse_mtproto_link(m.group(1), source_url)

    for m in _RE_SOCKS_LINK.finditer(text):
        _parse_socks_link(m.group(1), source_url)

    for m in _RE_PLAIN_TRIPLET.finditer(text):
        port = _parse_port(m.group(2))
        if port is None:
            continue
        host = _normalize_host(m.group(1))
        secret = _valid_secret(m.group(3))
        if not host or not secret:
            continue
        _add(RawProxy(
            host=host,
            port=port,
            secret=secret,
            kind="mtproto",
            source_url=source_url,
        ))

    for proxy in _parse_structured_records(text, source_url):
        _add(proxy)

    extra = _try_decode_base64_block(text)
    if extra:
        for m in _RE_MTPROTO_LINK.finditer(extra):
            _parse_mtproto_link(m.group(1), source_url + "[b64]")

    logger.debug("parse_raw_text: %d прокси из %s", len(result), source_url)
    return result


def _get_fetch_proxy() -> str | None:
    """
    Возвращает URL прокси для HTTP-запросов харвестера.
    Поддерживает HTTP/HTTPS-прокси, которые нативно понимает aiohttp.
    Задаётся через переменную окружения FETCH_PROXY.
    """
    value = os.getenv("FETCH_PROXY", "").strip()
    if not value:
        return None
    if urlsplit(value).scheme not in {"http", "https"}:
        logger.warning("FETCH_PROXY пропущен: поддерживаются только http:// и https://")
        return None
    return value


async def _fetch_one(
    session: ClientSession,
    url: str,
    timeout_sec: float = 20.0,
    fetch_proxy: str | None = None,
) -> list[RawProxy]:
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    verify_ssl = os.getenv("FETCH_INSECURE_SSL", "0").strip().lower() not in {"1", "true", "yes"}
    kwargs: dict = {"headers": _HEADERS, "timeout": timeout, "ssl": verify_ssl}
    if fetch_proxy:
        kwargs["proxy"] = fetch_proxy
    try:
        async with session.get(url, **kwargs) as resp:
            if resp.status not in (200, 206):
                logger.debug("fetch %s → HTTP %s", url, resp.status)
                return []
            content_length = resp.content_length
            if content_length is not None and content_length > MAX_RESPONSE_BYTES:
                logger.warning("fetch %s пропущен: размер %d байт", url, content_length)
                return []
            body = await resp.content.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                logger.warning("fetch %s пропущен: ответ больше %d байт", url, MAX_RESPONSE_BYTES)
                return []
            charset = resp.charset or "utf-8"
            proxies = parse_raw_text(body.decode(charset, errors="replace"), source_url=url)
            logger.debug("fetch %s → %d прокси", url, len(proxies))
            return proxies
    except Exception as exc:
        logger.debug("fetch %s error: %s", url, exc)
        return []


async def harvest(
    urls: list[str],
    *,
    concurrency: int = 30,
    timeout_sec: float = 20.0,
) -> list[RawProxy]:
    """
    Параллельно скачивает все URL и агрегирует уникальные прокси.
    Если задан FETCH_PROXY — все запросы идут через него (обход блокировок).
    """
    sem = asyncio.Semaphore(concurrency)
    connector = TCPConnector(limit=concurrency, ttl_dns_cache=300)
    fetch_proxy = _get_fetch_proxy()
    if fetch_proxy:
        logger.info("harvest: используем FETCH_PROXY=%s", fetch_proxy.split("@")[-1])

    async def _guarded(url: str) -> list[RawProxy]:
        async with sem:
            return await _fetch_one(session, url, timeout_sec, fetch_proxy=fetch_proxy)

    async with ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(_guarded(url)) for url in urls]
        batches = await asyncio.gather(*tasks, return_exceptions=True)

    seen: set[tuple[str, int, str]] = set()
    result: list[RawProxy] = []
    for batch in batches:
        if not isinstance(batch, list):
            continue
        for p in batch:
            key = (p.host, p.port, p.secret)
            if key not in seen:
                seen.add(key)
                result.append(p)

    logger.info("harvest: итого уникальных прокси = %d из %d источников", len(result), len(urls))
    return result


_RE_DATA_BEFORE = re.compile(r'data-before=["\'](\d+)["\']', re.IGNORECASE)


def _extract_next_before(html: str) -> int | None:
    """Извлекает data-before из кнопки 'загрузить ещё' TG. None = конец истории."""
    m = _RE_DATA_BEFORE.search(html)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


async def _fetch_channel_paginated(
    session: ClientSession,
    channel: str,
    pages: int = 6,
    timeout_sec: float = 20.0,
    fetch_proxy: str | None = None,
) -> list[RawProxy]:
    """
    Скачивает несколько страниц TG-канала, следя за data-before.
    Страница 1 — самые свежие посты; каждая следующая — глубже в историю.
    """
    all_proxies: list[RawProxy] = []
    seen: set[tuple[str, int, str]] = set()
    url = f"https://t.me/s/{channel}"

    for page_num in range(pages):
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        verify_ssl = os.getenv("FETCH_INSECURE_SSL", "0").strip().lower() not in {"1", "true", "yes"}
        kwargs: dict = {"headers": _HEADERS, "timeout": timeout, "ssl": verify_ssl}
        if fetch_proxy:
            kwargs["proxy"] = fetch_proxy
        try:
            async with session.get(url, **kwargs) as resp:
                if resp.status not in (200, 206):
                    break
                body = await resp.content.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    logger.warning("channel %s page %d пропущен: слишком большой ответ", channel, page_num)
                    break
                html = body.decode(resp.charset or "utf-8", errors="replace")
        except Exception as exc:
            logger.debug("fetch_channel_paginated %s page %d error: %s", channel, page_num, exc)
            break

        proxies = parse_raw_text(html, source_url=url)
        for p in proxies:
            key = (p.host, p.port, p.secret)
            if key not in seen:
                seen.add(key)
                all_proxies.append(p)

        if page_num >= pages - 1:
            break
        next_before = _extract_next_before(html)
        if next_before is None:
            break
        url = f"https://t.me/s/{channel}?before={next_before}"
        logger.debug("fetch_channel_paginated %s page %d before=%d", channel, page_num + 1, next_before)

    return all_proxies


async def harvest_channels(
    channels: list[str],
    *,
    pages: int = 6,
    concurrency: int = 20,
    timeout_sec: float = 20.0,
) -> list[RawProxy]:
    """
    Параллельно скачивает несколько страниц каждого TG-канала
    с умной пагинацией по data-before.
    """
    sem = asyncio.Semaphore(concurrency)
    connector = TCPConnector(limit=concurrency, ttl_dns_cache=300)
    fetch_proxy = _get_fetch_proxy()

    async def _guarded(channel: str) -> list[RawProxy]:
        async with sem:
            return await _fetch_channel_paginated(
                session, channel, pages=pages,
                timeout_sec=timeout_sec, fetch_proxy=fetch_proxy,
            )

    async with ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(_guarded(ch)) for ch in channels]
        batches = await asyncio.gather(*tasks, return_exceptions=True)

    seen: set[tuple[str, int, str]] = set()
    result: list[RawProxy] = []
    for batch in batches:
        if not isinstance(batch, list):
            continue
        for p in batch:
            key = (p.host, p.port, p.secret)
            if key not in seen:
                seen.add(key)
                result.append(p)

    logger.info(
        "harvest_channels: %d каналов × до %d стр. → %d уникальных прокси",
        len(channels), pages, len(result),
    )
    return result


def channel_urls(channels: list[str], pages: int = 6) -> list[str]:
    """Устаревший вариант — возвращает базовые URL каналов (1 страница)."""
    return [f"https://t.me/s/{ch}" for ch in channels]
