"""Асинхронный конвейер прокси: источники → разбор → проверка → ранжирование.

Оценка здесь является наблюдаемой оценкой транспорта, а не обещанием обхода:
проверка выполняется из сети сервера и не может воспроизвести правила конкретного
оператора связи пользователя.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from app.proxy.decoder import DecodedSecret, decode_secret, describe_secret
from app.proxy.catalog import russian_reachability_score
from app.proxy.filter import ProxyCategory, filter_proxies
from app.proxy.harvester import RawProxy, harvest, harvest_channels
from app.proxy.sources import get_channels, get_source_urls

logger = logging.getLogger(__name__)


def _proxy_id(host: str, port: int) -> str:
    # Сохраняем формат существующей схемы БД и callback-кнопок.
    return hashlib.md5(f"{host}:{port}".encode()).hexdigest()[:8]


def _source_identity(source_url: str) -> str:
    value = (source_url or "unknown").removesuffix("[b64]")
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
    return value


def _env_number(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


TCP_TIMEOUT = _env_number("PROXY_TCP_TIMEOUT", 3.5, 1.0, 15.0)
CHECK_ROUNDS = int(_env_number("PROXY_CHECK_ROUNDS", 3, 2, 5))
SEM_LIMIT = int(_env_number("PROXY_CHECK_CONCURRENCY", 120, 10, 500))
CACHE_SIZE = int(_env_number("PROXY_CACHE_SIZE", 300, 10, 1000))
WORKER_INTERVAL = int(_env_number("PROXY_UPDATE_INTERVAL", 180, 60, 3600))
MIN_TRANSPORT_SCORE = int(_env_number("PROXY_MIN_SCORE", 35, 0, 100))
TLS_COVER_TIMEOUT = _env_number("PROXY_TLS_TIMEOUT", 5.0, 1.0, 15.0)


@dataclass(slots=True)
class CheckedProxy:
    id: str
    host: str
    port: int
    secret: str
    kind: str
    generation: str
    sni_domain: str
    category: ProxyCategory
    ping_ms: int
    transport_score: int
    stability: int
    rank: int
    is_alive: bool
    checked_at: datetime
    probe_state: str
    source_count: int = 1
    ru_successes: int = 0
    ru_failures: int = 0
    ru_reachability_score: int = 50
    admin_recommended: bool = False
    admin_recommended_at: Any | None = None

    @property
    def tspu_score(self) -> int:
        """Совместимость со старой схемой БД/API."""
        return self.transport_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host": self.host,
            "server": self.host,
            "port": self.port,
            "secret": self.secret,
            "kind": self.kind,
            "generation": self.generation,
            "sni_domain": self.sni_domain,
            "category": self.category,
            "ping_ms": self.ping_ms,
            "ping": self.ping_ms,
            "transport_score": self.transport_score,
            "tspu_score": self.transport_score,
            "tspu": self.transport_score,
            "stability": self.stability,
            "rank": self.rank,
            "is_alive": self.is_alive,
            "checked_at": self.checked_at,
            "probe_state": self.probe_state,
            "source_count": self.source_count,
            "ru_successes": self.ru_successes,
            "ru_failures": self.ru_failures,
            "ru_feedback_total": self.ru_successes + self.ru_failures,
            "ru_reachability_score": self.ru_reachability_score,
            "admin_recommended": self.admin_recommended,
            "admin_recommended_at": self.admin_recommended_at,
        }


def calculate_transport_score(
    decoded: DecodedSecret,
    port: int,
    probe_state: str = "tcp_only",
    source_count: int = 1,
) -> int:
    """Оценивает только наблюдаемые свойства ссылки и контрольного соединения."""
    base = {
        "faketls": 68,
        "randpad": 46,
        "plain": 18,
        "unknown": 10,
    }.get(decoded.generation, 10)

    if decoded.generation == "faketls" and decoded.sni_domain:
        base += 7
    if port == 443:
        base += 6
    elif port in {80, 8080, 8443}:
        base += 2

    base += {
        "tls_verified": 15,
        "tls_unverified": 3,
        "tls_rejected": -8,
        "tls_timeout": -10,
        "tcp_only": 0,
    }.get(probe_state, -4)
    base += min(max(source_count - 1, 0) * 2, 6)
    return max(0, min(100, base))


async def _tcp_ping(host: str, port: int) -> tuple[bool, float]:
    started = time.monotonic()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        return True, (time.monotonic() - started) * 1000
    except (asyncio.TimeoutError, OSError):
        return False, 0.0
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (asyncio.TimeoutError, OSError):
                pass


async def _probe_tls_cover(host: str, port: int, sni_domain: str) -> str:
    """Проверяет публичную TLS-маску FakeTLS без попытки выдать её за MTProto-тест."""
    if not sni_domain:
        return "tls_rejected"
    writer = None
    try:
        context = ssl.create_default_context()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=sni_domain),
            timeout=TLS_COVER_TIMEOUT,
        )
        return "tls_verified"
    except ssl.SSLCertVerificationError:
        return "tls_unverified"
    except asyncio.TimeoutError:
        return "tls_timeout"
    except (ssl.SSLError, OSError):
        return "tls_rejected"
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (asyncio.TimeoutError, OSError):
                pass


async def _check_one(
    raw: RawProxy,
    decoded: DecodedSecret,
    category: ProxyCategory,
    source_count: int,
    sem: asyncio.Semaphore,
) -> CheckedProxy | None:
    async with sem:
        samples: list[float] = []
        for round_index in range(CHECK_ROUNDS):
            ok, elapsed = await _tcp_ping(raw.host, raw.port)
            if ok:
                samples.append(elapsed)
            if round_index + 1 < CHECK_ROUNDS:
                await asyncio.sleep(0.1)

        if not samples:
            return None

        success_ratio = len(samples) / CHECK_ROUNDS
        jitter = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        stability = round(max(0.0, min(100.0, success_ratio * 100 - min(jitter / 3, 20))))
        ping_ms = round(statistics.median(samples))

        probe_state = "tcp_only"
        if decoded.generation == "faketls":
            probe_state = await _probe_tls_cover(raw.host, raw.port, decoded.sni_domain)

        score = calculate_transport_score(decoded, raw.port, probe_state, source_count)
        # Меньше — лучше. Нет искусственного бонуса по стране/SNI: это не измерение сети пользователя.
        # Отклик Орегон → proxy — слабый диагностический фактор, не прогноз для РФ.
        rank = min(ping_ms, 500) // 5 + (100 - score) * 6 + (100 - stability) * 3
        proxy_id = _proxy_id(raw.host, raw.port)
        return CheckedProxy(
            id=proxy_id,
            host=raw.host,
            port=raw.port,
            secret=raw.secret,
            kind=raw.kind,
            generation=decoded.generation,
            sni_domain=decoded.sni_domain,
            category=category,
            ping_ms=ping_ms,
            transport_score=score,
            stability=stability,
            rank=rank,
            is_alive=True,
            checked_at=datetime.now(tz=timezone.utc),
            probe_state=probe_state,
            source_count=source_count,
        )


async def run_pipeline(*, extra_urls: list[str] | None = None, repo: Any | None = None) -> list[CheckedProxy]:
    channels = get_channels()
    source_urls = extra_urls if extra_urls is not None else get_source_urls()
    logger.info("pipeline: сбор из %d каналов и %d web-источников", len(channels), len(source_urls))

    channel_task = asyncio.create_task(
        harvest_channels(channels, pages=6, concurrency=min(20, len(channels) or 1), timeout_sec=20.0)
    )
    web_task = asyncio.create_task(harvest(source_urls, concurrency=30, timeout_sec=20.0))
    channel_proxies, web_proxies = await asyncio.gather(channel_task, web_task)

    unique: dict[tuple[str, int, str], RawProxy] = {}
    appearances: dict[tuple[str, int, str], set[str]] = {}
    for proxy in channel_proxies + web_proxies:
        key = (proxy.host, proxy.port, proxy.secret)
        unique.setdefault(key, proxy)
        appearances.setdefault(key, set()).add(_source_identity(proxy.source_url))

    raw_proxies = list(unique.values())
    logger.info("pipeline: получено %d уникальных ссылок", len(raw_proxies))
    filtered = filter_proxies(raw_proxies)
    if not filtered:
        logger.warning("pipeline: валидных MTProto-ссылок не найдено")
        return []

    sem = asyncio.Semaphore(SEM_LIMIT)
    tasks = []
    for raw, decoded, category in filtered:
        key = (raw.host, raw.port, raw.secret)
        tasks.append(asyncio.create_task(
            _check_one(raw, decoded, category, len(appearances.get(key, ())), sem)
        ))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive = [result for result in results if isinstance(result, CheckedProxy)]

    if repo is not None and alive:
        try:
            summaries = await repo.get_feedback_summaries([proxy.id for proxy in alive])
            for proxy in alive:
                summary = summaries.get(proxy.id, {})
                proxy.ru_successes = int(summary.get("successes", 0))
                proxy.ru_failures = int(summary.get("failures", 0))
                proxy.ru_reachability_score = russian_reachability_score(
                    proxy.ru_successes, proxy.ru_failures
                )
                # Российская обратная связь доминирует над измерением из Орегона.
                proxy.rank += (50 - proxy.ru_reachability_score) * 10
        except Exception as exc:
            logger.warning("pipeline: не удалось загрузить отзывы из РФ: %s", exc)

        try:
            recommendations = await repo.get_admin_recommendations([proxy.id for proxy in alive])
            for proxy in alive:
                if proxy.id in recommendations:
                    proxy.admin_recommended = True
                    proxy.admin_recommended_at = recommendations[proxy.id]
        except Exception as exc:
            logger.warning("pipeline: не удалось загрузить рекомендации администратора: %s", exc)

    quality = [proxy for proxy in alive if proxy.transport_score >= MIN_TRANSPORT_SCORE]
    quality.sort(key=lambda proxy: (
        -int(proxy.admin_recommended),
        -proxy.ru_reachability_score,
        -(proxy.ru_successes + proxy.ru_failures),
        proxy.rank,
    ))
    top = quality[:CACHE_SIZE]

    logger.info(
        "pipeline: доступно %d/%d, порог качества прошли %d, в кэше %d",
        len(alive), len(filtered), len(quality), len(top),
    )
    if repo is not None:
        try:
            await repo.upsert_many([proxy.to_dict() for proxy in alive])
            alive_ids = {proxy.id for proxy in alive}
            dead_ids = [
                _proxy_id(raw.host, raw.port)
                for raw, _, _ in filtered
                if _proxy_id(raw.host, raw.port) not in alive_ids
            ]
            await repo.mark_dead(dead_ids)
        except Exception as exc:
            logger.error("pipeline: не удалось записать результат в БД: %s", exc)
    return top


CACHED_BEST_PROXIES: list[dict[str, Any]] = []
banned_proxies: dict[str, float] = {}
LAST_CYCLE_AT = 0.0
_force_update_event: asyncio.Event | None = None
_proxy_strikes: dict[str, int] = {}


async def load_initial_cache(repo: Any) -> None:
    global CACHED_BEST_PROXIES
    try:
        rows = await repo.get_best(limit=CACHE_SIZE)
        loaded: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.setdefault("server", item.get("host", ""))
            item.setdefault("ping", item.get("ping_ms", 0))
            item.setdefault("transport_score", item.get("tspu_score", 0))
            item.setdefault("tspu", item.get("transport_score", 0))
            item.setdefault("ru_successes", 0)
            item.setdefault("ru_failures", 0)
            item.setdefault("admin_recommended", False)
            item.setdefault("admin_recommended_at", None)
            item["ru_feedback_total"] = item["ru_successes"] + item["ru_failures"]
            item["ru_reachability_score"] = russian_reachability_score(
                item["ru_successes"], item["ru_failures"]
            )
            loaded.append(item)
        CACHED_BEST_PROXIES = loaded
        logger.info("pipeline: из БД загружено %d прокси", len(loaded))
    except Exception as exc:
        logger.error("pipeline: не удалось загрузить начальный кэш: %s", exc)


def request_pipeline_update() -> None:
    if _force_update_event is not None:
        _force_update_event.set()


async def proxy_updater_worker(repo: Any | None = None) -> None:
    global CACHED_BEST_PROXIES, LAST_CYCLE_AT, _force_update_event
    _force_update_event = asyncio.Event()
    cycle = 0
    while True:
        try:
            top = await run_pipeline(repo=repo)
            now = time.time()
            banned_proxies.update({})
            for proxy_id, until in list(banned_proxies.items()):
                if until <= now:
                    banned_proxies.pop(proxy_id, None)

            top_ids = {proxy.id for proxy in top}
            for proxy in top:
                _proxy_strikes.pop(proxy.id, None)
            for old in CACHED_BEST_PROXIES:
                proxy_id = old.get("id", "")
                if proxy_id and proxy_id not in top_ids:
                    strikes = _proxy_strikes.get(proxy_id, 0) + 1
                    _proxy_strikes[proxy_id] = strikes
                    if strikes >= 5:
                        banned_proxies[proxy_id] = now + 6 * 3600
                        _proxy_strikes.pop(proxy_id, None)

            if top:
                CACHED_BEST_PROXIES = [proxy.to_dict() for proxy in top]
            LAST_CYCLE_AT = now
            cycle += 1

            if repo is not None and cycle % 40 == 0:
                try:
                    await repo.purge_old_dead(days=3)
                    await repo.cap_proxies(3000)
                    await repo.purge_old_feedback(days=30)
                except Exception as exc:
                    logger.error("pipeline: ошибка обслуживания БД: %s", exc)

            if CACHED_BEST_PROXIES:
                best = CACHED_BEST_PROXIES[0]
                logger.info(
                    "pipeline: кэш=%d, топ=%s:%s, транспорт=%s, оценка=%s",
                    len(CACHED_BEST_PROXIES), best["host"], best["port"],
                    describe_secret(decode_secret(best["secret"])), best.get("transport_score", 0),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("pipeline worker: %s", exc, exc_info=True)

        try:
            await asyncio.wait_for(_force_update_event.wait(), timeout=WORKER_INTERVAL)
        except asyncio.TimeoutError:
            pass
        finally:
            _force_update_event.clear()
