"""
web_routes.py — API-маршруты веб-сервера.

Публичные:
  GET  /                      — главная страница (SPA)
  GET  /logout                — выход
  GET  /api/config            — публичный конфиг (bot_username)
  POST /api/auth/login        — вход (логин = username Telegram)
  POST /api/auth/register     — заглушка: аккаунт создаётся только ботом

Приватные (требуют cookie-сессию):
  GET  /api/me                — профиль + статус бесплатного доступа
  GET  /api/proxies           — топ-10 прокси
  POST /api/proxies/find-best — персональный подбор одного прокси

Webhook:
  POST /tg-webhook/<token>    — апдейты от Telegram (prod-режим)
"""
from __future__ import annotations

import json
import hmac
import logging
import re
import time
from pathlib import Path

# Версия статических файлов — меняется при каждом запуске сервера,
# гарантирует сброс браузерного кеша после деплоя.
_STATIC_VER = str(int(time.time()))

from aiohttp import web

from app.proxy import pipeline as worker
from app.core.auth import (
    clear_session_cookie,
    get_uid_from_request,
    set_session_cookie,
)
from app.proxy.catalog import (
    available_proxies,
    feedback,
    filter_proxies as catalog_filter_proxies,
    secret_type,
)
from app.proxy.selector import select_first_reachable
from app.proxy.personalization import normalize_client_profile, personalize_proxies

logger = logging.getLogger(__name__)
PROJECT_DIR = Path(__file__).resolve().parents[2]

# Допустимый формат логина
_LOGIN_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')


# ──────────────────────────────────────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────────────────────────────────────

def _secret_type(secret: str) -> str:
    return secret_type(secret)


def _available_proxies(user_id: int | None = None) -> list[dict]:
    """Все незабаненные прокси из кэша."""
    return available_proxies(
        worker.CACHED_BEST_PROXIES,
        worker.banned_proxies,
        user_id=user_id,
    )


def _get_proxies_filtered(
    region: str = "all",
    proxy_type: str = "all",
    sort_by: str = "recommended",
    limit: int = 10,
    user_id: int | None = None,
) -> list[dict]:
    """Возвращает отфильтрованные и отсортированные прокси."""
    return catalog_filter_proxies(
        _available_proxies(user_id),
        region=region,
        proxy_type=proxy_type,
        sort_by=sort_by,
        limit=limit,
    )


# Keep old name for backward compat (bot handlers)
def _get_top10() -> list[dict]:
    return _get_proxies_filtered(limit=10)


def _json(data, status: int = 200) -> web.Response:
    return web.Response(
        text=json.dumps(data, ensure_ascii=False, default=str),
        content_type="application/json",
        status=status,
    )


def _request_is_https(request: web.Request) -> bool:
    forwarded = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return request.secure or forwarded == "https" or str(request.app.get("base_url", "")).startswith("https://")


# ──────────────────────────────────────────────────────────────────────────────
# Главная страница
# ──────────────────────────────────────────────────────────────────────────────

async def index(request: web.Request) -> web.Response:
    bot_username = request.app.get("bot_username", "")
    html = (PROJECT_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    html = html.replace("__BOT_USERNAME__", bot_username)
    html = html.replace("__STATIC_VER__", _STATIC_VER)
    return web.Response(text=html, content_type="text/html",
                        headers={"Cache-Control": "no-store"})


async def favicon(request: web.Request) -> web.Response:
    return web.Response(status=204)


async def logout(request: web.Request) -> web.Response:
    response = web.HTTPFound("/")
    clear_session_cookie(response)
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Конфиг (публичный)
# ──────────────────────────────────────────────────────────────────────────────

async def api_config(request: web.Request) -> web.Response:
    return _json({
        "bot_username": request.app.get("bot_username", ""),
        "base_url":     request.app.get("base_url", ""),
        "probe_region": request.app.get("probe_region", "us-oregon"),
        "access_price_rub": 0,
    })


async def healthz(request: web.Request) -> web.Response:
    """Лёгкая проверка Render: веб-процесс отвечает, кэш доступен."""
    return _json({
        "ok": True,
        "probe_region": request.app.get("probe_region", "us-oregon"),
        "cached_proxies": len(worker.CACHED_BEST_PROXIES),
    })


# ──────────────────────────────────────────────────────────────────────────────
# Авторизация по логину + паролю
# ──────────────────────────────────────────────────────────────────────────────

async def api_auth_login(request: web.Request) -> web.Response:
    """
    POST /api/auth/login
    Body: { "login": "...", "password": "..." }
    """
    user_repo  = request.app.get("user_repo")
    secret_key = request.app.get("secret_key", "")

    if not user_repo:
        return _json({"ok": False, "error": "База данных недоступна."}, status=503)

    try:
        body     = await request.json()
        login    = str(body.get("login", "")).strip()
        password = str(body.get("password", ""))
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    if not login or not password:
        return _json({"ok": False, "error": "Введите логин и пароль."}, status=400)

    user = await user_repo.login_user(login, password)
    if not user:
        return _json({"ok": False, "error": "Неверный логин или пароль."}, status=401)

    response = _json({"ok": True})
    set_session_cookie(
        response, user["telegram_id"], secret_key, secure=_request_is_https(request)
    )
    logger.info("auth/login: telegram_id=%d login=%s", user["telegram_id"], login)
    return response


async def api_auth_register(request: web.Request) -> web.Response:
    """
    POST /api/auth/register
    Body: { "login": "...", "password": "..." }
    Регистрация нового аккаунта через сайт без Telegram.
    """
    user_repo = request.app.get("user_repo")
    if not user_repo:
        return _json({"ok": False, "error": "База данных недоступна."}, status=503)

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    login    = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))

    # Валидация логина
    if not login:
        return _json({"ok": False, "error": "Введите логин."}, status=400)
    if len(login) < 3:
        return _json({"ok": False, "error": "Логин должен быть не короче 3 символов."}, status=400)
    if len(login) > 32:
        return _json({"ok": False, "error": "Логин не может быть длиннее 32 символов."}, status=400)
    if not re.match(r'^[a-zA-Z0-9_]+$', login):
        return _json({"ok": False, "error": "Логин может содержать только буквы a-z, цифры и _"}, status=400)

    # Валидация пароля
    if not password:
        return _json({"ok": False, "error": "Введите пароль."}, status=400)
    if len(password) < 10:
        return _json({"ok": False, "error": "Пароль должен быть не короче 10 символов."}, status=400)

    try:
        # Регистрация на сайте не зависит от того, видел ли пользователя бот.
        # Telegram username остаётся логином, а привязка к боту может произойти
        # позже при первом обращении пользователя к боту.
        normalized_login = login.lower()
        existing = await user_repo.get_user_by_login(normalized_login)
        if existing:
            user = await user_repo.register_existing_telegram_user(normalized_login, password)
        else:
            user = await user_repo.create_web_user(normalized_login, password)
    except ValueError as exc:
        return _json({"ok": False, "error": str(exc)}, status=409)
    except Exception as exc:
        logger.error("auth/register: %s", exc)
        return _json({"ok": False, "error": "Ошибка сервера. Попробуйте позже."}, status=500)

    # Выдаём сессионный cookie
    secret_key = request.app.get("secret_key", "")
    response = _json({"ok": True, "login": login})
    set_session_cookie(
        response, user["telegram_id"], secret_key, secure=_request_is_https(request)
    )
    logger.info("auth/register: new web user login=%s id=%d", login, user["telegram_id"])
    return response


async def api_auth_reg_poll(request: web.Request) -> web.Response:
    """
    GET /api/auth/reg/poll?token=<token>
    Проверяет, подтвердил ли пользователь регистрацию через Telegram.
    Если да — устанавливает сессионный cookie.
    """
    token      = request.rel_url.query.get("token", "").strip()
    user_repo  = request.app.get("user_repo")
    secret_key = request.app.get("secret_key", "")

    if not token or not user_repo:
        return _json({"ok": True, "done": False})

    row = await user_repo.get_pending_reg(token)
    if not row:
        return _json({"ok": False, "error": "Ссылка устарела. Зарегистрируйтесь заново."})

    if not row.get("telegram_id"):
        return _json({"ok": True, "done": False})

    # Регистрация завершена — выдаём сессию
    response = web.Response(
        text=json.dumps({"ok": True, "done": True}, ensure_ascii=False),
        content_type="application/json",
    )
    set_session_cookie(
        response, row["telegram_id"], secret_key, secure=_request_is_https(request)
    )
    # Удаляем pending запись
    async with user_repo._pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM pending_registrations WHERE token = $1", token
        )
    logger.info("auth/reg/poll: completed for telegram_id=%d", row["telegram_id"])
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Текущий пользователь
# ──────────────────────────────────────────────────────────────────────────────

async def api_me(request: web.Request) -> web.Response:
    uid       = get_uid_from_request(request)
    user_repo = request.app.get("user_repo")

    if not uid:
        return _json({"authenticated": False})

    user = await user_repo.get_user(uid) if user_repo else None
    if not user:
        return _json({"authenticated": False})

    return _json({
        "authenticated":  True,
        "account_login":  user.get("account_login", ""),
        "first_name":     user.get("first_name", ""),
        "username":       user.get("username", ""),
        "photo_url":      user.get("photo_url", ""),
        "access_price_rub": 0,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Прокси (только подписчики)
# ──────────────────────────────────────────────────────────────────────────────

async def api_account_password(request: web.Request) -> web.Response:
    """
    POST /api/account/password
    Body: { "old_password": "...", "new_password": "..." }
    """
    uid = get_uid_from_request(request)
    user_repo = request.app.get("user_repo")

    if not uid:
        return _json({"ok": False, "error": "Войдите в аккаунт."}, status=401)
    if not user_repo:
        return _json({"ok": False, "error": "База данных недоступна."}, status=503)

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    old_password = str(body.get("old_password", ""))
    new_password = str(body.get("new_password", ""))
    if not old_password:
        return _json({"ok": False, "error": "Введите текущий пароль."}, status=400)
    if len(new_password) < 10:
        return _json({"ok": False, "error": "Новый пароль должен быть не короче 10 символов."}, status=400)
    if old_password == new_password:
        return _json({"ok": False, "error": "Новый пароль должен отличаться от текущего."}, status=400)

    user = await user_repo.get_user(uid)
    if not user:
        return _json({"ok": False, "error": "Аккаунт не найден."}, status=404)

    login = user.get("account_login") or user.get("username") or f"user{uid}"
    if not await user_repo.login_user(login, old_password):
        return _json({"ok": False, "error": "Текущий пароль указан неверно."}, status=401)

    await user_repo.set_credentials(uid, login, new_password)
    logger.info("account/password: changed for telegram_id=%d login=%s", uid, login)
    return _json({"ok": True})


def _proxy_dict(p: dict) -> dict:
    score = p.get("transport_score", p.get("tspu_score", p.get("tspu", 0))) or 0
    return {
        "id":        p["id"],
        "server":    p["server"],
        "port":      p["port"],
        "secret":    p["secret"],
        "ping":      p.get("ping_ms") or p.get("ping", 0),
        "transport_score": score,
        "tspu":      score,
        "stability": p.get("stability", 100),
        "category":  p.get("category", "EU"),
        "type":      _secret_type(p["secret"]),
        "sni":       p.get("sni_domain", ""),
        "probe":     p.get("probe_state", "tcp_only"),
        "source_count": p.get("source_count", 1),
        "score_notice": "Оценка сервера, а не гарантия доступности у конкретного оператора.",
        "ru_reachability_score": p.get("ru_reachability_score", 50),
        "ru_feedback_total": p.get("ru_feedback_total", 0),
        "ru_successes": p.get("ru_successes", 0),
        "ru_failures": p.get("ru_failures", 0),
        "admin_recommended": bool(p.get("admin_recommended", False)),
        "personal_score": p.get("personal_score"),
        "match_reasons": p.get("match_reasons", []),
        "tg_url":    f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}",
    }


async def _tcp_check_one(server: str, port: int, timeout: float = 3.5) -> int | None:
    """TCP-connect к хосту. Возвращает пинг в мс или None если недоступен."""
    try:
        import asyncio as _aio
        t0 = time.monotonic()
        r, w = await _aio.wait_for(_aio.open_connection(server, port), timeout=timeout)
        ms = int((time.monotonic() - t0) * 1000)
        w.close()
        try:
            await _aio.wait_for(w.wait_closed(), timeout=0.5)
        except Exception:
            pass
        return ms
    except Exception:
        return None


async def api_find_best_proxy(request: web.Request) -> web.Response:
    """
    POST /api/proxies/find-best {region, type, sort, profile, skip_ids}

    Двухфазный батчевый поиск — логика идентична _find_first_working в боте:

    Phase 1 — Итерируем по прокси согласно фильтрам (region/type/sort) батчами
              по BATCH=10. Недоступный батч пропускаем только в рамках
              текущего поиска, затем берём следующие 10.

    Phase 2 — Если по фильтру все прокси кончились: ищем по абсолютно всем
              прокси (region=all, type=all), пропуская уже проверенные.
              Пропускается, если фильтр и так был all/all.
    """
    uid       = get_uid_from_request(request)
    if not uid:
        return _json({"ok": False, "error": "auth"}, status=401)

    try:
        body = await request.json() if request.can_read_body else {}
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    region = str(body.get("region", request.rel_url.query.get("region", "all"))).strip()
    proxy_type = str(body.get("type", request.rel_url.query.get("type", "all"))).strip()
    sort_by = str(body.get("sort", request.rel_url.query.get("sort", "recommended"))).strip()
    raw_skip = body.get("skip_ids", [])
    skip_ids = {
        str(proxy_id) for proxy_id in raw_skip[:100]
        if isinstance(proxy_id, (str, int)) and str(proxy_id).strip()
    } if isinstance(raw_skip, list) else set()
    profile = normalize_client_profile(body.get("profile") if isinstance(body.get("profile"), dict) else {})

    BATCH   = 10
    THRESH  = 350   # мс — порог TCP-ответа

    primary = personalize_proxies(_get_proxies_filtered(
        region=region, proxy_type=proxy_type, sort_by=sort_by, limit=300, user_id=uid
    ), profile, user_id=uid)
    fallback: list[dict] = []
    if not (region == "all" and proxy_type == "all"):
        fallback = personalize_proxies(_get_proxies_filtered(
            region="all", proxy_type="all", sort_by=sort_by, limit=300, user_id=uid
        ), profile, user_id=uid)
    selection = await select_first_reachable(
        primary,
        fallback,
        _tcp_check_one,
        skip_ids=skip_ids,
        batch_size=BATCH,
        threshold_ms=THRESH,
    )
    checked = len(selection.checked_unreachable)
    if selection.proxy is not None:
        found = {**_proxy_dict(selection.proxy), "real_ms": selection.response_ms}
        return _json({
            "ok": True,
            "proxy": found,
            "checked_unreachable": checked,
            "profile": profile.as_dict(),
            "profile_summary": profile.summary(),
        })
    return _json({
        "ok": False,
        "error": "none_working",
        "checked_unreachable": checked,
        "profile_summary": profile.summary(),
    })


async def api_proxy_ban(request: web.Request) -> web.Response:
    """
    POST /api/proxies/ban
    Клиент сообщает, что прокси недоступен из его сети.
    Прокси временно баниятся в ротации (1 час).
    """
    uid = get_uid_from_request(request)
    if not uid:
        return _json({"ok": False, "error": "auth"}, status=401)

    try:
        data = await request.json()
    except Exception:
        return _json({"ok": False, "error": "bad_json"}, status=400)

    # Жалоба сразу скрывает адрес для автора. Глобальное исключение требует
    # нескольких разных пользователей, чтобы один клиент не мог испортить пул.
    ids = data.get("ids") or ([data["id"]] if data.get("id") else [])
    ids = ids[:10] if isinstance(ids, list) else []
    reported = 0
    globally_hidden = 0
    for pid in ids:
        pid = str(pid).strip()
        if pid:
            if await _record_ru_feedback(request, uid, pid, False):
                globally_hidden += int(feedback.is_blocked(pid, now=time.time()))
                reported += 1

    return _json({"ok": True, "reported": reported, "globally_hidden": globally_hidden})


async def _record_ru_feedback(
    request: web.Request,
    uid: int,
    proxy_id: str,
    works: bool,
    *,
    network_type: str = "unknown",
    operator_name: str = "",
) -> bool:
    if not any(proxy.get("id") == proxy_id for proxy in worker.CACHED_BEST_PROXIES):
        return False
    if works:
        feedback.report_success(proxy_id, uid)
    else:
        feedback.report_failure(proxy_id, uid)
    repo = request.app.get("proxy_repo")
    if repo is not None:
        try:
            await repo.record_feedback(
                proxy_id,
                uid,
                works,
                network_type=network_type,
                operator_name=operator_name,
            )
        except Exception as exc:
            logger.warning("proxy feedback persistence failed: %s", exc)
    return True


async def api_proxy_feedback(request: web.Request) -> web.Response:
    """POST /api/proxies/feedback — результат реального подключения пользователя из РФ."""
    uid = get_uid_from_request(request)
    if not uid:
        return _json({"ok": False, "error": "auth"}, status=401)
    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "bad_json"}, status=400)
    proxy_id = str(body.get("id", "")).strip()
    outcome = str(body.get("outcome", "")).strip().lower()
    if outcome not in {"works", "fails"}:
        return _json({"ok": False, "error": "outcome must be works or fails"}, status=400)
    saved = await _record_ru_feedback(
        request,
        uid,
        proxy_id,
        outcome == "works",
        network_type=str(body.get("network_type", "unknown")),
        operator_name=str(body.get("operator", "")),
    )
    if not saved:
        return _json({"ok": False, "error": "proxy_not_found"}, status=404)
    return _json({"ok": True})


async def api_proxies(request: web.Request) -> web.Response:
    uid       = get_uid_from_request(request)
    if not uid:
        return _json({"error": "Unauthorized"}, status=401)

    region     = request.rel_url.query.get("region", "all").strip()
    proxy_type = request.rel_url.query.get("type",   "all").strip()
    sort_by    = request.rel_url.query.get("sort",   "recommended").strip()

    try:
        limit = min(int(request.rel_url.query.get("limit", "10")), 200)
    except (ValueError, TypeError):
        limit = 10

    proxies = _get_proxies_filtered(
        region=region, proxy_type=proxy_type, sort_by=sort_by, limit=limit, user_id=uid
    )
    total = len(_available_proxies(uid))

    last_at = worker.LAST_CYCLE_AT
    interval = worker.WORKER_INTERVAL
    if last_at > 0:
        elapsed = time.time() - last_at
        next_update_in = max(0, int(interval - elapsed))
    else:
        next_update_in = interval

    return _json({
        "proxies": [_proxy_dict(p) for p in proxies],
        "total": total,
        "next_update_in": next_update_in,
        "worker_interval": interval,
    })


async def api_proxies_check(request: web.Request) -> web.Response:
    """
    POST /api/proxies/check
    Body: { "proxies": [{"id": "...", "server": "...", "port": 443}, ...] }
    Проверяет каждый прокси TCP-соединением, возвращает реальный пинг в мс.
    """
    uid       = get_uid_from_request(request)
    if not uid:
        return _json({"ok": False, "error": "Unauthorized"}, status=401)

    try:
        body = await request.json()
        proxies_to_check = body.get("proxies", [])
    except Exception:
        return _json({"ok": False, "error": "Bad request"}, status=400)

    if not isinstance(proxies_to_check, list) or len(proxies_to_check) > 30:
        return _json({"ok": False, "error": "Список прокси должен содержать не более 30 элементов."}, status=400)

    import asyncio as _asyncio
    results: dict = {}
    sem = _asyncio.Semaphore(20)

    async def check_one(p: dict) -> None:
        pid    = str(p.get("id", ""))
        server = str(p.get("server", "")).strip()
        port   = p.get("port", 0)
        if not server or not port or not pid:
            return
        async with sem:
            try:
                t0 = time.monotonic()
                reader, writer = await _asyncio.wait_for(
                    _asyncio.open_connection(server, int(port)),
                    timeout=5.0,
                )
                ms = int((time.monotonic() - t0) * 1000)
                writer.close()
                try:
                    await _asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
                results[pid] = {"ok": True, "ms": ms}
            except Exception:
                results[pid] = {"ok": False, "ms": None}

    await _asyncio.gather(*[check_one(p) for p in proxies_to_check])
    return _json({"ok": True, "results": results})


async def api_proxies_replace(request: web.Request) -> web.Response:
    """POST /api/proxies/replace  { proxy_id, region, type, sort }"""
    uid       = get_uid_from_request(request)
    if not uid:
        return _json({"ok": False, "error": "Unauthorized"}, status=401)

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Bad request"}, status=400)

    proxy_id   = str(body.get("proxy_id", "")).strip()
    region     = str(body.get("region",   "all")).strip()
    proxy_type = str(body.get("type",     "all")).strip()
    sort_by    = str(body.get("sort",     "recommended")).strip()

    if not proxy_id:
        return _json({"ok": False, "error": "proxy_id required"}, status=400)

    await _record_ru_feedback(request, uid, proxy_id, False)
    logger.info("proxies/replace: user=%s reported proxy=%s", uid, proxy_id)

    # Возвращаем следующий подходящий прокси с теми же фильтрами
    proxies = _get_proxies_filtered(
        region=region, proxy_type=proxy_type, sort_by=sort_by, limit=10, user_id=uid
    )
    if not proxies:
        return _json({"ok": False, "error": "Нет доступных прокси для замены."})

    return _json({"ok": True, "proxies": [_proxy_dict(p) for p in proxies]})




# ──────────────────────────────────────────────────────────────────────────────
# Telegram webhook (prod)
# ──────────────────────────────────────────────────────────────────────────────

async def telegram_webhook(request: web.Request) -> web.Response:
    expected = str(request.app.get("tg_webhook_secret", ""))
    received = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not expected or not hmac.compare_digest(received, expected):
        return web.Response(status=403)
    bot = request.app.get("bot")
    dp  = request.app.get("dp")
    if not bot or not dp:
        return web.Response(status=503)
    try:
        from aiogram.types import Update
        data   = await request.json()
        update = Update.model_validate(data)
        await dp.feed_update(bot=bot, update=update)
    except Exception as exc:
        logger.error("Webhook processing error: %s", exc)
    return web.Response(text="ok")


# ──────────────────────────────────────────────────────────────────────────────
# Регистрация маршрутов
# ──────────────────────────────────────────────────────────────────────────────

def setup_routes(app: web.Application, webhook_path: str = "", admin_path: str = "admin") -> None:
    from app.web.admin_routes import setup_admin_routes
    setup_admin_routes(app, admin_path=admin_path)

    app.router.add_get("/",                       index)
    app.router.add_get("/login",                  index)
    app.router.add_get("/login/",                 index)
    app.router.add_get("/register",               index)
    app.router.add_get("/register/",              index)
    app.router.add_get("/app",                    index)
    app.router.add_get("/app/",                   index)
    app.router.add_get("/account",                index)
    app.router.add_get("/account/",               index)
    app.router.add_get("/subscribe",              index)
    app.router.add_get("/subscribe/",             index)
    app.router.add_get("/connect_proxy",          index)
    app.router.add_get("/connect_proxy/",         index)
    app.router.add_get("/favicon.ico",            favicon)
    app.router.add_get("/logout",                 logout)
    app.router.add_get("/api/config",             api_config)
    app.router.add_get("/healthz",               healthz)
    app.router.add_get("/api/me",                 api_me)
    app.router.add_get("/api/proxies",             api_proxies)
    app.router.add_get("/api/proxies/find-best",  api_find_best_proxy)
    app.router.add_post("/api/proxies/find-best", api_find_best_proxy)
    app.router.add_post("/api/proxies/ban",        api_proxy_ban)
    app.router.add_post("/api/proxies/feedback",   api_proxy_feedback)
    app.router.add_post("/api/proxies/replace",   api_proxies_replace)
    app.router.add_post("/api/proxies/check",     api_proxies_check)
    app.router.add_get("/api/auth/reg/poll",      api_auth_reg_poll)
    app.router.add_post("/api/auth/login",        api_auth_login)
    app.router.add_post("/api/auth/register",     api_auth_register)
    app.router.add_post("/api/account/password",  api_account_password)
    if webhook_path:
        app.router.add_post(webhook_path, telegram_webhook)
    static_path = PROJECT_DIR / "static"
    app.router.add_static("/static/", path=str(static_path), name="static")
