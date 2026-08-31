"""
admin_routes.py — Защищённая административная панель.

Безопасность:
  - Пароль из ADMIN_PASSWORD (env var).
  - HMAC-SHA256 подписанный cookie, TTL 8 часов.
  - Rate limiting: 5 неверных попыток → блокировка на 15 мин (в памяти процесса).
  - Все /admin/api/* маршруты требуют валидного cookie.
  - Cookie: HttpOnly, SameSite=Strict, Secure (в prod).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
from pathlib import Path

from aiohttp import web

logger = logging.getLogger(__name__)

_ADM_COOKIE   = "adm_s"
_ADM_MAX_AGE  = 8 * 3600       # 8 часов
_MAX_FAILS    = 5
_LOCKOUT_SECS = 15 * 60        # 15 минут

# Rate-limit store: ip → {"fails": int, "until": float}
_rl: dict[str, dict] = {}


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _make_token(secret: str) -> str:
    ts  = str(int(time.time()))
    sig = hmac.new(secret.encode(), f"adm:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _verify_token(token: str, secret: str) -> bool:
    try:
        ts_str, sig = token.split(".", 1)
        if time.time() - int(ts_str) > _ADM_MAX_AGE:
            return False
        expected = hmac.new(
            secret.encode(), f"adm:{ts_str}".encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def _get_ip(request: web.Request) -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or str(request.remote)
        or "unknown"
    )


def _request_is_https(request: web.Request) -> bool:
    forwarded = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return request.secure or forwarded == "https" or str(request.app.get("base_url", "")).startswith("https://")


def _rl_allowed(ip: str) -> bool:
    entry = _rl.get(ip)
    if not entry:
        return True
    return time.time() >= entry.get("until", 0)


def _rl_fail(ip: str) -> None:
    now   = time.time()
    entry = _rl.get(ip, {"fails": 0, "until": 0})
    if entry.get("until", 0) > now:
        return
    entry["fails"] = entry.get("fails", 0) + 1
    if entry["fails"] >= _MAX_FAILS:
        entry["until"] = now + _LOCKOUT_SECS
        entry["fails"] = 0
        logger.warning("admin: IP %s заблокирован на 15 мин (5 неверных попыток)", ip)
    _rl[ip] = entry


def _rl_reset(ip: str) -> None:
    _rl.pop(ip, None)


def _is_admin(request: web.Request) -> bool:
    secret = request.app.get("secret_key", "")
    token  = request.cookies.get(_ADM_COOKIE, "")
    return bool(secret and token and _verify_token(token, secret))


def _json(data: dict, *, status: int = 200) -> web.Response:
    import json
    return web.Response(
        text=json.dumps(data, ensure_ascii=False, default=str),
        content_type="application/json",
        status=status,
    )


def _require_admin(handler):
    """Декоратор: 401 если нет валидного admin cookie."""
    async def wrapper(request: web.Request):
        if not _is_admin(request):
            return _json({"ok": False, "error": "Unauthorized"}, status=401)
        return await handler(request)
    return wrapper


# ── Страница ──────────────────────────────────────────────────────────────────

async def admin_index(request: web.Request) -> web.Response:
    """GET /{admin_path} — отдаёт admin.html с подставленным base-path."""
    html_path = Path(__file__).resolve().parents[2] / "static" / "admin.html"
    if not html_path.exists():
        return web.Response(text="admin.html not found", status=500)
    admin_path = request.app.get("admin_path", "admin")
    html = html_path.read_text(encoding="utf-8").replace(
        "%%ADMIN_BASE%%", "/" + admin_path
    )
    return web.Response(text=html, content_type="text/html")


# ── Auth ──────────────────────────────────────────────────────────────────────

async def admin_login(request: web.Request) -> web.Response:
    """POST /admin/login  { "password": "..." }"""
    ip = _get_ip(request)
    if not _rl_allowed(ip):
        return _json(
            {"ok": False, "error": "Слишком много попыток. Подождите 15 минут."},
            status=429,
        )

    admin_pw = request.app.get("admin_password", "")
    if not admin_pw:
        return _json(
            {"ok": False, "error": "ADMIN_PASSWORD не задан на сервере."},
            status=503,
        )

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    password = str(body.get("password", ""))
    if not hmac.compare_digest(password.encode(), admin_pw.encode()):
        _rl_fail(ip)
        logger.warning("admin: неверный пароль с IP %s", ip)
        return _json({"ok": False, "error": "Неверный пароль."}, status=403)

    _rl_reset(ip)
    secret = request.app.get("secret_key", "")
    token  = _make_token(secret)

    resp = _json({"ok": True})
    admin_path = request.app.get("admin_path", "admin")
    resp.set_cookie(
        _ADM_COOKIE, token,
        max_age=_ADM_MAX_AGE,
        httponly=True,
        samesite="Strict",
        secure=_request_is_https(request),
        path="/" + admin_path,
    )
    logger.info("admin: успешный вход с IP %s", ip)
    return resp


async def admin_logout(request: web.Request) -> web.Response:
    """POST /{admin_path}/logout"""
    admin_path = request.app.get("admin_path", "admin")
    resp = _json({"ok": True})
    resp.del_cookie(_ADM_COOKIE, path="/" + admin_path)
    return resp


# ── API: статистика ────────────────────────────────────────────────────────────

@_require_admin
async def admin_stats(request: web.Request) -> web.Response:
    """GET /admin/api/stats"""
    user_repo  = request.app.get("user_repo")
    proxy_repo = request.app.get("proxy_repo")
    result: dict = {}

    if proxy_repo:
        try:
            proxy_stats = await proxy_repo.stats()
            proxy_stats["db_size_mb"] = await proxy_repo.get_db_size_mb()
            result["proxies"] = proxy_stats
        except Exception as exc:
            result["proxies"] = {"error": str(exc)}

    if user_repo:
        try:
            async with user_repo._pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT
                        COUNT(*) AS total_users
                    FROM users
                """)
            result["users"] = dict(row)
        except Exception as exc:
            result["users"] = {"error": str(exc)}

    return _json({"ok": True, **result})


# ── API: пользователи ─────────────────────────────────────────────────────────

@_require_admin
async def admin_users(request: web.Request) -> web.Response:
    """GET /admin/api/users?page=1&q=&limit=25"""
    user_repo = request.app.get("user_repo")
    if not user_repo:
        return _json({"ok": False, "error": "БД недоступна."}, status=503)

    q      = request.rel_url.query.get("q", "").strip()
    page   = max(1, int(request.rel_url.query.get("page",  "1")  or 1))
    limit  = min(100, max(10, int(request.rel_url.query.get("limit", "25") or 25)))
    offset = (page - 1) * limit

    try:
        async with user_repo._pool.acquire() as conn:
            if q:
                q_like = f"%{q}%"
                where  = """
                    WHERE account_login ILIKE $1
                       OR username      ILIKE $1
                       OR first_name    ILIKE $1
                """
                rows = await conn.fetch(
                    f"""
                    SELECT telegram_id AS internal_id, account_login, username,
                           first_name, last_name, created_at, updated_at
                    FROM users {where}
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                    """,
                    q_like, limit, offset,
                )
                total = await conn.fetchval(
                    f"SELECT COUNT(*) FROM users {where}", q_like
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT telegram_id AS internal_id, account_login, username,
                           first_name, last_name, created_at, updated_at
                    FROM users
                    ORDER BY created_at DESC LIMIT $1 OFFSET $2
                    """,
                    limit, offset,
                )
                total = await conn.fetchval("SELECT COUNT(*) FROM users")
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)

    return _json({
        "ok":    True,
        "users": [dict(r) for r in rows],
        "total": int(total),
        "page":  page,
        "limit": limit,
    })


@_require_admin
async def admin_user_detail(request: web.Request) -> web.Response:
    """GET /admin/api/user/{tid}"""
    user_repo = request.app.get("user_repo")
    if not user_repo:
        return _json({"ok": False, "error": "БД недоступна."}, status=503)
    try:
        tid = int(request.match_info["tid"])
    except (KeyError, ValueError):
        return _json({"ok": False, "error": "Неверный ID."}, status=400)

    try:
        async with user_repo._pool.acquire() as conn:
            user = await conn.fetchrow(
                """SELECT telegram_id AS internal_id, account_login, username, first_name, last_name,
                          created_at, updated_at
                   FROM users WHERE telegram_id = $1""",
                tid,
            )
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)

    if not user:
        return _json({"ok": False, "error": "Пользователь не найден."}, status=404)

    return _json({
        "ok":         True,
        "user":       dict(user),
    })


@_require_admin
async def admin_user_delete(request: web.Request) -> web.Response:
    """DELETE /admin/api/user/{tid}"""
    user_repo = request.app.get("user_repo")
    if not user_repo:
        return _json({"ok": False, "error": "БД недоступна."}, status=503)
    try:
        tid = int(request.match_info["tid"])
    except (KeyError, ValueError):
        return _json({"ok": False, "error": "Неверный ID."}, status=400)

    try:
        async with user_repo._pool.acquire() as conn:
            async with conn.transaction():
                dep_tables = await conn.fetch(
                    """
                    SELECT kcu.table_name, kcu.column_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                        ON tc.constraint_name = kcu.constraint_name
                        AND tc.table_schema = kcu.table_schema
                    JOIN information_schema.referential_constraints rc
                        ON tc.constraint_name = rc.constraint_name
                        AND tc.table_schema = rc.constraint_schema
                    JOIN information_schema.key_column_usage rcu
                        ON rc.unique_constraint_name = rcu.constraint_name
                        AND rc.unique_constraint_schema = rcu.table_schema
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                      AND rcu.table_name = 'users'
                      AND rcu.column_name = 'telegram_id'
                    """
                )
                for row in dep_tables:
                    tbl = row["table_name"]
                    col = row["column_name"]
                    await conn.execute(f"DELETE FROM {tbl} WHERE {col}=$1", tid)
                    logger.info("admin: del deps uid=%d table=%s", tid, tbl)
                result = await conn.execute("DELETE FROM users WHERE telegram_id=$1", tid)
        deleted = int(result.split()[-1])
        logger.info("admin: пользователь удалён uid=%d (rows=%d)", tid, deleted)
        return _json({"ok": True, "deleted": deleted})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


# ── API: очистка прокси ───────────────────────────────────────────────────────

@_require_admin
async def admin_purge_proxies(request: web.Request) -> web.Response:
    """POST /admin/api/purge  { "days": 7 }"""
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)

    try:
        body = await request.json()
        days = max(1, min(365, int(body.get("days", 7))))
    except Exception:
        days = 7

    try:
        deleted = await proxy_repo.purge_old_dead(days=days)
        logger.info("admin: purge_old_dead days=%d deleted=%d", days, deleted)
        return _json({"ok": True, "deleted": deleted, "days": days})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)



# ── API: список прокси для управления ────────────────────────────────────────

@_require_admin
async def admin_proxies_list(request: web.Request) -> web.Response:
    """GET /admin/api/proxies?page=1&limit=50&category=&generation=&alive="""
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)

    q          = request.rel_url.query
    try:
        page  = max(1, int(q.get("page",  "1")  or 1))
        limit = min(200, max(10, int(q.get("limit", "50") or 50)))
    except (ValueError, TypeError):
        return _json({"ok": False, "error": "Неверные параметры page/limit."}, status=400)
    category   = q.get("category",   "").strip() or None
    generation = q.get("generation", "").strip() or None
    alive_str  = q.get("alive", "").strip()
    alive_only = True if alive_str == "1" else (False if alive_str == "0" else None)

    try:
        proxies, total = await proxy_repo.list_proxies(
            page=page, limit=limit,
            category=category, generation=generation,
            alive_only=alive_only,
        )
        return _json({"ok": True, "proxies": proxies, "total": total, "page": page, "limit": limit})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


@_require_admin
async def admin_proxy_recommend(request: web.Request) -> web.Response:
    """POST /admin/api/proxies/recommend {id, recommended}."""
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)
    try:
        body = await request.json()
        proxy_id = str(body.get("id", "")).strip()
        recommended = body.get("recommended") is True
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)
    if not proxy_id:
        return _json({"ok": False, "error": "Не указан ID прокси."}, status=400)

    try:
        updated = await proxy_repo.set_admin_recommendation(proxy_id, recommended)
        if not updated:
            message = "Рекомендовать можно только живой прокси." if recommended else "Прокси не найден."
            return _json({"ok": False, "error": message}, status=404)

        from app.proxy import pipeline as proxy_pipeline
        for cached in proxy_pipeline.CACHED_BEST_PROXIES:
            if cached.get("id") == proxy_id:
                cached["admin_recommended"] = recommended
                cached["admin_recommended_at"] = updated.get("admin_recommended_at")
                break
        proxy_pipeline.request_pipeline_update()
        logger.info("admin: proxy recommendation id=%s recommended=%s", proxy_id, recommended)
        return _json({"ok": True, **updated})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


@_require_admin
async def admin_proxies_delete(request: web.Request) -> web.Response:
    """POST /admin/api/proxies/delete  { "ids": ["abc123", ...] }"""
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)

    try:
        body = await request.json()
        ids  = [str(i) for i in (body.get("ids") or [])]
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    if not ids:
        return _json({"ok": False, "error": "Список ID пуст."}, status=400)
    if len(ids) > 1000:
        return _json({"ok": False, "error": "Слишком много ID (макс. 1000)."}, status=400)

    try:
        deleted = await proxy_repo.delete_by_ids(ids)
        logger.info("admin: proxies_delete ids=%d deleted=%d", len(ids), deleted)
        return _json({"ok": True, "deleted": deleted})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)

# ── API: удаление прокси по фильтру ──────────────────────────────────────────

@_require_admin
async def admin_proxies_delete_filter(request: web.Request) -> web.Response:
    """
    POST /admin/api/proxies/delete-filter
    { "sni_contains": "biscotti.yektanet.com", "category": "", "generation": "", "host_contains": "", "alive_only": null }
    """
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    sni_contains  = (body.get("sni_contains")  or "").strip() or None
    host_contains = (body.get("host_contains") or "").strip() or None
    category      = (body.get("category")      or "").strip() or None
    generation    = (body.get("generation")    or "").strip() or None
    alive_str     = body.get("alive_only")
    alive_only    = True if alive_str == "1" else (False if alive_str == "0" else None)

    if not any([sni_contains, host_contains, category, generation, alive_only is not None]):
        return _json({"ok": False, "error": "Укажите хотя бы один фильтр."}, status=400)

    try:
        deleted = await proxy_repo.delete_by_filter(
            sni_contains=sni_contains,
            host_contains=host_contains,
            category=category,
            generation=generation,
            alive_only=alive_only,
        )
        logger.info("admin: delete_filter deleted=%d", deleted)

        # Запускаем принудительное обновление пайплайна
        try:
            from app.proxy import pipeline as _pipeline
            _pipeline.request_pipeline_update()
        except Exception:
            pass

        return _json({"ok": True, "deleted": deleted})
    except ValueError as exc:
        return _json({"ok": False, "error": str(exc)}, status=400)
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


@_require_admin
async def admin_proxies_count_filter(request: web.Request) -> web.Response:
    """
    POST /admin/api/proxies/count-filter  — предварительный подсчёт без удаления.
    """
    proxy_repo = request.app.get("proxy_repo")
    if not proxy_repo:
        return _json({"ok": False, "error": "ProxyRepository недоступен."}, status=503)

    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "Неверный формат запроса."}, status=400)

    sni_contains  = (body.get("sni_contains")  or "").strip() or None
    host_contains = (body.get("host_contains") or "").strip() or None
    category      = (body.get("category")      or "").strip() or None
    generation    = (body.get("generation")    or "").strip() or None
    alive_str     = body.get("alive_only")
    alive_only    = True if alive_str == "1" else (False if alive_str == "0" else None)

    try:
        count = await proxy_repo.count_by_filter(
            sni_contains=sni_contains,
            host_contains=host_contains,
            category=category,
            generation=generation,
            alive_only=alive_only,
        )
        return _json({"ok": True, "count": count})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


@_require_admin
async def admin_trigger_update(request: web.Request) -> web.Response:
    """POST /admin/api/trigger-update — немедленный перезапуск пайплайна."""
    try:
        from app.proxy import pipeline as _pipeline
        _pipeline.request_pipeline_update()
        return _json({"ok": True, "message": "Обновление запрошено. Пайплайн запустится немедленно."})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)}, status=500)


@_require_admin
async def admin_maintenance_status(request: web.Request) -> web.Response:
    user_repo = request.app.get("user_repo")
    proxy_repo = request.app.get("proxy_repo")
    result: dict[str, object] = {"ok": True}

    if proxy_repo:
        try:
            result["db_size_mb"] = await proxy_repo.get_db_size_mb()
        except Exception as exc:
            result["db_size_error"] = str(exc)

    if user_repo:
        try:
            async with user_repo._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        (SELECT COUNT(*) FROM auth_tokens WHERE expires_at < NOW()) AS expired_auth_tokens,
                        (SELECT COUNT(*) FROM pending_registrations WHERE expires_at < NOW()) AS expired_pending_regs,
                        (SELECT COUNT(*) FROM proxy_feedback WHERE reported_at < NOW() - INTERVAL '30 days') AS old_proxy_feedback
                    """
                )
            result["cleanup_candidates"] = dict(row)
            result["table_sizes"] = await user_repo.table_sizes()
        except Exception as exc:
            result["maintenance_error"] = str(exc)

    return _json(result)


@_require_admin
async def admin_maintenance_run(request: web.Request) -> web.Response:
    user_repo = request.app.get("user_repo")
    proxy_repo = request.app.get("proxy_repo")
    result: dict[str, object] = {"ok": True}

    if user_repo:
        result["user_cleanup"] = await user_repo.cleanup_expired()
    if proxy_repo:
        result["proxy_cleanup"] = {
            "dead": await proxy_repo.purge_old_dead(days=3),
            "cap": await proxy_repo.cap_proxies(3000),
            "feedback": await proxy_repo.purge_old_feedback(days=30),
        }
        result["db_size_mb"] = await proxy_repo.get_db_size_mb()

    logger.info("admin: maintenance run %s", result)
    return _json(result)


# ── Регистрация маршрутов ─────────────────────────────────────────────────────

def setup_admin_routes(app: web.Application, admin_path: str = "admin") -> None:
    # Нормализуем: убираем слэши по краям
    p = admin_path.strip("/") or "admin"
    app["admin_path"] = p

    app.router.add_get( f"/{p}",                             admin_index)
    app.router.add_post(f"/{p}/login",                       admin_login)
    app.router.add_post(f"/{p}/logout",                      admin_logout)
    app.router.add_get( f"/{p}/api/stats",                   admin_stats)
    app.router.add_get( f"/{p}/api/users",                   admin_users)
    app.router.add_post(f"/{p}/api/purge",                   admin_purge_proxies)
    app.router.add_get( f"/{p}/api/proxies",                 admin_proxies_list)
    app.router.add_post(f"/{p}/api/proxies/recommend",       admin_proxy_recommend)
    app.router.add_post(f"/{p}/api/proxies/delete",          admin_proxies_delete)
    app.router.add_get( f"/{p}/api/user/{{tid}}",                 admin_user_detail)
    app.router.add_get( f"/{p}/api/maintenance/status",           admin_maintenance_status)
    app.router.add_post(f"/{p}/api/maintenance/run",              admin_maintenance_run)
    app.router.add_delete(f"/{p}/api/user/{{tid}}",               admin_user_delete)
    app.router.add_post(f"/{p}/api/proxies/delete-filter",        admin_proxies_delete_filter)
    app.router.add_post(f"/{p}/api/proxies/count-filter",         admin_proxies_count_filter)
    app.router.add_post(f"/{p}/api/trigger-update",               admin_trigger_update)
    logger.info("admin: панель доступна по пути /%s", p)
