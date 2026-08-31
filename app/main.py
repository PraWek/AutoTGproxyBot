"""
main.py — Точка входа. Запускает веб-сервер и Telegram-бот.

Режимы бота:
  Webhook (prod) — если BASE_URL начинается с https://
                   бот принимает апдейты на POST /tg-webhook/<token>
                   → нет конфликтов при нескольких деплоях
  Polling (dev)  — иначе, с drop_pending_updates=True
"""
import asyncio
import hashlib
import logging
import os

import asyncpg
from aiohttp import web
from dotenv import load_dotenv
from app.core.settings import Settings

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@web.middleware
async def performance_headers(request: web.Request, handler):
    """Сжимает ответы и кэширует версионированные локальные ресурсы."""
    response = await handler(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    if response.content_type in {
        "text/html", "text/css", "application/javascript", "application/json",
    }:
        response.enable_compression()
    return response


async def db_maintenance_worker(user_repo, proxy_repo) -> None:
    while True:
        try:
            if user_repo is not None:
                counts = await user_repo.cleanup_expired()
                if any(counts.values()):
                    logger.info("db maintenance: temporary records cleanup=%s", counts)
            if proxy_repo is not None:
                deleted_dead = await proxy_repo.purge_old_dead(days=3)
                deleted_cap = await proxy_repo.cap_proxies(3000)
                deleted_feedback = await proxy_repo.purge_old_feedback(days=30)
                if deleted_dead or deleted_cap or deleted_feedback:
                    logger.info(
                        "db maintenance: proxies dead=%d cap=%d feedback=%d",
                        deleted_dead, deleted_cap, deleted_feedback,
                    )
        except Exception as exc:
            logger.error("db maintenance failed: %s", exc)
        await asyncio.sleep(6 * 3600)


async def main() -> None:
    app = web.Application(middlewares=[performance_headers])
    settings = Settings.from_env()

    # ── Конфиг ───────────────────────────────────────────────────────────────
    secret_key       = settings.secret_key or os.urandom(32).hex()
    webhook_secret   = settings.tg_webhook_secret
    if not 1 <= len(webhook_secret) <= 256 or not all(ch.isalnum() or ch in "_-" for ch in webhook_secret):
        webhook_secret = hashlib.sha256((secret_key + ":telegram-webhook").encode()).hexdigest()
    bot_token        = settings.bot_token
    bot_username     = settings.bot_username
    base_url         = settings.base_url
    admin_password   = settings.admin_password
    admin_path       = settings.admin_path

    if not admin_password:
        logger.warning("ADMIN_PASSWORD не задан — панель администратора будет недоступна!")
    if not admin_path:
        logger.warning("ADMIN_PATH не задан — используется путь по умолчанию 'admin'. Задайте секретный путь!")

    if not os.getenv("SECRET_KEY"):
        logger.warning("SECRET_KEY не задан — сессии будут сброшены при перезапуске!")

    # ── База данных ──────────────────────────────────────────────────────────
    repo = user_repo = None
    db_url = settings.database_url
    if db_url:
        try:
            pool = await asyncpg.create_pool(dsn=db_url, min_size=2, max_size=10)
            from app.db.schema import ProxyRepository, UserRepository
            repo      = ProxyRepository(pool)
            user_repo = UserRepository(pool)
            await repo.migrate()
            await user_repo.migrate()
            logger.info("PostgreSQL подключён.")
        except Exception as exc:
            logger.error("БД недоступна: %s", exc)
            repo = user_repo = None
    else:
        logger.warning("DATABASE_URL не задан — работаем без БД.")

    # ── Bot + Dispatcher ─────────────────────────────────────────────────────
    bot = dp = None
    use_webhook  = False
    webhook_path = ""

    if bot_token:
        from aiogram import Bot, Dispatcher
        from app.bot.handlers import setup_handlers, router

        setup_handlers(
            user_repo=user_repo,
            proxy_repo=repo,
            site_url=base_url,
        )
        bot = Bot(token=bot_token)
        dp  = Dispatcher()
        dp.include_router(router)

        use_webhook  = settings.use_webhook
        webhook_path = f"/tg-webhook/{webhook_secret}" if use_webhook else ""

        if use_webhook:
            logger.info("Бот: режим webhook для %s", base_url)
        else:
            logger.info("Бот: режим polling (dev)")
    else:
        logger.warning("BOT_TOKEN не задан — бот отключён.")

    # ── Маршруты ─────────────────────────────────────────────────────────────
    from app.web.routes import setup_routes
    setup_routes(app, webhook_path=webhook_path, admin_path=admin_path or "admin")

    # ── App state ────────────────────────────────────────────────────────────
    app["secret_key"]     = secret_key
    app["bot_username"]   = bot_username
    app["base_url"]       = base_url
    app["bot_token"]      = bot_token
    app["tg_webhook_secret"] = webhook_secret
    app["user_repo"]      = user_repo
    app["proxy_repo"]     = repo
    app["bot"]            = bot
    app["dp"]             = dp
    app["admin_password"] = admin_password
    app["probe_region"]   = settings.probe_region

    # ── Webhook startup/cleanup — aiohttp вызывает их сам через AppRunner ────
    if use_webhook and bot:
        webhook_url = base_url + webhook_path

        async def on_startup(application: web.Application) -> None:
            from aiogram.exceptions import TelegramRetryAfter
            for attempt in range(6):
                try:
                    await bot.set_webhook(
                        webhook_url,
                        drop_pending_updates=True,
                        secret_token=webhook_secret,
                    )
                    logger.info("Webhook Telegram установлен.")
                    return
                except TelegramRetryAfter as e:
                    wait = int(e.retry_after) + 2
                    logger.warning(
                        "Webhook: rate-limit, жду %d с (попытка %d/6)", wait, attempt + 1
                    )
                    await asyncio.sleep(wait)
                except Exception as exc:
                    logger.error("Webhook: не удалось установить: %s", exc)
                    return
            logger.error("Webhook: не установлен после 6 попыток")

        async def on_cleanup(application: web.Application) -> None:
            try:
                await bot.delete_webhook()
                logger.info("Webhook удалён.")
            except Exception:
                pass
            try:
                await bot.session.close()
            except Exception:
                pass

        # AppRunner.setup() сам вызывает on_startup — не дублировать вручную!
        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)

    # ── Веб-сервер ────────────────────────────────────────────────────────────
    runner = web.AppRunner(app)
    await runner.setup()          # ← здесь вызываются on_startup хуки
    port = settings.port
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("Веб-сервер запущен на порту %d.", port)

    # ── Фоновые задачи ────────────────────────────────────────────────────────
    tasks: list[asyncio.Task] = []

    from app.proxy.pipeline import proxy_updater_worker, load_initial_cache

    # Грузим последние рабочие прокси из БД сразу, не ожидая первого цикла (5–10 мин).
    # Это позволяет боту и API сразу отдавать данные после перезапуска.
    if repo is not None:
        await load_initial_cache(repo)

    tasks.append(asyncio.create_task(proxy_updater_worker(repo=repo)))
    if repo is not None or user_repo is not None:
        tasks.append(asyncio.create_task(db_maintenance_worker(user_repo, repo)))

    if bot and dp and not use_webhook:
        tasks.append(asyncio.create_task(
            dp.start_polling(bot, drop_pending_updates=True)
        ))

    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await runner.cleanup()


def run() -> None:
    asyncio.run(main())
