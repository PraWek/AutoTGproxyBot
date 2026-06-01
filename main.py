import asyncio
import re
import time
import os
import hashlib
import logging
from aiohttp import web, ClientSession
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest

# Включаем логирование, чтобы видеть работу воркера в панели Render
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "8878625564:AAGIOedrNil1KjzDRVg_VVHqnsxnpTpszA4")

# 1. СУЩЕСТВЕННО РАСШИРЕННЫЙ СПИСОК КАНАЛОВ (добавлены крупные агрегаторы)
CHANNELS = [
    "ProxyMTProto", "MTProto_Proxy", "proxymtproto_ru",
    "VipProxyMTProto", "TelMTProtoProxy", "Mypromtproto",
    "PinkMTProto", "falconProxy", "Daily_Proxy"
]

PROXY_REGEX = r"tg://proxy\?server=([^&\"]+)&(?:amp;)?port=([0-9]+)&(?:amp;)?secret=([^&\"\s<]+)"

# Параметры таймингов
CACHE_UPDATE_INTERVAL = 180  # Обновлять кэш раз в 3 минуты (180 сек)
REPORT_THRESHOLD = 2  # Жалоб для бана
BAN_DURATION = 45 * 60  # Бан на 45 минут

# --- ГЛОБАЛЬНЫЕ ХРАНИЛИЩА СОСТОЯНИЯ (КЭШ) ---
CACHED_BEST_PROXIES = []  # Здесь всегда лежат топ-5 проверенных и чистых прокси
proxy_cache = {}  # Общий кэш pid -> proxy_data (для обработки репортов)
proxy_reports = {}  # pid -> set(user_ids)
banned_proxies = {}  # pid -> timestamp бана

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


def generate_proxy_id(server: str, port: str) -> str:
    data = f"{server}:{port}".encode('utf-8')
    return hashlib.md5(data).hexdigest()[:8]


def clean_expired_bans():
    now = time.time()
    expired = [pid for pid, expire_time in banned_proxies.items() if now > expire_time]
    for pid in expired:
        del banned_proxies[pid]
        if pid in proxy_reports:
            del proxy_reports[pid]
    if expired:
        logger.info(f"Очищено устаревших банов: {len(expired)}")


async def fetch_html(session: ClientSession, channel: str) -> str:
    url = f"https://t.me/s/{channel}"
    try:
        async with session.get(url, timeout=8) as response:
            return await response.text()
    except Exception as e:
        logger.error(f"Ошибка парсинга канала {channel}: {e}")
        return ""


async def check_proxy(server: str, port: str, secret: str, timeout=1.0):
    pid = generate_proxy_id(server, port)

    if pid in banned_proxies and time.time() < banned_proxies[pid]:
        return None

    start_time = time.time()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, int(port)),
            timeout=timeout
        )
        writer.write(b'\x00')
        await writer.drain()
        await asyncio.sleep(0.05)

        ping = int((time.time() - start_time) * 1000)

        # Сохраняем в глобальный кэш для callback-кнопок (он живет долго)
        proxy_cache[pid] = {"server": server, "port": port, "secret": secret}

        return {"id": pid, "server": server, "port": port, "secret": secret, "ping": ping}
    except Exception:
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# --- 2. ФОНОВЫЙ АЛГОРИТМ ПАРСИНГА И ОБНОВЛЕНИЯ КЭША ---
async def proxy_updater_worker():
    """Фоновый воркер, который собирает и фильтрует прокси независимо от юзеров."""
    global CACHED_BEST_PROXIES

    logger.info("Фоновый воркер парсинга успешно запущен.")

    while True:
        try:
            logger.info("Старт очередной итерации парсинга...")
            clean_expired_bans()

            html_contents = []
            async with ClientSession() as session:
                tasks = [fetch_html(session, ch) for ch in CHANNELS]
                html_contents = await asyncio.gather(*tasks)

            # Собираем все прокси со всех страниц в один set
            proxies_found = set()
            for html in html_contents:
                matches = re.findall(PROXY_REGEX, html)
                for match in matches:
                    proxies_found.add(match)

            logger.info(f"Всего найдено уникальных прокси в HTML: {len(proxies_found)}")

            # Запускаем массовую асинхронную проверку
            check_tasks = [check_proxy(s, p, sec) for s, p, sec in proxies_found]
            results = await asyncio.gather(*check_tasks)

            # Фильтруем живые, отсекаем пустые результаты
            good_proxies = [r for r in results if r is not None]
            good_proxies.sort(key=lambda x: x['ping'])

            # Записываем топ-15 лучших прокси в глобальный кэш
            CACHED_BEST_PROXIES = good_proxies[:15]
            logger.info(f"Кэш успешно обновлен. Доступно живых прокси в пуле: {len(CACHED_BEST_PROXIES)}")

        except Exception as e:
            logger.error(f"Критическая ошибка в фоновом воркере: {e}")

        # Засыпаем на N минут до следующего парсинга
        await asyncio.sleep(CACHE_UPDATE_INTERVAL)


# --- ХЕНДЛЕРЫ БОТА ---

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "Привет! Я бот с мгновенным поиском MTProto прокси.\n"
        "Жми /proxy и рабочие сервера появятся **секундно** благодаря кэшированию!",
        parse_mode="Markdown"
    )


@dp.message(Command("proxy"))
async def cmd_proxy(message: types.Message):
    now = time.time()
    # Фильтруем кэш «на лету» на случай, если какой-то прокси забанили репортами ПОСЛЕ обновления кэша
    active_proxies = [
        p for p in CACHED_BEST_PROXIES
        if p['id'] not in banned_proxies or now > banned_proxies[p['id']]
    ]

    # Берем топ-5 из доступных в кэше
    display_proxies = active_proxies[:5]

    if not display_proxies:
        await message.answer(
            "❌ Кэш пуст или все прокси заблокированы. Фоновый воркер уже ищет новые, подожди пару минут!")
        return

    keyboard = []
    for p in display_proxies:
        pid = p['id']
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"

        connect_btn = InlineKeyboardButton(text=f"🟢 {p['ping']} мс | Подключить", url=url)
        report_btn = InlineKeyboardButton(text="❌ Не работает в РФ", callback_data=f"report:{pid}")

        keyboard.append([connect_btn])
        keyboard.append([report_btn])

    reply_markup = InlineKeyboardMarkup(inline_keyboard=keyboard)
    await message.answer("🚀 *Мгновенный ответ из кэша:*\nВыбирай любой прокси. Если не работает — жми кнопку репорта.",
                         reply_markup=reply_markup, parse_mode="Markdown")


@dp.callback_query(F.data.startswith("report:"))
async def process_report(callback: types.CallbackQuery):
    pid = callback.data.split(":")[1]
    user_id = callback.from_user.id
    global CACHED_BEST_PROXIES

    if pid in banned_proxies and time.time() < banned_proxies[pid]:
        await callback.answer("Этот прокси уже удален из выдачи системы!", show_alert=True)
        return

    if pid not in proxy_reports:
        proxy_reports[pid] = set()

    if user_id in proxy_reports[pid]:
        await callback.answer("Вы уже отправляли репорт.", show_alert=False)
        return

    proxy_reports[pid].add(user_id)

    if len(proxy_reports[pid]) >= REPORT_THRESHOLD:
        banned_proxies[pid] = time.time() + BAN_DURATION

        # Сразу выкидываем забаненный прокси из текущего кэша выдачи, чтобы другие его не видели
        CACHED_BEST_PROXIES = [p for p in CACHED_BEST_PROXIES if p['id'] != pid]

        await callback.answer("Спасибо! Прокси заблокирован коллективным разумом и удален из кэша.", show_alert=True)

        # Пытаемся отредактировать сообщение пользователя, убрав мертвый прокси
        try:
            await callback.message.edit_text(
                "ℹ️ Один из прокси был удален из-за жалоб. Запросите свежий список через /proxy")
        except TelegramBadRequest:
            pass
    else:
        await callback.answer("Репорт принят. Если еще один человек подтвердит — прокси удалится.", show_alert=False)


# --- ОРКЕСТРАЦИЯ ЗАПУСКА ПРИЛОЖЕНИЯ ---

async def health_check(request):
    return web.Response(text="Bot and cache worker are active!")


async def run_web_server():
    app = web.Application()
    app.router.add_get('/', health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()


async def main():
    # Запускаем Long Polling бота, Веб-сервер Render И Фоновый воркер одновременно!
    await asyncio.gather(
        dp.start_polling(bot),
        run_web_server(),
        proxy_updater_worker()  # Наш вечный двигатель парсинга
    )


if __name__ == "__main__":
    asyncio.run(main())