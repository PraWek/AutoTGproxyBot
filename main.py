import asyncio
import re
import time
import os
from aiohttp import web, ClientSession
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest

# Вставляем токен или берем из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "8878625564:AAGIOedrNil1KjzDRVg_VVHqnsxnpTpszA4")

# Каналы для парсинга (без @)
CHANNELS = ["ProxyMTProto", "MTProto_Proxy", "proxymtproto_ru"]

# Регулярное выражение для поиска ссылок.
# Учитываем, что в HTML символы '&' могут превращаться в '&amp;'
PROXY_REGEX = r"tg://proxy\?server=([^&\"]+)&(?:amp;)?port=([0-9]+)&(?:amp;)?secret=([^&\"\s<]+)"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


async def fetch_html(session: ClientSession, channel: str) -> str:
    """Загружает HTML-код публичного канала."""
    url = f"https://t.me/s/{channel}"
    try:
        async with session.get(url, timeout=5) as response:
            return await response.text()
    except Exception:
        return ""


async def check_proxy(server: str, port: str, secret: str, timeout=1.5):
    """Проверяет TCP-соединение и замеряет пинг."""
    start_time = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, int(port)),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()

        ping = int((time.time() - start_time) * 1000)
        return {"server": server, "port": port, "secret": secret, "ping": ping}
    except Exception:
        return None


async def get_best_proxies(limit=5):
    """Собирает прокси с каналов, проверяет их и возвращает лучшие."""
    html_contents = []
    async with ClientSession() as session:
        tasks = [fetch_html(session, ch) for ch in CHANNELS]
        html_contents = await asyncio.gather(*tasks)

    proxies_found = set()
    for html in html_contents:
        matches = re.findall(PROXY_REGEX, html)
        for match in matches:
            proxies_found.add(match)  # (server, port, secret)

    # Запускаем проверку всех найденных прокси одновременно
    check_tasks = [check_proxy(s, p, sec) for s, p, sec in proxies_found]
    results = await asyncio.gather(*check_tasks)

    # Фильтруем мертвые и сортируем по пингу
    good_proxies = [r for r in results if r is not None]
    good_proxies.sort(key=lambda x: x['ping'])

    return good_proxies[:limit]


@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "Привет! Я бот для поиска рабочих MTProto прокси.\n"
        "Отправь /proxy или нажми на кнопку в меню, чтобы получить свежие быстрые прокси."
    )


@dp.message(Command("proxy"))
async def cmd_proxy(message: types.Message):
    msg = await message.answer("🔍 Паршу каналы и проверяю пинг... Это займет пару секунд.")

    best_proxies = await get_best_proxies(limit=5)

    if not best_proxies:
        await msg.edit_text("❌ Не удалось найти живые прокси. Попробуй позже.")
        return

    # Создаем клавиатуру с кнопками-ссылками
    keyboard = []
    for p in best_proxies:
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
        btn_text = f"🟢 Подключить ({p['ping']} мс)"
        keyboard.append([InlineKeyboardButton(text=btn_text, url=url)])

    reply_markup = InlineKeyboardMarkup(inline_keyboard=keyboard)

    text = f"✅ Найдено {len(best_proxies)} быстрых прокси.\nВыбирай любой:"

    try:
        await msg.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest:
        await message.answer(text, reply_markup=reply_markup)


# --- ФЕЙКОВЫЙ ВЕБ-СЕРВЕР ДЛЯ БЕСПЛАТНОГО ХОСТИНГА ---
# Бесплатные сервисы (вроде Render) требуют, чтобы приложение слушало web-порт.
async def health_check(request):
    return web.Response(text="Bot is running!")


async def run_web_server():
    app = web.Application()
    app.router.add_get('/', health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    print(f"Web server started on port {port}")


async def main():
    # Запускаем бота и веб-сервер параллельно
    await asyncio.gather(
        dp.start_polling(bot),
        run_web_server()
    )


if __name__ == "__main__":
    asyncio.run(main())