import asyncio
import re
import time
import os
import hashlib
from aiohttp import web, ClientSession
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest

BOT_TOKEN = os.getenv("BOT_TOKEN", "8878625564:AAGIOedrNil1KjzDRVg_VVHqnsxnpTpszA4")
CHANNELS = ["ProxyMTProto", "MTProto_Proxy", "proxymtproto_ru"]
PROXY_REGEX = r"tg://proxy\?server=([^&\"]+)&(?:amp;)?port=([0-9]+)&(?:amp;)?secret=([^&\"\s<]+)"

# Настройки краудсорсинга
REPORT_THRESHOLD = 1  # Сколько уникальных жалоб нужно для бана прокси
BAN_DURATION = 30 * 60  # Время бана в секундах (30 минут)

# Хранилища состояния (в оперативной памяти)
# proxy_id -> {"server": str, "port": str, "secret": str}
proxy_cache = {}

# proxy_id -> set(user_id1, user_id2, ...)
proxy_reports = {}

# proxy_id -> timestamp (до какого времени забанен)
banned_proxies = {}

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


def generate_proxy_id(server: str, port: str) -> str:
    """Генерирует короткий уникальный ID для прокси (нужен для callback_data)."""
    data = f"{server}:{port}".encode('utf-8')
    return hashlib.md5(data).hexdigest()[:8]


def clean_expired_bans():
    """Очищает устаревшие баны, чтобы не раздувать память."""
    now = time.time()
    expired = [pid for pid, expire_time in banned_proxies.items() if now > expire_time]
    for pid in expired:
        del banned_proxies[pid]
        if pid in proxy_reports:
            del proxy_reports[pid]


async def fetch_html(session: ClientSession, channel: str) -> str:
    url = f"https://t.me/s/{channel}"
    try:
        async with session.get(url, timeout=5) as response:
            return await response.text()
    except Exception:
        return ""


async def check_proxy(server: str, port: str, secret: str, timeout=1.0):
    """Строгая проверка TCP + эмуляция передачи данных."""
    pid = generate_proxy_id(server, port)

    # Сразу отсекаем забаненные коллективным разумом прокси
    if pid in banned_proxies and time.time() < banned_proxies[pid]:
        return None

    start_time = time.time()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, int(port)),
            timeout=timeout
        )
        # Отправляем пустой байт, чтобы отсеять фейковые открытые порты
        writer.write(b'\x00')
        await writer.drain()
        await asyncio.sleep(0.05)

        ping = int((time.time() - start_time) * 1000)

        # Сохраняем в кэш для callback-кнопок
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


async def get_best_proxies(limit=5):
    clean_expired_bans()

    html_contents = []
    async with ClientSession() as session:
        tasks = [fetch_html(session, ch) for ch in CHANNELS]
        html_contents = await asyncio.gather(*tasks)

    proxies_found = set()
    for html in html_contents:
        matches = re.findall(PROXY_REGEX, html)
        for match in matches:
            proxies_found.add(match)

    check_tasks = [check_proxy(s, p, sec) for s, p, sec in proxies_found]
    results = await asyncio.gather(*check_tasks)

    good_proxies = [r for r in results if r is not None]
    good_proxies.sort(key=lambda x: x['ping'])

    return good_proxies[:limit]


@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "Привет! Я бот для поиска рабочих MTProto прокси.\n"
        "Жми /proxy, чтобы получить свежие сервера.\n\n"
        "💡 *Важно:* Если прокси не подключается, нажми кнопку «Не работает в РФ». "
        "Так ты поможешь другим пользователям не натыкаться на заблокированные адреса.",
        parse_mode="Markdown"
    )


@dp.message(Command("proxy"))
async def cmd_proxy(message: types.Message):
    msg = await message.answer("🔍 Собираю прокси и проверяю доступность...")

    best_proxies = await get_best_proxies(limit=5)

    if not best_proxies:
        await msg.edit_text("❌ Все найденные прокси сейчас заблокированы или недоступны. Попробуй через 5 минут.")
        return

    keyboard = []
    for p in best_proxies:
        pid = p['id']
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"

        # Кнопка подключения
        connect_btn = InlineKeyboardButton(text=f"🟢 {p['ping']} мс | Подключить", url=url)
        # Кнопка репорта (в callback_data передаем 'report:ID')
        report_btn = InlineKeyboardButton(text="❌ Не работает в РФ", callback_data=f"report:{pid}")

        keyboard.append([connect_btn])
        keyboard.append([report_btn])

    reply_markup = InlineKeyboardMarkup(inline_keyboard=keyboard)
    text = f"✅ Найдено {len(best_proxies)} прокси.\n\nПожалуйста, отмечайте неработающие, это помогает системе обучаться!"

    try:
        await msg.edit_text(text, reply_markup=reply_markup)
    except TelegramBadRequest:
        await message.answer(text, reply_markup=reply_markup)


@dp.callback_query(F.data.startswith("report:"))
async def process_report(callback: types.CallbackQuery):
    pid = callback.data.split(":")[1]
    user_id = callback.from_user.id

    # Если прокси уже забанен, просто уведомляем
    if pid in banned_proxies and time.time() < banned_proxies[pid]:
        await callback.answer("Этот прокси уже удален из выдачи благодаря жалобам!", show_alert=True)
        return

    if pid not in proxy_reports:
        proxy_reports[pid] = set()

    if user_id in proxy_reports[pid]:
        await callback.answer("Вы уже жаловались на этот прокси.", show_alert=False)
        return

    # Добавляем голос пользователя
    proxy_reports[pid].add(user_id)
    current_reports = len(proxy_reports[pid])

    if current_reports >= REPORT_THRESHOLD:
        # Баним прокси
        banned_proxies[pid] = time.time() + BAN_DURATION
        await callback.answer("Спасибо! Прокси набрал критическое число жалоб и удален из выдачи на 30 минут.",
                              show_alert=True)
    else:
        # Еще нужны голоса
        remaining = REPORT_THRESHOLD - current_reports
        await callback.answer(f"Жалоба принята! Осталось жалоб до удаления: {remaining}", show_alert=False)


# --- ВЕБ-СЕРВЕР ДЛЯ RENDER ---
async def health_check(request):
    return web.Response(text="Crowdsource Bot is running!")


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
    await asyncio.gather(
        dp.start_polling(bot),
        run_web_server()
    )


if __name__ == "__main__":
    asyncio.run(main())