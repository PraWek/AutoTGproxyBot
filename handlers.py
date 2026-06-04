from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
import worker
import time

router = Router()


def build_proxy_keyboard():
    """Собирает клавиатуру, всегда стараясь выдать ровно 5 прокси из резерва."""
    # Отсеиваем забаненные
    active_proxies = [p for p in worker.CACHED_BEST_PROXIES if p['id'] not in worker.banned_proxies]

    # Берем топ-5 из чистых
    display_proxies = active_proxies[:5]

    kb = []
    for p in display_proxies:
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
        kb.append([InlineKeyboardButton(text=f"🟢 {p['ping']}мс | ТСПУ: {p['tspu']}%", url=url)])
        kb.append([InlineKeyboardButton(text="❌ Не работает (Заменить)", callback_data=f"rep:{p['id']}")])

    return InlineKeyboardMarkup(inline_keyboard=kb), len(display_proxies)


@router.message(Command("start"))
async def cmd_start(message):
    text = (
        "👋 **Добро пожаловать в Anti-DPI Proxy Bot!**\n\n"
        "Я — умный алгоритм, который круглосуточно сканирует каналы, проверяет MTProto прокси "
        "и оценивает их способность обходить современные блокировки ТСПУ.\n\n"
        "🚀 Нажми /proxy, чтобы получить топ-5 лучших серверов прямо сейчас.\n\n"
        "💡 **Фишка:** Если какой-то прокси не подключается, просто нажми кнопку «❌ Не работает» под ним. "
        "Я моментально заменю его на новый рабочий вариант!"
    )
    await message.answer(text, parse_mode="Markdown")


@router.message(Command("proxy"))
async def cmd_proxy(message):
    kb, count = build_proxy_keyboard()

    if count == 0:
        return await message.answer(
            "🔍 База стабильных прокси обновляется. Воркер ищет новые сервера, попробуйте через пару минут!")

    await message.answer(
        "⚡️ **Топ стабильных прокси на данный момент:**\n"
        "Выбирай любой. Если не грузит — смело жми кнопку замены.",
        reply_markup=kb,
        parse_mode="Markdown"
    )


@router.callback_query(F.data.startswith("rep:"))
async def report(callback):
    pid = callback.data.split(":")[1]

    # Отправляем плохой прокси в блеклист на 2 часа (7200 сек)
    if pid not in worker.banned_proxies:
        worker.banned_proxies[pid] = time.time() + 7200

    # Генерируем новую клавиатуру с учетом бана (бот подтянет новый прокси из резерва)
    kb, count = build_proxy_keyboard()

    if count == 0:
        await callback.message.edit_text(
            "❌ Все резервные прокси закончились или заблокированы. Ждем следующего цикла проверки...")
    else:
        try:
            await callback.message.edit_reply_markup(reply_markup=kb)
            await callback.answer("✅ Прокси заблокирован! Список моментально пополнен новой заменой.", show_alert=True)
        except Exception:
            # Защита от спама кликами (если клавиатура не изменилась)
            await callback.answer("Этот прокси уже заменен.", show_alert=False)