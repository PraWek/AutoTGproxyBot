from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
import worker, time

router = Router()


@router.message(Command("proxy"))
async def cmd_proxy(message):
    best = [p for p in worker.CACHED_BEST_PROXIES if p['id'] not in worker.banned_proxies]
    if not best: return await message.answer("🔍 Идет поиск, подождите...")

    kb = []
    for p in best[:5]:
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
        kb.append([InlineKeyboardButton(text=f"🟢 {p['ping']}мс | ТСПУ:{p['tspu']}%", url=url)])
        kb.append([InlineKeyboardButton(text="❌ Не работает", callback_data=f"rep:{p['id']}")])
    await message.answer("Выбирайте:", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb))


@router.callback_query(F.data.startswith("rep:"))
async def report(callback):
    pid = callback.data.split(":")[1]
    worker.banned_proxies[pid] = time.time() + 3600
    await callback.answer("Принято, прокси скрыт на час.")