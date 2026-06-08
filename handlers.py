from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest
import worker
import time
import logging
from db import get_live_proxies, mark_dead, get_proxy_by_id

router = Router()


@router.message(Command("start"))
async def cmd_start(message):
    """Обработчик команды /start - приветствие пользователя"""
    text = (
        "👋 **Добро пожаловать в Anti-DPI Proxy Bot!**\n\n"
        "Я — умный алгоритм, который сканирует каналы и оценивает способность прокси "
        "обходить современные блокировки ТСПУ.\n\n"
        "🚀 Нажми /proxy, чтобы получить топ-5 лучших серверов прямо сейчас.\n\n"
        "💡 Если какой-то прокси не работает, нажми кнопку «❌ Не работает» под ним. "
        "Я точечно заменю его на новый рабочий вариант!"
    )
    await message.answer(text, parse_mode="Markdown")


@router.message(Command("proxy"))
async def cmd_proxy(message):
    """Обработчик команды /proxy - отправить топ-5 лучших прокси"""
    # Получаем активные прокси из базы данных
    active_proxies = await get_live_proxies(limit=5)
    # Фильтруем заблокированные пользователем прокси
    display_proxies = [p for p in active_proxies if p['id'] not in worker.banned_proxies][:5]

    if not display_proxies:
        return await message.answer(
            "🔍 База стабильных прокси обновляется. Воркер ищет новые сервера, попробуйте через пару минут!")

    # Собираем кнопки с прокси и кнопками отчёта
    kb = []
    for p in display_proxies:
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
        kb.append([InlineKeyboardButton(text=f"🟢 {p['ping']}мс | ТСПУ: {p['tspu']}%", url=url)])
        kb.append([InlineKeyboardButton(text="❌ Не работает (Заменить)", callback_data=f"rep:{p['id']}")])

    await message.answer(
        "⚡️ **Топ стабильных прокси на данный момент:**\n"
        "Выбирай любой. Если не грузит — смело жми кнопку замены.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=kb),
        parse_mode="Markdown"
    )


@router.callback_query(F.data.startswith("rep:"))
async def report(callback):
    """Обработчик нажатия кнопки «Не работает» - заменить прокси"""
    target_pid = callback.data.split(":")[1]

    # Заносим прокси в чёрный список на 2 часа
    if target_pid not in worker.banned_proxies:
        worker.banned_proxies[target_pid] = time.time() + 7200

    # Отмечаем прокси как неработающий в БД
    await mark_dead(target_pid, 7200)

    # Получаем текущую клавиатуру сообщения
    old_markup = callback.message.reply_markup
    if not old_markup:
        return await callback.answer("Ошибка: клавиатура устарела.", show_alert=True)

    # Собираем ID всех прокси на экране
    current_pids = []
    for row in old_markup.inline_keyboard:
        for btn in row:
            if btn.callback_data and btn.callback_data.startswith("rep:"):
                current_pids.append(btn.callback_data.split(":")[1])

    # Ищем новый рабочий прокси из резерва
    new_proxy = None
    all_proxies = await get_live_proxies(limit=100)
    for p in all_proxies:
        if p['id'] not in worker.banned_proxies and p['id'] not in current_pids:
            new_proxy = p
            break

    # Пересобираем клавиатуру с заменой неработающего прокси
    new_keyboard = []
    for i in range(0, len(old_markup.inline_keyboard), 2):
        row1 = old_markup.inline_keyboard[i]

        if i + 1 < len(old_markup.inline_keyboard):
            row2 = old_markup.inline_keyboard[i + 1]
        else:
            new_keyboard.append(row1)
            continue

        btn_rep = row2[0]

        # Если это строка, которую нажал пользователь
        if btn_rep.callback_data == f"rep:{target_pid}":
            if new_proxy:
                # Заменяем на новый рабочий прокси
                url = f"tg://proxy?server={new_proxy['server']}&port={new_proxy['port']}&secret={new_proxy['secret']}"
                new_row1 = [InlineKeyboardButton(text=f"🟢 {new_proxy['ping']}мс | ТСПУ: {new_proxy['tspu']}%", url=url)]
                new_row2 = [
                    InlineKeyboardButton(text="❌ Не работает (Заменить)", callback_data=f"rep:{new_proxy['id']}")]
                new_keyboard.append(new_row1)
                new_keyboard.append(new_row2)
            # Если замены нет, просто удаляем неработающий прокси
        else:
            # Остальные прокси оставляем на месте
            new_keyboard.append(row1)
            new_keyboard.append(row2)

    try:
        # Обновляем сообщение с новой клавиатурой
        await callback.message.edit_reply_markup(reply_markup=InlineKeyboardMarkup(inline_keyboard=new_keyboard))

        if new_proxy:
            await callback.answer("✅ Замена произведена!", show_alert=False)
        else:
            await callback.answer("Прокси удален. Резервных серверов пока нет.", show_alert=True)

    except TelegramBadRequest:
        # Перехватываем двойной клик
        await callback.answer("Этот прокси уже заменен.", show_alert=False)
    except Exception as e:
        logging.error(f"UI update error: {e}")
        await callback.answer("Ошибка обновления интерфейса.", show_alert=False)
