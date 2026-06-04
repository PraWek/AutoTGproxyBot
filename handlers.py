from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest
import worker
import time
import logging

router = Router()


@router.message(Command("start"))
async def cmd_start(message):
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
    # Берем чистые прокси из кэша
    active_proxies = [p for p in worker.CACHED_BEST_PROXIES if p['id'] not in worker.banned_proxies]
    display_proxies = active_proxies[:5]

    if not display_proxies:
        return await message.answer(
            "🔍 База стабильных прокси обновляется. Воркер ищет новые сервера, попробуйте через пару минут!")

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
    target_pid = callback.data.split(":")[1]

    # 1. Заносим прокси в блеклист на 2 часа
    if target_pid not in worker.banned_proxies:
        worker.banned_proxies[target_pid] = time.time() + 7200

    # 2. Получаем текущую клавиатуру сообщения, которую видит юзер
    old_markup = callback.message.reply_markup
    if not old_markup:
        return await callback.answer("Ошибка: клавиатура устарела.", show_alert=True)

    # 3. Собираем ID всех прокси, которые СЕЙЧАС отображаются на экране
    current_pids = []
    for row in old_markup.inline_keyboard:
        for btn in row:
            if btn.callback_data and btn.callback_data.startswith("rep:"):
                current_pids.append(btn.callback_data.split(":")[1])

    # 4. Ищем один новый прокси из резерва, которого еще НЕТ на экране
    new_proxy = None
    for p in worker.CACHED_BEST_PROXIES:
        if p['id'] not in worker.banned_proxies and p['id'] not in current_pids:
            new_proxy = p
            break

    # 5. Точечно пересобираем клавиатуру (меняем только 2 нужных ряда)
    new_keyboard = []
    for i in range(0, len(old_markup.inline_keyboard), 2):
        row1 = old_markup.inline_keyboard[i]

        # Проверка границ на случай аномалий в разметке
        if i + 1 < len(old_markup.inline_keyboard):
            row2 = old_markup.inline_keyboard[i + 1]
        else:
            new_keyboard.append(row1)
            continue

        btn_rep = row2[0]

        # Нашли прокси, на который нажал юзер
        if btn_rep.callback_data == f"rep:{target_pid}":
            if new_proxy:  # Если есть замена
                url = f"tg://proxy?server={new_proxy['server']}&port={new_proxy['port']}&secret={new_proxy['secret']}"
                new_row1 = [InlineKeyboardButton(text=f"🟢 {new_proxy['ping']}мс | ТСПУ: {new_proxy['tspu']}%", url=url)]
                new_row2 = [
                    InlineKeyboardButton(text="❌ Не работает (Заменить)", callback_data=f"rep:{new_proxy['id']}")]
                new_keyboard.append(new_row1)
                new_keyboard.append(new_row2)
            else:
                # Если резерв пуст, просто не добавляем эти ряды (прокси исчезнет с экрана)
                pass
        else:
            # Чужие прокси оставляем нетронутыми на своих местах!
            new_keyboard.append(row1)
            new_keyboard.append(row2)

    # 6. Обновляем сообщение
    try:
        await callback.message.edit_reply_markup(reply_markup=InlineKeyboardMarkup(inline_keyboard=new_keyboard))

        if new_proxy:
            await callback.answer("✅ Замена произведена!", show_alert=False)
        else:
            await callback.answer("Прокси удален. Резервных серверов пока нет.", show_alert=True)

    except TelegramBadRequest:
        # Изящно перехватываем ошибку двойного клика пользователя
        await callback.answer("Этот прокси уже заменен.", show_alert=False)
    except Exception as e:
        logging.error(f"UI update error: {e}")
        await callback.answer("Ошибка обновления интерфейса.", show_alert=False)