"""
handlers.py — Обработчики Telegram-бота (aiogram 3).

Команды:
  /start     — приветствие
  /proxy     — список и персональный подбор прокси
  /subscribe — бесплатный тариф и переход к прокси
  /account   — информация об аккаунте
"""
from __future__ import annotations

import logging
import asyncio
import time

from aiogram import F, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from app.proxy import pipeline as worker
from app.proxy.catalog import (
    available_proxies,
    feedback,
    filter_proxies as catalog_filter_proxies,
    secret_type,
)
from app.proxy.selector import select_first_reachable
from app.proxy.personalization import (
    ClientProfile,
    normalize_client_profile,
    personalize_proxies,
)

logger = logging.getLogger(__name__)
router = Router()

# ──────────────────────────────────────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────────────────────────────────────

_user_repo    = None
_proxy_repo   = None
_site_url: str  = ""


def setup_handlers(
    user_repo,
    proxy_repo=None,
    site_url: str = "",
) -> None:
    global _user_repo, _proxy_repo, _site_url
    _user_repo   = user_repo
    _proxy_repo  = proxy_repo
    _site_url    = site_url.rstrip("/")


# ──────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────────────────────────────────────

def _secret_type_label(secret: str) -> str:
    return secret_type(secret)


def _proxy_button_text(p: dict) -> str:
    stype     = _secret_type_label(p["secret"])
    type_label = {"FakeTLS": "Рекомендуемый", "RandPad": "Совместимый", "Plain": "Обычный"}.get(stype, "Обычный")
    stability = p.get("stability", 100)
    icon      = "🟢" if stability == 100 else "🟡"
    score     = p.get("transport_score", p.get("tspu_score", p.get("tspu", 0))) or 0
    ru_score  = p.get("ru_reachability_score", 50)
    ru_total  = p.get("ru_feedback_total", 0)
    ru_label  = f"Люди {ru_score}/100" if ru_total else "Люди: нет оценок"
    admin_mark = "⭐ " if p.get("admin_recommended") else ""
    return f"{admin_mark}{icon} {ru_label} | Сервер {score}/100 | {type_label}"


async def _save_proxy_feedback(proxy_id: str, user_id: int, works: bool) -> None:
    if works:
        feedback.report_success(proxy_id, user_id)
    else:
        feedback.report_failure(proxy_id, user_id)
    if _proxy_repo is not None:
        try:
            await _proxy_repo.record_feedback(proxy_id, user_id, works)
        except Exception as exc:
            logger.warning("bot feedback persistence failed: %s", exc)


async def _send_free_access(message: Message) -> None:
    """Показывает фиктивный тариф 0 ₽ без внешней платёжной системы."""
    if _site_url:
        button = InlineKeyboardButton(
            text="Оплатить 0 ₽ — открыть прокси",
            url=f"{_site_url}/connect_proxy",
        )
    else:
        button = InlineKeyboardButton(
            text="Оплатить 0 ₽ — открыть прокси",
            callback_data="free_access",
        )
    await message.answer(
        "💎 **Подписка Proxy Bot**\n\n"
        "Стоимость: **0 ₽**. Списание денег и привязка карты не требуются.\n\n"
        "Нажмите кнопку — сразу откроется панель с прокси.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[button]]),
    )


# ──────────────────────────────────────────────────────────────────────────────
# /start
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("start"))
async def cmd_start(message: Message, command: CommandObject) -> None:
    uid        = message.from_user.id
    args       = command.args or ""
    tg_user    = message.from_user
    tg_username  = (tg_user.username or "").strip()
    first_name   = (tg_user.first_name or "").strip()
    last_name    = (tg_user.last_name or "").strip()

    # Регистрируем / обновляем профиль; account_login = TG username
    if _user_repo is not None:
        await _user_repo.upsert_user(
            uid,
            username=tg_username,
            first_name=first_name,
            last_name=last_name,
        )

    # ── Deeplink: /start subscribe — бесплатный тариф ───────────────────────
    if args == "subscribe":
        await _send_free_access(message)
        return

    # ── Первая регистрация: генерируем пароль и показываем credentials ────────
    if _user_repo is not None:
        login, plain_pw = await _user_repo.ensure_credentials(uid)
        if plain_pw:
            site_ref = f"\n🌐 Сайт: {_site_url}" if _site_url else ""
            await message.answer(
                f"👋 **Добро пожаловать в Proxy Bot!**\n\n"
                f"🎉 Ваш аккаунт создан:\n\n"
                f"Логин: `{login}`\n"
                f"Пароль: `{plain_pw}`\n\n"
                f"⚠️ *Сохраните пароль — он показывается только один раз!*\n"
                f"Войти в личный кабинет можно по логину и этому паролю.{site_ref}\n\n"
                "💎 /subscribe — бесплатный доступ (0 ₽)\n"
                "🚀 /proxy     — подобрать прокси\n"
                "👤 /account   — мой аккаунт",
                parse_mode="Markdown",
            )
            return

    # ── Обычный /start (пользователь уже зарегистрирован) ────────────────────
    site_ref = f"\n🌐 Сайт: {_site_url}" if _site_url else ""
    text = (
        "👋 **Proxy Bot для Telegram**\n\n"
        "Я собираю публичные MTProto-прокси, проверяю их доступность и "
        "помогаю быстро заменить неработающий адрес. Результат зависит от вашего оператора.\n\n"
        "💎 /subscribe — бесплатный доступ (0 ₽)\n"
        "🚀 /proxy     — топ-10 прокси\n"
        f"👤 /account   — мой аккаунт{site_ref}\n\n"
        "💡 Нажми «❌ Не работает», чтобы скрыть этот вариант и получить следующий."
    )
    await message.answer(text, parse_mode="Markdown")


# ──────────────────────────────────────────────────────────────────────────────
# /account — информация об аккаунте
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("account"))
async def cmd_account(message: Message) -> None:
    uid = message.from_user.id

    if _user_repo is None:
        await message.answer("ℹ️ База данных не настроена.")
        return

    user = await _user_repo.get_user(uid)
    if not user:
        await message.answer(
            "👤 Аккаунт не найден.\n"
            "Используй /start чтобы зарегистрироваться."
        )
        return

    login   = user.get("account_login") or f"user{uid}"
    tg_name = user.get("username", "")
    sub_line = "✅ Доступ: бесплатный тариф 0 ₽"

    tg_line = f"TG: @{tg_name}\n" if tg_name else ""
    site_ref = f"\n🌐 Сайт: {_site_url}" if _site_url else ""

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Получить новый пароль", callback_data="reset_pw")],
        [InlineKeyboardButton(text="🚀 Открыть прокси", callback_data="free_access")],
    ])

    await message.answer(
        f"👤 **Ваш аккаунт**\n\n"
        f"{tg_line}"
        f"Логин: `{login}`\n"
        f"{sub_line}\n\n"
        f"Пароль хранится только в виде хеша — нажми кнопку ниже, "
        f"чтобы сбросить и узнать новый.{site_ref}",
        parse_mode="Markdown",
        reply_markup=kb,
    )


# ──────────────────────────────────────────────────────────────────────────────
# /link — привязка существующего аккаунта к Telegram
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("link"))
async def cmd_link(message: Message, command: CommandObject) -> None:
    """
    /link <логин> <пароль>
    Привязывает существующий web-аккаунт к текущему Telegram ID.
    """
    uid  = message.from_user.id
    args = (command.args or "").strip().split(maxsplit=1)

    if len(args) < 2:
        await message.answer(
            "🔗 **Привязка существующего аккаунта**\n\n"
            "Используй команду:\n"
            "`/link ваш_логин ваш_пароль`\n\n"
            "Это свяжет аккаунт, созданный на сайте, с вашим Telegram.",
            parse_mode="Markdown",
        )
        return

    if _user_repo is None:
        await message.answer("⚠️ База данных недоступна. Попробуй позже.")
        return

    # Если у пользователя уже есть аккаунт с паролем — отклоняем
    existing = await _user_repo.get_user(uid)
    if existing and existing.get("password_hash"):
        login = existing.get("account_login", "")
        await message.answer(
            f"❌ У тебя уже есть аккаунт (`{login}`).\n"
            f"Используй /account для просмотра данных.",
            parse_mode="Markdown",
        )
        return

    account_login = args[0]
    plain_password = args[1]
    tg_user = message.from_user

    ok = await _user_repo.link_tg_to_existing(
        uid,
        account_login,
        plain_password,
        username=(tg_user.username or "").strip(),
        first_name=(tg_user.first_name or "").strip(),
        last_name=(tg_user.last_name or "").strip(),
    )

    if not ok:
        await message.answer("❌ Неверный логин или пароль. Проверь данные и попробуй снова.")
        return

    site_ref = f"\n🌐 {_site_url}" if _site_url else ""
    await message.answer(
        f"✅ **Аккаунт успешно привязан!**\n\n"
        f"Логин: `{account_login}`\n\n"
        f"Теперь используй /proxy для прокси. Доступ бесплатный.{site_ref}",
        parse_mode="Markdown",
    )
    logger.info("cmd_link: telegram_id=%d linked to account=%s", uid, account_login)


@router.callback_query(F.data == "reset_pw")
async def cb_reset_password(callback: CallbackQuery) -> None:
    uid = callback.from_user.id

    if _user_repo is None:
        await callback.answer("База данных недоступна.", show_alert=True)
        return

    user = await _user_repo.get_user(uid)
    if not user:
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    from app.db.schema import _gen_password
    new_pw = _gen_password(12)
    login  = user.get("account_login") or f"user{uid}"
    await _user_repo.set_credentials(uid, login, new_pw)

    site_ref = f"\n🌐 {_site_url}" if _site_url else ""
    await callback.message.answer(
        f"🔑 **Новый пароль установлен:**\n\n"
        f"Логин: `{login}`\n"
        f"Пароль: `{new_pw}`\n\n"
        f"Сохраните пароль — он больше не будет показан.{site_ref}",
        parse_mode="Markdown",
    )
    await callback.answer()


# ──────────────────────────────────────────────────────────────────────────────
# /login — показать логин или привязать аккаунт
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("login"))
async def cmd_login(message: Message, command: CommandObject) -> None:
    """
    /login               — показать текущий логин
    /login <л> <п>       — войти в существующий аккаунт (аналог /link)
    """
    uid  = message.from_user.id
    args = (command.args or "").strip().split(maxsplit=1)

    if _user_repo is None:
        await message.answer("⚠️ База данных недоступна.")
        return

    # Если переданы аргументы — пробуем привязать аккаунт
    if len(args) >= 2:
        account_login  = args[0]
        plain_password = args[1]
        tg_user        = message.from_user

        ok = await _user_repo.link_tg_to_existing(
            uid, account_login, plain_password,
            username   = (tg_user.username or "").strip(),
            first_name = (tg_user.first_name or "").strip(),
            last_name  = (tg_user.last_name or "").strip(),
        )
        if not ok:
            await message.answer("❌ Неверный логин или пароль. Проверьте данные.")
            return
        site_ref = f"\n🌐 {_site_url}" if _site_url else ""
        await message.answer(
            f"✅ **Вход выполнен!**\n\n"
            f"Логин: `{account_login}`\n\n"
            f"Используй /proxy для получения прокси.{site_ref}",
            parse_mode="Markdown",
        )
        return

    # Без аргументов — показываем текущий логин
    user = await _user_repo.get_user(uid)
    if not user:
        await message.answer(
            "👤 Аккаунт не найден.\n"
            "Используй /start чтобы зарегистрироваться и получить логин/пароль."
        )
        return

    login    = user.get("account_login") or f"user{uid}"
    site_ref = f"\n🌐 Сайт: {_site_url}" if _site_url else ""
    await message.answer(
        f"👤 **Ваш аккаунт**\n\n"
        f"Логин: `{login}`\n\n"
        f"Пароль хранится только в виде хеша.\n"
        f"Чтобы получить новый пароль — перейди в /account и нажми «Получить новый пароль».{site_ref}\n\n"
        f"Войти на сайт: /login `{login}` `ваш_пароль`",
        parse_mode="Markdown",
    )


# ──────────────────────────────────────────────────────────────────────────────
# /register — создать аккаунт (если уже есть — показать)
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("register"))
async def cmd_register(message: Message) -> None:
    """
    /register — создаёт аккаунт или показывает существующий.
    Аккаунт автоматически создаётся при первом /start,
    поэтому эта команда просто напоминает о нём.
    """
    uid = message.from_user.id

    if _user_repo is None:
        await message.answer("⚠️ База данных недоступна.")
        return

    # Если аккаунт уже есть — напоминаем
    user = await _user_repo.get_user(uid)
    if user and user.get("password_hash"):
        login    = user.get("account_login") or f"user{uid}"
        site_ref = f"\n🌐 {_site_url}" if _site_url else ""
        await message.answer(
            f"✅ У вас уже есть аккаунт!\n\n"
            f"Логин: `{login}`\n\n"
            f"Пароль хранится только в виде хеша.\n"
            f"Нажмите «Получить новый пароль» в /account чтобы узнать его.{site_ref}",
            parse_mode="Markdown",
        )
        return

    # Создаём аккаунт (аналог /start)
    tg_user = message.from_user
    await _user_repo.upsert_user(
        uid,
        username   = (tg_user.username or "").strip(),
        first_name = (tg_user.first_name or "").strip(),
        last_name  = (tg_user.last_name or "").strip(),
    )
    login, plain_pw = await _user_repo.ensure_credentials(uid)
    site_ref = f"\n🌐 {_site_url}" if _site_url else ""

    if plain_pw:
        await message.answer(
            f"🎉 **Аккаунт создан!**\n\n"
            f"Логин: `{login}`\n"
            f"Пароль: `{plain_pw}`\n\n"
            f"⚠️ *Сохраните пароль — он показывается только один раз!*{site_ref}\n\n"
            f"💎 /subscribe — бесплатный тариф\n"
            f"🚀 /proxy     — прокси",
            parse_mode="Markdown",
        )
    else:
        await message.answer(
            "✅ Аккаунт готов. Используй /account для просмотра данных."
        )


# ──────────────────────────────────────────────────────────────────────────────
# /logout — выход (в боте сессий нет, объясняем)
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("logout"))
async def cmd_logout(message: Message) -> None:
    site_ref = f"{_site_url}/logout" if _site_url else "сайта"
    await message.answer(
        f"ℹ️ **Выход из аккаунта**\n\n"
        f"В Telegram-боте сессий нет — бот всегда знает вас по вашему Telegram ID.\n\n"
        f"Если хотите выйти из **веб-кабинета**, перейдите по ссылке:\n"
        f"{site_ref}",
        parse_mode="Markdown",
    )


# Для обратной совместимости: /status → /account
@router.message(Command("status"))
async def cmd_status(message: Message) -> None:
    await cmd_account(message)


# ──────────────────────────────────────────────────────────────────────────────
# /subscribe
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Умный поиск: первый рабочий прокси через TCP-проверку
# ──────────────────────────────────────────────────────────────────────────────

async def _tcp_check_proxy(server: str, port: int, timeout: float = 3.5) -> int | None:
    """TCP-connect к прокси-серверу. Возвращает пинг в мс или None."""
    try:
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )
        ms = int((time.monotonic() - t0) * 1000)
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return ms
    except Exception:
        return None


# Per-user skip-sets: накапливают ID уже проверенных/показанных прокси.
# Очищаются при новом «Найти лучший» (fb:).
_user_skip: dict[int, set[str]] = {}
_user_profiles: dict[int, ClientProfile] = {}


def _user_skip_get(uid: int) -> set[str]:
    return _user_skip.setdefault(uid, set())


def _user_skip_clear(uid: int) -> None:
    _user_skip.pop(uid, None)


def _user_skip_add(uid: int, proxy_id: str) -> None:
    _user_skip.setdefault(uid, set()).add(proxy_id)


def _profile_keyboard(flt: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📱 Телефон · мобильная сеть", callback_data=f"fp:{flt}:mc")],
        [InlineKeyboardButton(text="📱 Телефон · Wi-Fi", callback_data=f"fp:{flt}:mw")],
        [InlineKeyboardButton(text="💻 Компьютер · Wi-Fi/кабель", callback_data=f"fp:{flt}:dw")],
    ])


def _profile_from_code(code: str) -> ClientProfile:
    raw = {
        "device": "desktop" if code.startswith("d") else "mobile",
        "network": "cellular" if code.endswith("c") else "wifi",
        "effective_type": "4g" if code.endswith("c") else "unknown",
        "platform": "telegram",
    }
    return normalize_client_profile(raw)


async def _find_first_working(
    region: str = "all",
    ptype: str = "all",
    sort: str = "recommended",
    skip_ids: set[str] | None = None,
    user_id: int | None = None,
    profile: ClientProfile | None = None,
) -> dict | None:
    """
    Двухфазный батчевый поиск:

    Phase 1 — Итерируем по прокси согласно установленным фильтрам батчами
              по 10. Если батч не прошёл TCP-проверку, пропускаем его
              только в рамках текущего поиска. Так до первого
              рабочего или до исчерпания прокси по фильтру.

    Phase 2 — Если по фильтру все прокси кончились: ищем по
              абсолютно всем прокси (без фильтра), теми же батчами,
              пропуская уже проверенные.

    Порог: TCP-ответ < 350 мс.
    """
    client_profile = profile or ClientProfile()
    primary = personalize_proxies(
        _get_filtered_proxies(region, ptype, sort, limit=300, user_id=user_id),
        client_profile,
        user_id=user_id,
    )
    fallback: list[dict] = []
    if not (region == "all" and ptype == "all"):
        fallback = personalize_proxies(
            _get_filtered_proxies("all", "all", sort, limit=300, user_id=user_id),
            client_profile,
            user_id=user_id,
        )
    selection = await select_first_reachable(
        primary,
        fallback,
        _tcp_check_proxy,
        skip_ids=skip_ids,
        batch_size=10,
        threshold_ms=350,
    )
    if selection.proxy is None:
        return None
    return {**selection.proxy, "real_ms": selection.response_ms}


@router.message(Command("subscribe"))
async def cmd_subscribe(message: Message, command: CommandObject) -> None:
    await _send_free_access(message)


# ──────────────────────────────────────────────────────────────────────────────
# Фильтрация прокси — вспомогательные функции
# ──────────────────────────────────────────────────────────────────────────────

# Кодировка фильтра в 3 символа: [регион][тип][сортировка]
# регион: a=все r=RU e=EU
# тип:    a=все f=FakeTLS d=RandPad p=Plain
# сорт:   u=оценка пользователей v=оценка сервера

_REGION_ENC = {"all": "a", "RU": "r", "EU": "e"}
_REGION_DEC = {"a": "all", "r": "RU", "e": "EU"}
_TYPE_ENC   = {"all": "a", "FakeTLS": "f", "RandPad": "d", "Plain": "p"}
_TYPE_DEC   = {"a": "all", "f": "FakeTLS", "d": "RandPad", "p": "Plain"}
_SORT_ENC   = {
    "recommended": "u", "user_rating": "u",
    "tspu": "v", "server_rating": "v",
}
_SORT_DEC   = {
    "u": "user_rating", "v": "server_rating",
    # Совместимость со старыми сообщениями бота.
    "r": "user_rating", "p": "server_rating",
    "t": "server_rating", "s": "server_rating",
}

_DEFAULT_FILTER = "aau"


def _encode_filter(region: str, ptype: str, sort: str) -> str:
    return (
        _REGION_ENC.get(region, "a")
        + _TYPE_ENC.get(ptype, "a")
        + _SORT_ENC.get(sort, "u")
    )


def _decode_filter(code: str) -> tuple[str, str, str]:
    if len(code) < 3:
        code = _DEFAULT_FILTER
    return (
        _REGION_DEC.get(code[0], "all"),
        _TYPE_DEC.get(code[1], "all"),
        _SORT_DEC.get(code[2], "user_rating"),
    )


def _get_filtered_proxies(
    region: str,
    ptype: str,
    sort: str,
    limit: int = 10,
    user_id: int | None = None,
) -> list[dict]:
    """Возвращает отфильтрованные и отсортированные прокси из кэша."""
    proxies = available_proxies(
        worker.CACHED_BEST_PROXIES,
        worker.banned_proxies,
        user_id=user_id,
    )
    return catalog_filter_proxies(
        proxies, region=region, proxy_type=ptype, sort_by=sort, limit=limit
    )


def _proxies_with_fallback(
    flt: str, region: str, ptype: str, sort: str, limit: int = 10,
    user_id: int | None = None,
) -> tuple[list[dict], str, str, str, str]:
    """Ручной список строго следует выбранным фильтрам, как на сайте."""
    proxies = _get_filtered_proxies(region, ptype, sort, limit, user_id)
    return proxies, flt, region, ptype, ""


def _build_proxy_keyboard(
    proxies: list[dict],
    flt: str,
    region: str,
    ptype: str,
    sort: str,
) -> InlineKeyboardMarkup:
    """Строит inline-клавиатуру с фильтрами и списком прокси."""

    def _btn(label: str, r: str, t: str, s: str) -> InlineKeyboardButton:
        code = _encode_filter(r, t, s)
        marker = "✅ " if code == flt else ""
        return InlineKeyboardButton(
            text=f"{marker}{label}",
            callback_data=f"prx:{code}",
        )

    kb: list[list[InlineKeyboardButton]] = []

    # Строка 1: Регион
    kb.append([
        _btn("🌐 Все",  "all", ptype, sort),
        _btn("🇷🇺 RU", "RU",  ptype, sort),
        _btn("🇪🇺 EU", "EU", ptype, sort),
    ])

    # Строка 2: Тип
    kb.append([
        _btn("Все", region, "all", sort),
        _btn("Рекомендуемый", region, "FakeTLS", sort),
        _btn("Совместимый", region, "RandPad", sort),
        _btn("Обычный", region, "Plain", sort),
    ])

    # Строка 3: Сортировка
    kb.append([
        _btn("👥 Оценка пользователей", region, ptype, "user_rating"),
        _btn("⭐ Оценка сервера", region, ptype, "server_rating"),
    ])

    # Разделитель
    kb.append([InlineKeyboardButton(text="─────────────────────", callback_data="noop")])

    # Прокси + кнопки замены
    for p in proxies:
        url = f"tg://proxy?server={p['server']}&port={p['port']}&secret={p['secret']}"
        kb.append([InlineKeyboardButton(text=_proxy_button_text(p), url=url)])
        kb.append([
            InlineKeyboardButton(text="✅ Работает", callback_data=f"ok:{p['id']}"),
            InlineKeyboardButton(text="❌ Не работает", callback_data=f"rep:{p['id']}:{flt}"),
        ])

    # Разделитель перед кнопкой умного поиска
    kb.append([InlineKeyboardButton(text="─────────────────────", callback_data="noop")])

    # Кнопка умного автопоиска — двухфазный TCP-поиск
    kb.append([
        InlineKeyboardButton(text="🎯 Подобрать прокси", callback_data=f"fb:{flt}"),
    ])

    return InlineKeyboardMarkup(inline_keyboard=kb)


def _proxy_message_text(region: str, ptype: str, sort: str, count: int) -> str:
    region_label = {"all": "Все регионы", "RU": "🇷🇺 RU", "EU": "🇪🇺 EU"}.get(region, region)
    type_label   = {"all": "Все типы", "FakeTLS": "Рекомендуемый", "RandPad": "Совместимый", "Plain": "Обычный"}.get(ptype, ptype)
    sort_label   = {"recommended": "Оценка пользователей", "user_rating": "Оценка пользователей", "tspu": "Оценка сервера", "server_rating": "Оценка сервера"}.get(sort, sort)
    return (
        f"⚡️ **Прокси для Telegram** | {region_label} | {type_label} | {sort_label}\n"
        f"Найдено: **{count}**. Рекомендации администратора всегда показываются первыми.\n"
        f"Нажмите на строку — Telegram предложит добавить прокси."
    )


# ──────────────────────────────────────────────────────────────────────────────
# /proxy
# ──────────────────────────────────────────────────────────────────────────────

@router.message(Command("proxy"))
async def cmd_proxy(message: Message) -> None:
    await _send_proxy_panel(message, message.from_user.id)


async def _send_proxy_panel(message: Message, uid: int) -> None:

    flt = _DEFAULT_FILTER
    region, ptype, sort = _decode_filter(flt)
    proxies, flt, region, ptype, fallback_note = _proxies_with_fallback(
        flt, region, ptype, sort, user_id=uid
    )

    if not proxies:
        await message.answer(
            "🔍 База прокси пока пуста — воркер проверяет серверы.\n"
            "Попробуй через пару минут!"
        )
        return

    text = _proxy_message_text(region, ptype, sort, len(proxies))
    if fallback_note:
        text += fallback_note
    await message.answer(
        text,
        reply_markup=_build_proxy_keyboard(proxies, flt, region, ptype, sort),
        parse_mode="Markdown",
    )


@router.callback_query(F.data == "free_access")
async def cb_free_access(callback: CallbackQuery) -> None:
    await callback.answer("Доступ открыт — бесплатно")
    await _send_proxy_panel(callback.message, callback.from_user.id)


@router.callback_query(F.data.startswith("prx:"))
async def cb_proxy_filter(callback: CallbackQuery) -> None:
    uid = callback.from_user.id
    flt = callback.data.split(":", 1)[1] if ":" in callback.data else _DEFAULT_FILTER
    region, ptype, sort = _decode_filter(flt)
    proxies, flt, region, ptype, fallback_note = _proxies_with_fallback(
        flt, region, ptype, sort, user_id=uid
    )

    text = _proxy_message_text(region, ptype, sort, len(proxies))
    if not proxies:
        text += "\n\n⚠️ Прокси не найдены — база обновляется. Попробуй через минуту."
    elif fallback_note:
        text += fallback_note

    try:
        await callback.message.edit_text(
            text,
            reply_markup=_build_proxy_keyboard(proxies, flt, region, ptype, sort),
            parse_mode="Markdown",
        )
    except TelegramBadRequest:
        pass
    await callback.answer()


def _make_result_keyboard(tg_url: str, flt: str, pid: str) -> InlineKeyboardMarkup:
    """Кнопки для найденного прокси: подключить + найти другой (с ID для пропуска)."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚀 Подключить в Telegram", url=tg_url)],
        [
            InlineKeyboardButton(text="✅ Работает", callback_data=f"ok:{pid}"),
            InlineKeyboardButton(text="❌ Не работает", callback_data=f"rep:{pid}:{flt}"),
        ],
        [InlineKeyboardButton(text="🔄 Найти другой", callback_data=f"fn:{flt}:{pid}")],
        [InlineKeyboardButton(text="⚙️ Изменить профиль", callback_data=f"pc:{flt}")],
    ])


def _format_found_text(found: dict, label: str = "Лучший рабочий прокси") -> tuple[str, str, str]:
    """Возвращает (text, tg_url, pid) для найденного прокси."""
    server = found["server"]
    port   = found["port"]
    secret = found["secret"]
    score  = found.get("transport_score", found.get("tspu_score", found.get("tspu", 0)))
    ru_score = found.get("ru_reachability_score", 50)
    ru_total = found.get("ru_feedback_total", 0)
    tg_url = f"tg://proxy?server={server}&port={port}&secret={secret}"
    pid    = found.get("id", "")
    admin_line = "⭐ **Выбор сервиса**\n" if found.get("admin_recommended") else ""
    users_line = f"**{ru_score}/100** ({ru_total} оценок)" if ru_total else "пока нет оценок"
    reasons = found.get("match_reasons") or []
    reason_line = f"🎯 Почему выбран: {', '.join(reasons)}\n" if reasons else ""
    text = (
        f"✅ **{label}:**\n\n"
        f"{admin_line}🌐 `{server}:{port}`\n"
        f"👥 Оценка пользователей: {users_line}\n"
        f"⭐ Оценка сервера: **{score}/100**\n\n"
        f"{reason_line}"
        f"Нажмите кнопку, подтвердите подключение в Telegram, затем отметьте результат:"
    )
    return text, tg_url, pid


@router.callback_query(F.data.startswith("fb:"))
async def cb_find_best(callback: CallbackQuery) -> None:
    """
    «Найти лучший прокси» — сбрасывает историю поиска пользователя,
    запускает двухфазный TCP-поиск по текущим фильтрам.
    """
    uid = callback.from_user.id
    flt = callback.data.split(":", 1)[1] if ":" in callback.data else _DEFAULT_FILTER
    if uid not in _user_profiles:
        await callback.answer("Уточните устройство и сеть")
        await callback.message.answer(
            "🎯 **Персональный подбор**\n\n"
            "Бот не видит ваше устройство и интернет-трафик автоматически. "
            "Выберите текущий вариант — он будет учтён вместе с фильтрами и вашими отметками:",
            parse_mode="Markdown",
            reply_markup=_profile_keyboard(flt),
        )
        return
    await _run_personal_search(callback, flt)


@router.callback_query(F.data.startswith("fp:"))
async def cb_choose_profile(callback: CallbackQuery) -> None:
    parts = callback.data.split(":")
    flt = parts[1] if len(parts) > 1 else _DEFAULT_FILTER
    code = parts[2] if len(parts) > 2 else "mw"
    _user_profiles[callback.from_user.id] = _profile_from_code(code)
    await _run_personal_search(callback, flt)


async def _run_personal_search(callback: CallbackQuery, flt: str) -> None:
    uid = callback.from_user.id
    region, ptype, sort = _decode_filter(flt)

    # Сбрасываем список пропущенных прокси для этого пользователя
    _user_skip_clear(uid)

    await callback.answer("🔍 Ищу лучший прокси…")

    profile = _user_profiles.get(uid, ClientProfile())
    found = await _find_first_working(
        region, ptype, sort, skip_ids=set(), user_id=uid, profile=profile
    )
    if not found:
        await callback.message.answer(
            "❌ Рабочих прокси не найдено.\n"
            "Попробуйте позже или выберите прокси вручную."
        )
        return

    # Добавляем найденный прокси в skip-сет (следующий «Найти другой» его пропустит)
    _user_skip_add(uid, found["id"])

    text, tg_url, pid = _format_found_text(
        found, f"Лучший вариант для профиля: {profile.summary()}"
    )
    await callback.message.answer(
        text,
        parse_mode="Markdown",
        reply_markup=_make_result_keyboard(tg_url, flt, pid),
    )


@router.callback_query(F.data.startswith("fn:"))
async def cb_find_next(callback: CallbackQuery) -> None:
    """
    «Найти другой» — пропускаем текущий прокси, берём накопленный skip-сет
    пользователя и ищем следующий рабочий прокси.
    Callback data: fn:{flt}:{pid_to_ban}
    """
    uid = callback.from_user.id
    parts = callback.data.split(":")  # ["fn", flt, pid]
    flt = parts[1] if len(parts) > 1 else _DEFAULT_FILTER
    pid_to_ban = parts[2] if len(parts) > 2 else ""
    region, ptype, sort = _decode_filter(flt)

    # Это не жалоба: пользователь мог просто захотеть другой вариант.
    if pid_to_ban:
        _user_skip_add(uid, pid_to_ban)

    skip = _user_skip_get(uid)

    await callback.answer("🔍 Ищу следующий рабочий прокси…")

    found = await _find_first_working(
        region,
        ptype,
        sort,
        skip_ids=skip,
        user_id=uid,
        profile=_user_profiles.get(uid, ClientProfile()),
    )
    if not found:
        try:
            await callback.message.edit_text(
                "❌ Рабочих прокси не найдено.\n"
                "Все доступные серверы проверены. Попробуйте позже."
            )
        except Exception:
            pass
        return

    # Добавляем новый найденный прокси в skip-сет
    _user_skip_add(uid, found["id"])

    text, tg_url, pid = _format_found_text(found, "Найден рабочий прокси")
    try:
        await callback.message.edit_text(
            text,
            parse_mode="Markdown",
            reply_markup=_make_result_keyboard(tg_url, flt, pid),
        )
    except Exception:
        pass


@router.callback_query(F.data.startswith("pc:"))
async def cb_change_profile(callback: CallbackQuery) -> None:
    flt = callback.data.split(":", 1)[1] if ":" in callback.data else _DEFAULT_FILTER
    await callback.answer()
    await callback.message.answer(
        "Выберите устройство и сеть для следующего подбора:",
        reply_markup=_profile_keyboard(flt),
    )


@router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery) -> None:
    await callback.answer()


@router.callback_query(F.data.startswith("ok:"))
async def report_working(callback: CallbackQuery) -> None:
    proxy_id = callback.data.split(":", 1)[1] if ":" in callback.data else ""
    if not proxy_id:
        await callback.answer("Не удалось определить прокси.", show_alert=True)
        return
    await _save_proxy_feedback(proxy_id, callback.from_user.id, True)
    await callback.answer("Спасибо! Учтём, что прокси работает из России.", show_alert=True)


# ──────────────────────────────────────────────────────────────────────────────
# Callback: замена прокси
# ──────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data.startswith("rep:"))
async def report(callback: CallbackQuery) -> None:
    parts = callback.data.split(":")
    target_pid = parts[1] if len(parts) > 1 else ""
    flt = parts[2] if len(parts) > 2 else _DEFAULT_FILTER

    if target_pid:
        await _save_proxy_feedback(target_pid, callback.from_user.id, False)

    region, ptype, sort = _decode_filter(flt)

    # Как на сайте: после персональной отметки заново строим актуальный топ-10.
    final = _get_filtered_proxies(
        region, ptype, sort, limit=10, user_id=callback.from_user.id
    )

    try:
        if final:
            await callback.message.edit_text(
                _proxy_message_text(region, ptype, sort, len(final)),
                reply_markup=_build_proxy_keyboard(final, flt, region, ptype, sort),
                parse_mode="Markdown",
            )
            await callback.answer("✅ Замена произведена!", show_alert=False)
        else:
            await callback.answer("Резервных серверов пока нет.", show_alert=True)
    except TelegramBadRequest:
        await callback.answer("Этот прокси уже заменён.", show_alert=False)
    except Exception as e:
        logger.error("UI update error: %s", e)
        await callback.answer("Ошибка обновления интерфейса.", show_alert=False)
