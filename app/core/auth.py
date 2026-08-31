"""
auth_utils.py — Аутентификация и управление сессиями.

Пароли:
  hash_password(plain)         → версия + число итераций + соль + ключ
  verify_password(plain, hash) → True/False

Сессии:
  - Подписанный cookie через itsdangerous.URLSafeTimedSerializer
  - В токене только telegram_id — никаких персональных данных
  - HttpOnly + SameSite=Lax — защита от XSS / CSRF
  - Срок действия 30 дней
"""
from __future__ import annotations

import binascii
import hashlib
import hmac
import logging
import os
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger(__name__)

SESSION_COOKIE  = "tgsession"
SESSION_MAX_AGE = 30 * 24 * 3600   # 30 дней
PBKDF2_ITERS    = 600_000           # OWASP Password Storage Cheat Sheet
LEGACY_PBKDF2_ITERS = 260_000


# ──────────────────────────────────────────────────────────────────────────────
# Хэширование паролей (PBKDF2-HMAC-SHA256)
# ──────────────────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """
    Хэширует пароль.
    Возвращает самодокументируемую строку с алгоритмом и числом итераций.
    """
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, PBKDF2_ITERS)
    return "$".join((
        "pbkdf2_sha256",
        str(PBKDF2_ITERS),
        binascii.hexlify(salt).decode(),
        binascii.hexlify(key).decode(),
    ))


def verify_password(plain: str, stored: str) -> bool:
    """
    Проверяет пароль против сохранённого хэша.
    Constant-time сравнение — защита от timing-атак.
    """
    if not stored:
        return False
    try:
        if stored.startswith("pbkdf2_sha256$"):
            algorithm, iterations_raw, salt_hex, key_hex = stored.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            iterations = int(iterations_raw)
            if not 100_000 <= iterations <= 2_000_000:
                return False
        elif ":" in stored:
            salt_hex, key_hex = stored.split(":", 1)
            iterations = LEGACY_PBKDF2_ITERS
        else:
            return False
        salt = binascii.unhexlify(salt_hex)
        key  = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(binascii.hexlify(key).decode(), key_hex)
    except Exception:
        return False


def password_needs_rehash(stored: str) -> bool:
    return not isinstance(stored, str) or not stored.startswith(f"pbkdf2_sha256${PBKDF2_ITERS}$")


# ──────────────────────────────────────────────────────────────────────────────
# Управление сессиями (подписанные cookies)
# ──────────────────────────────────────────────────────────────────────────────

def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="tg-proxy-session-v2")


def make_session_token(telegram_id: int, secret_key: str) -> str:
    """Создаёт подписанный токен для хранения в cookie."""
    return _serializer(secret_key).dumps({"uid": telegram_id})


def read_session_token(token: str, secret_key: str) -> Optional[int]:
    """
    Декодирует токен сессии.
    :return: telegram_id или None если токен невалиден / просрочен
    """
    if not token:
        return None
    try:
        data = _serializer(secret_key).loads(token, max_age=SESSION_MAX_AGE)
        return int(data["uid"])
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError):
        return None


def get_uid_from_request(request) -> Optional[int]:
    """Читает telegram_id пользователя из cookie запроса."""
    secret_key: str = request.app.get("secret_key", "")
    if not secret_key:
        return None
    token = request.cookies.get(SESSION_COOKIE)
    return read_session_token(token or "", secret_key)


def set_session_cookie(
    response,
    telegram_id: int,
    secret_key: str,
    *,
    secure: bool = False,
) -> None:
    """Устанавливает защищённый сессионный cookie в ответе."""
    token = make_session_token(telegram_id, secret_key)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="Lax",
        secure=secure,
    )


def clear_session_cookie(response) -> None:
    """Удаляет сессионный cookie."""
    response.del_cookie(SESSION_COOKIE, samesite="Lax")


# ──────────────────────────────────────────────────────────────────────────────
# Устаревшая функция — оставлена для совместимости, не используется
# ──────────────────────────────────────────────────────────────────────────────

def verify_telegram_auth(data: dict, bot_token: str) -> bool:
    """Legacy: проверка Telegram Login Widget. Больше не используется."""
    received_hash = data.get("hash", "")
    if not received_hash:
        return False
    fields = {k: v for k, v in data.items() if k != "hash"}
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    computed   = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, received_hash)
