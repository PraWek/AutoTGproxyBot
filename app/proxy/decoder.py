"""
proxy_decoder.py — Модуль декодирования MTProto-секретов.

MTProto поддерживает три поколения секретов:

  Поколение 1 — Plain (32 hex-символа = 16 байт):
      Открытый MTProto. Трафик легко детектируется DPI/ТСПУ.
      Пример: "aabbccddeeff00112233445566778899"

  Поколение 2 — Random Padding (префикс 0xDD):
      "dd" + 32 hex-символа секрета.
      К каждому пакету добавляется случайный паддинг → трафик
      менее предсказуем, но заголовок MTProto всё ещё виден.
      Пример: "ddaabbccddeeff00112233445566778899"

  Поколение 3 — Fake-TLS (префикс 0xEE):
      "ee" + hex(16-байтовый-секрет + SNI-домен-в-UTF-8).

      Механизм маскировки Fake-TLS (упрощённо):
      ┌─────────────────────────────────────────────────────────┐
      │  Клиент делает ClientHello с SNI = домен из секрета.    │
      │  Сервер отвечает как настоящий TLS-сервер этого домена. │
      │  Соединение имитирует TLS; результат зависит от клиента │
      │  и правил конкретной сети.                              │
      └─────────────────────────────────────────────────────────┘

      Структура байт после удаления "ee" и hex-декодирования:
        [0:16]  — 16 байт настоящего MTProto-секрета (случайный ключ)
        [16:]   — UTF-8 строка SNI-домена (например "www.google.com")

      Именно этот домен клиент Telegram подставляет в поле server_name.
      Одного имени SNI недостаточно, чтобы предсказать доступность.
"""

from __future__ import annotations

import binascii
import logging
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Типы
# ──────────────────────────────────────────────────────────────────────────────

SecretGeneration = Literal["plain", "randpad", "faketls", "unknown"]


@dataclass
class DecodedSecret:
    """Результат расшифровки одного MTProto-секрета."""
    raw: str                         # исходная hex-строка
    generation: SecretGeneration     # тип секрета
    core_bytes: bytes                # 16-байтовый MTProto-ключ
    sni_domain: str                  # SNI-домен (только для FakeTLS)
    is_valid: bool                   # прошёл ли базовую валидацию


# ──────────────────────────────────────────────────────────────────────────────
# Основная функция декодирования
# ──────────────────────────────────────────────────────────────────────────────

def decode_secret(secret: str) -> DecodedSecret:
    """
    Декодирует MTProto-секрет любого поколения.

    Алгоритм для Fake-TLS (ee...):
      1. Убираем префикс "ee" (2 hex-символа).
      2. Оставшуюся hex-строку декодируем в байты: bytes.fromhex(...)
      3. Первые 16 байт — это MTProto core-ключ (используется для шифрования).
      4. Байты с 16-го до конца — UTF-8 строка SNI-домена.
         Если байт 16 == 0x00, домен начинается с байта 17 (null-prefix вариант).

    :param secret: hex-строка секрета (регистр не важен)
    :return:       DecodedSecret с разобранными полями
    """
    s = secret.strip().lower()

    # ── Определяем поколение по префиксу ─────────────────────────────────────
    if s.startswith("ee"):
        return _decode_faketls(s)

    if s.startswith("dd"):
        return _decode_randpad(s)

    # Plain: 32 hex-символа без префикса
    if len(s) == 32 and _is_hex(s):
        return _decode_plain(s)

    logger.debug("decode_secret: неизвестный формат секрета (len=%d)", len(s))
    return DecodedSecret(
        raw=secret,
        generation="unknown",
        core_bytes=b"",
        sni_domain="",
        is_valid=False,
    )


def _decode_faketls(s: str) -> DecodedSecret:
    """
    Декодирует Fake-TLS секрет (префикс «ee»).

    Структура после снятия «ee»:
      hex_payload = s[2:]                 # убираем «ee»
      raw_bytes   = bytes.fromhex(hex_payload)

      raw_bytes[0:16]  → MTProto core key (16 байт)
      raw_bytes[16:]   → SNI-домен в UTF-8

    Если hex_payload содержит нечётное количество символов или
    не является валидным hex — помечаем секрет как невалидный.
    """
    hex_payload = s[2:]  # убираем двухсимвольный префикс "ee"

    if len(hex_payload) < 32:  # минимум 16 байт core key
        logger.debug("faketls: hex_payload слишком короткий (%d символов)", len(hex_payload))
        return DecodedSecret(raw=s, generation="faketls",
                             core_bytes=b"", sni_domain="", is_valid=False)

    try:
        raw_bytes = bytes.fromhex(hex_payload)
    except (binascii.Error, ValueError) as exc:
        logger.debug("faketls: ошибка hex-декодирования: %s", exc)
        return DecodedSecret(raw=s, generation="faketls",
                             core_bytes=b"", sni_domain="", is_valid=False)

    # ── Разбиваем на core key и SNI-домен ────────────────────────────────────
    core_key   = raw_bytes[:16]           # MTProto-ключ (фиксированные 16 байт)
    domain_raw = raw_bytes[16:]           # всё остальное — домен

    # Некоторые клиенты кодируют домен с ведущим нулевым байтом (null-prefix)
    # Пример официального клиента Telegram Desktop:
    #   raw_bytes[16] == 0x00, raw_bytes[17:] == "cloudflare.com"
    if domain_raw and domain_raw[0] == 0x00:
        domain_raw = domain_raw[1:]

    # Пробуем декодировать домен как UTF-8; некорректные байты заменяем на «?»
    sni_domain = domain_raw.decode("utf-8", errors="replace").strip("\x00").strip()

    # Санитарная проверка формата. Репутация домена здесь не оценивается.
    labels = sni_domain.lower().rstrip(".").split(".")
    is_valid = (
        2 <= len(labels) <= 127
        and len(sni_domain) <= 253
        and all(
            label
            and len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        )
    )

    if is_valid:
        logger.debug("faketls: SNI=%s, core=%s...", sni_domain, core_key.hex()[:8])
    else:
        logger.debug("faketls: SNI не извлечён (raw=%r)", domain_raw)

    return DecodedSecret(
        raw=s,
        generation="faketls",
        core_bytes=core_key,
        sni_domain=sni_domain,
        is_valid=is_valid,
    )


def _decode_randpad(s: str) -> DecodedSecret:
    """
    Декодирует Random Padding секрет (префикс «dd»).
    После «dd» идут 32 hex-символа (16 байт) MTProto-ключа.
    SNI-домена нет.
    """
    hex_payload = s[2:]

    if len(hex_payload) != 32 or not _is_hex(hex_payload):
        return DecodedSecret(raw=s, generation="randpad",
                             core_bytes=b"", sni_domain="", is_valid=False)

    try:
        core_key = bytes.fromhex(hex_payload[:32])
    except ValueError:
        return DecodedSecret(raw=s, generation="randpad",
                             core_bytes=b"", sni_domain="", is_valid=False)

    return DecodedSecret(
        raw=s,
        generation="randpad",
        core_bytes=core_key,
        sni_domain="",
        is_valid=True,
    )


def _decode_plain(s: str) -> DecodedSecret:
    """
    Декодирует Plain-секрет (ровно 32 hex-символа, нет префикса).
    """
    try:
        core_key = bytes.fromhex(s)
    except ValueError:
        return DecodedSecret(raw=s, generation="plain",
                             core_bytes=b"", sni_domain="", is_valid=False)

    return DecodedSecret(
        raw=s,
        generation="plain",
        core_bytes=core_key,
        sni_domain="",
        is_valid=True,
    )


def _is_hex(s: str) -> bool:
    """Возвращает True, если строка — валидный hex чётной длины."""
    return len(s) % 2 == 0 and all(c in "0123456789abcdef" for c in s)


# ──────────────────────────────────────────────────────────────────────────────
# Утилита: форматированный вывод для логов/отладки
# ──────────────────────────────────────────────────────────────────────────────

def describe_secret(decoded: DecodedSecret) -> str:
    """Возвращает читаемое описание декодированного секрета."""
    gen_labels: dict[str, str] = {
        "faketls": "Fake-TLS (ee)",
        "randpad":  "Random Padding (dd)",
        "plain":    "Plain MTProto",
        "unknown":  "Неизвестный формат",
    }
    label = gen_labels.get(decoded.generation, decoded.generation)
    if decoded.generation == "faketls" and decoded.sni_domain:
        return f"{label} | SNI: {decoded.sni_domain}"
    return f"{label} | valid={decoded.is_valid}"
