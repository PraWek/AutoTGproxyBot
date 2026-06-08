import asyncio
import re
import time
import hashlib
import logging
from aiohttp import ClientSession
from config import BOT_TOKEN
from db import init_db, save_or_update_proxy, get_live_proxies, cleanup_dead_proxies, get_proxy_count, close_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Кеш лучших прокси (загружается из БД при старте)
CACHED_BEST_PROXIES = []
# Чёрный список заблокированных прокси с временем истечения
banned_proxies = {}

# Список каналов Telegram для парсинга прокси
CHANNELS = [
    "ProxyMTProto", "MTProto_Proxy", "proxymtproto_ru", "VipProxyMTProto",
    "tgproxy", "free_proxy_mtproto", "proxy_mtproto_channel",
    "proxy_socks5", "httpproxy", "mttrojan",
    "shadowsocks_proxy", "openproxy_channel", "proxy_master",
    "socks5_proxy", "warp_proxy_channel", "vpn_proxy_ru"
]

# Регулярное выражение для извлечения ссылок на прокси из HTML
PROXY_REGEX = r"tg://proxy\?server=([^&\"]+)&(?:amp;)?port=([0-9]+)&(?:amp;)?secret=([^&\"\s<]+)"

# Счётчик причин отклонения прокси (для отладки качества парсинга)
rejection_reasons = {}


def is_valid_server(server: str) -> bool:
    """Проверить валидность адреса сервера (домен или IP)"""
    if not server or len(server) > 255:
        return False
    # Проверка доменного имени
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    if re.match(pattern, server):
        return True
    # Проверка IPv4 адреса
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, server):
        parts = server.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def is_valid_port(port: str) -> bool:
    """Проверить валидность номера порта (1-65535)"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_secret(secret: str) -> bool:
    """Проверить валидность секрета прокси (32 или 34 hex-символа)"""
    if not secret:
        return False
    if len(secret) not in (32, 34):
        return False
    # 32 символа - обычный секрет
    if len(secret) == 32:
        return re.match(r"^[a-f0-9]{32}$", secret.lower()) is not None
    # 34 символа - с префиксом ad/dd/ee для MTProto
    if len(secret) == 34:
        return re.match(r"^(ad|dd|ee)[a-f0-9]{32}$", secret.lower()) is not None
    return False


def validate_proxy_format(server: str, port: str, secret: str) -> bool:
    """Полная проверка формата прокси перед дорогостоящей проверкой соединения"""
    if not is_valid_server(server):
        rejection_reasons["invalid_server"] = rejection_reasons.get("invalid_server", 0) + 1
        return False
    if not is_valid_port(port):
        rejection_reasons["invalid_port"] = rejection_reasons.get("invalid_port", 0) + 1
        return False
    if not is_valid_secret(secret):
        rejection_reasons["invalid_secret"] = rejection_reasons.get("invalid_secret", 0) + 1
        return False
    return True


def calculate_tspu_score(port, secret):
    """Рассчитать оценку способности прокси обходить DPI ТСПУ (0-100)"""
    score = 50
    # Штраф за обычный 32-символьный секрет
    if len(secret) == 32:
        score -= 40
    # Бонусы за специальные префиксы MTProto
    elif secret.lower().startswith('ee'):
        score += 40
    elif secret.lower().startswith('dd'):
        score += 30
    elif secret.lower().startswith('ad'):
        score += 25
    # Бонус за стандартный HTTPS порт
    if port == '443':
        score += 10
    return min(max(score, 0), 100)


async def check_proxy(server, port, secret):
    """Проверить работоспособность прокси через TCP соединение"""
    # Генерируем уникальный ID прокси (включая secret для избежания коллизий)
    pid = hashlib.md5(f"{server}:{port}:{secret}".encode()).hexdigest()[:8]

    # Пропускаем заблокированные прокси
    if pid in banned_proxies and time.time() < banned_proxies[pid]:
        return None

    start = time.time()
    try:
        # Пытаемся подключиться к прокси
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, int(port)),
            timeout=2.0
        )
        # Отправляем байт для активации соединения
        writer.write(b'\x00')
        await writer.drain()
        await asyncio.sleep(0.1)
        # Измеряем пинг
        ping = int((time.time() - start) * 1000)
        tspu = calculate_tspu_score(port, secret)

        proxy_data = {
            "id": pid,
            "server": server,
            "port": port,
            "secret": secret,
            "ping": ping,
            "tspu": tspu,
            "rank": ping + (100 - tspu) * 5
        }
        return proxy_data
    except asyncio.TimeoutError:
        rejection_reasons["timeout"] = rejection_reasons.get("timeout", 0) + 1
        logger.debug(f"Timeout checking {server}:{port}")
        return None
    except ConnectionRefusedError:
        rejection_reasons["refused"] = rejection_reasons.get("refused", 0) + 1
        logger.debug(f"Connection refused {server}:{port}")
        return None
    except OSError as e:
        rejection_reasons["network_error"] = rejection_reasons.get("network_error", 0) + 1
        logger.debug(f"Network error {server}:{port}: {e}")
        return None
    except Exception as e:
        rejection_reasons["unknown_error"] = rejection_reasons.get("unknown_error", 0) + 1
        logger.error(f"Unexpected error checking {server}:{port}: {e}")
        return None
    finally:
        # Закрываем соединение
        if 'writer' in locals():
            try:
                writer.close()
            except:
                pass


async def fetch_proxies_from_channels():
    """Получить прокси со всех каналов параллельно"""
    found = set()
    async with ClientSession() as session:
        tasks = []
        for ch in CHANNELS:
            tasks.append(fetch_channel(session, ch, found))
        # Загружаем все каналы одновременно
        await asyncio.gather(*tasks, return_exceptions=True)
    return found


async def fetch_channel(session, channel, found_set):
    """Парсить отдельный Telegram канал и добавить найденные прокси в набор"""
    try:
        # Загружаем HTML канала
        resp = await session.get(f"https://t.me/s/{channel}", timeout=10)
        html = await resp.text()
        # Извлекаем прокси по регулярному выражению
        proxies = re.findall(PROXY_REGEX, html)
        found_set.update(proxies)
        logger.info(f"Channel {channel}: found {len(proxies)} proxies")
    except Exception as e:
        logger.warning(f"Failed to fetch {channel}: {e}")


async def proxy_updater_worker():
    """Основной цикл обновления базы прокси (запускается в фоне)"""
    global CACHED_BEST_PROXIES

    # Инициализируем базу данных при запуске
    await init_db()
    logger.info("Database initialized with Render PostgreSQL")

    while True:
        try:
            logger.info("Starting proxy update cycle...")

            # 1. Загружаем прокси со всех каналов
            found = await fetch_proxies_from_channels()
            logger.info(f"Total proxies found: {len(found)}")

            # 2. Фильтруем прокси по формату ДО дорогостоящей проверки соединения
            valid_proxies = [
                p for p in found
                if validate_proxy_format(p[0], p[1], p[2])
            ]
            logger.info(f"Valid proxies after format check: {len(valid_proxies)}")
            logger.info(f"Rejection breakdown: {rejection_reasons}")

            # 3. Проверяем работоспособность валидных прокси параллельно
            check_tasks = [
                check_proxy(server, port, secret)
                for server, port, secret in valid_proxies
            ]

            results = await asyncio.gather(*check_tasks, return_exceptions=False)
            # 4. Оставляем только успешно проверённые прокси
            live_proxies = [r for r in results if r]
            logger.info(f"Live proxies: {len(live_proxies)}")

            # 5. КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Сохраняем ВСЕ найденные рабочие прокси (не только топ-50)
            # Это позволяет БД расти и хранить много прокси
            saved_count = 0
            for proxy in live_proxies:
                await save_or_update_proxy(proxy)
                saved_count += 1

            logger.info(f"Saved/Updated {saved_count} proxies in database")

            # 6. Обновляем кеш из БД (берём топ-50 для быстрого доступа)
            CACHED_BEST_PROXIES = await get_live_proxies(limit=50)
            logger.info(f"Cached top-50 proxies: {len(CACHED_BEST_PROXIES)}")

            # 7. Логируем общее количество прокси в БД
            total_count = await get_proxy_count()
            logger.info(f"Total proxies in database: {total_count}")

            # 8. Восстанавливаем прокси со истёкшей блокировкой
            await cleanup_dead_proxies()

        except Exception as e:
            logger.error(f"Error in proxy update cycle: {e}")

        # Ждём 3 минуты перед следующей проверкой
        await asyncio.sleep(180)
