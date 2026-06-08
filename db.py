import asyncpg
import logging
import time
from config import DATABASE_URL

logger = logging.getLogger(__name__)

# Глобальный пул подключений к PostgreSQL
pool = None


async def init_db():
    """Инициализация базы данных - подключение к Render PostgreSQL и создание таблицы"""
    global pool
    try:
        # Создаём пул подключений
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
        logger.info("Database pool created successfully")

        # Создаём таблицу если её нет
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    id TEXT PRIMARY KEY,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    secret TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    last_checked TIMESTAMP DEFAULT NOW(),
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    ping INTEGER,
                    tspu INTEGER,
                    rank_score REAL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)

            # Индексы для быстрого поиска
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_status_rank
                ON proxies(status, rank_score)
            """)

            logger.info("Database table and indexes created")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise


async def save_or_update_proxy(proxy_data):
    """Сохранить новый прокси или обновить существующий"""
    if not pool:
        logger.error("Database pool not initialized")
        return

    try:
        async with pool.acquire() as conn:
            # Используем UPSERT (INSERT ... ON CONFLICT UPDATE)
            await conn.execute("""
                INSERT INTO proxies
                (id, server, port, secret, status, ping, tspu, rank_score, last_checked, success_count, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    ping = EXCLUDED.ping,
                    tspu = EXCLUDED.tspu,
                    rank_score = EXCLUDED.rank_score,
                    last_checked = NOW(),
                    status = 'active',
                    success_count = success_count + 1,
                    updated_at = NOW()
            """, (
                proxy_data['id'],
                proxy_data['server'],
                proxy_data['port'],
                proxy_data['secret'],
                'active',
                proxy_data.get('ping'),
                proxy_data.get('tspu'),
                proxy_data.get('rank'),
                time.time()
            ))
    except Exception as e:
        logger.error(f"Error saving proxy {proxy_data.get('id')}: {e}")


async def get_live_proxies(limit=30):
    """Получить активные прокси отсортированные по рейтингу"""
    if not pool:
        logger.error("Database pool not initialized")
        return []

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, server, port, secret, ping, tspu, rank_score
                FROM proxies
                WHERE status = 'active'
                ORDER BY rank_score ASC
                LIMIT $1
            """, limit)

            return [
                {
                    'id': row['id'],
                    'server': row['server'],
                    'port': row['port'],
                    'secret': row['secret'],
                    'ping': row['ping'],
                    'tspu': row['tspu'],
                    'rank': row['rank_score']
                }
                for row in rows
            ]
    except Exception as e:
        logger.error(f"Error fetching proxies: {e}")
        return []


async def mark_dead(proxy_id, duration_seconds=7200):
    """Отметить прокси как неработающий на определённое время"""
    if not pool:
        logger.error("Database pool not initialized")
        return

    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                UPDATE proxies
                SET status = 'dead', fail_count = fail_count + 1, updated_at = NOW()
                WHERE id = $1
            """, proxy_id)
    except Exception as e:
        logger.error(f"Error marking proxy dead: {e}")


async def cleanup_dead_proxies():
    """Восстановить прокси, время блокировки которых истекло"""
    if not pool:
        logger.error("Database pool not initialized")
        return

    try:
        async with pool.acquire() as conn:
            # Восстанавливаем прокси, если они были отмечены давно
            await conn.execute("""
                UPDATE proxies
                SET status = 'active', updated_at = NOW()
                WHERE status = 'dead' AND last_checked < NOW() - INTERVAL '2 hours'
            """)
    except Exception as e:
        logger.error(f"Error cleaning up dead proxies: {e}")


async def get_proxy_by_id(proxy_id):
    """Получить информацию о прокси по ID"""
    if not pool:
        logger.error("Database pool not initialized")
        return None

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT id, server, port, secret, status, ping, tspu
                FROM proxies
                WHERE id = $1
            """, proxy_id)

            if row:
                return {
                    'id': row['id'],
                    'server': row['server'],
                    'port': row['port'],
                    'secret': row['secret'],
                    'status': row['status'],
                    'ping': row['ping'],
                    'tspu': row['tspu']
                }
            return None
    except Exception as e:
        logger.error(f"Error fetching proxy: {e}")
        return None


async def get_proxy_count():
    """Получить количество активных прокси в БД"""
    if not pool:
        return 0

    try:
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT COUNT(*) FROM proxies WHERE status = 'active'")
            return result or 0
    except Exception as e:
        logger.error(f"Error counting proxies: {e}")
        return 0


async def delete_proxy(proxy_id):
    """Удалить прокси из базы данных"""
    if not pool:
        logger.error("Database pool not initialized")
        return

    try:
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM proxies WHERE id = $1", proxy_id)
    except Exception as e:
        logger.error(f"Error deleting proxy: {e}")


async def close_db():
    """Закрыть подключение к БД (вызвать при завершении бота)"""
    global pool
    if pool:
        await pool.close()
        logger.info("Database pool closed")
