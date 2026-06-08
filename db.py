# НЕ РАБОТАЕТ !!11

import asyncpg
import logging
import time
import asyncio
from config import DATABASE_URL

logger = logging.getLogger(__name__)

# Глобальный пул подключений к PostgreSQL
pool = None
MAX_RETRIES = 3


async def init_db():
    """Инициализация базы данных - подключение к Render PostgreSQL и создание таблицы"""
    global pool

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Connecting to PostgreSQL (attempt {attempt + 1}/{MAX_RETRIES})...")

            # Создаём пул подключений с таймаутом
            pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=2,
                max_size=10,
                max_cached_statement_lifetime=300,
                max_cacheable_statement_size=15000,
                command_timeout=30,
                timeout=10
            )

            logger.info("Connection pool created successfully")

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

                logger.info("Database table and indexes created/verified")

            return True

        except Exception as e:
            logger.error(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(5)
            else:
                logger.critical(f"Failed to connect to database after {MAX_RETRIES} attempts!")
                raise


async def _get_connection():
    """Получить подключение из пула с проверкой"""
    if not pool:
        logger.error("Database pool not initialized!")
        return None

    try:
        conn = await asyncio.wait_for(pool.acquire(), timeout=10)
        return conn
    except Exception as e:
        logger.error(f"Failed to acquire database connection: {e}")
        return None


async def save_or_update_proxy(proxy_data):
    """Сохранить новый прокси или обновить существующий"""
    if not pool:
        logger.error("Database pool not initialized")
        return False

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return False

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
            int(proxy_data['port']),
            proxy_data['secret'],
            'active',
            proxy_data.get('ping'),
            proxy_data.get('tspu'),
            proxy_data.get('rank'),
            time.time()
        ))
        return True

    except Exception as e:
        logger.error(f"Error saving proxy {proxy_data.get('id')}: {e}")
        return False
    finally:
        if conn:
            await pool.release(conn)


async def get_live_proxies(limit=30):
    """Получить активные прокси отсортированные по рейтингу"""
    if not pool:
        logger.error("Database pool not initialized")
        return []

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return []

        rows = await conn.fetch("""
            SELECT id, server, port, secret, ping, tspu, rank_score
            FROM proxies
            WHERE status = 'active'
            ORDER BY rank_score ASC
            LIMIT $1
        """, limit)

        result = [
            {
                'id': row['id'],
                'server': row['server'],
                'port': str(row['port']),
                'secret': row['secret'],
                'ping': row['ping'],
                'tspu': row['tspu'],
                'rank': row['rank_score']
            }
            for row in rows
        ]

        if not result:
            logger.debug(f"No active proxies found in database")
        else:
            logger.debug(f"Retrieved {len(result)} proxies from database")

        return result

    except Exception as e:
        logger.error(f"Error fetching proxies: {e}")
        return []
    finally:
        if conn:
            await pool.release(conn)


async def mark_dead(proxy_id, duration_seconds=7200):
    """Отметить прокси как неработающий на определённое время"""
    if not pool:
        logger.error("Database pool not initialized")
        return False

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return False

        await conn.execute("""
            UPDATE proxies
            SET status = 'dead', fail_count = fail_count + 1, updated_at = NOW()
            WHERE id = $1
        """, proxy_id)
        return True

    except Exception as e:
        logger.error(f"Error marking proxy dead: {e}")
        return False
    finally:
        if conn:
            await pool.release(conn)


async def cleanup_dead_proxies():
    """Восстановить прокси, время блокировки которых истекло"""
    if not pool:
        logger.error("Database pool not initialized")
        return 0

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return 0

        # Восстанавливаем прокси, если они были отмечены давно
        result = await conn.execute("""
            UPDATE proxies
            SET status = 'active', updated_at = NOW()
            WHERE status = 'dead' AND last_checked < NOW() - INTERVAL '2 hours'
        """)

        # Парсим результат UPDATE команды
        updated = int(result.split()[-1]) if result else 0
        if updated > 0:
            logger.info(f"Cleaned up {updated} dead proxies")
        return updated

    except Exception as e:
        logger.error(f"Error cleaning up dead proxies: {e}")
        return 0
    finally:
        if conn:
            await pool.release(conn)


async def get_proxy_by_id(proxy_id):
    """Получить информацию о прокси по ID"""
    if not pool:
        logger.error("Database pool not initialized")
        return None

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return None

        row = await conn.fetchrow("""
            SELECT id, server, port, secret, status, ping, tspu
            FROM proxies
            WHERE id = $1
        """, proxy_id)

        if row:
            return {
                'id': row['id'],
                'server': row['server'],
                'port': str(row['port']),
                'secret': row['secret'],
                'status': row['status'],
                'ping': row['ping'],
                'tspu': row['tspu']
            }
        return None

    except Exception as e:
        logger.error(f"Error fetching proxy: {e}")
        return None
    finally:
        if conn:
            await pool.release(conn)


async def get_proxy_count():
    """Получить количество активных прокси в БД"""
    if not pool:
        return 0

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return 0

        result = await conn.fetchval("SELECT COUNT(*) FROM proxies WHERE status = 'active'")
        return result or 0

    except Exception as e:
        logger.error(f"Error counting proxies: {e}")
        return 0
    finally:
        if conn:
            await pool.release(conn)


async def delete_proxy(proxy_id):
    """Удалить прокси из базы данных"""
    if not pool:
        logger.error("Database pool not initialized")
        return False

    conn = None
    try:
        conn = await _get_connection()
        if not conn:
            return False

        await conn.execute("DELETE FROM proxies WHERE id = $1", proxy_id)
        return True

    except Exception as e:
        logger.error(f"Error deleting proxy: {e}")
        return False
    finally:
        if conn:
            await pool.release(conn)


async def close_db():
    """Закрыть подключение к БД (вызвать при завершении бота)"""
    global pool
    if pool:
        try:
            await pool.close()
            logger.info("Database pool closed")
        except Exception as e:
            logger.error(f"Error closing database pool: {e}")
        finally:
            pool = None
