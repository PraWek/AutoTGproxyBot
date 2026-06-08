import aiosqlite
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Путь к базе данных прокси
DB_PATH = Path("proxies.db")


async def init_db():
    """Инициализация базы данных с таблицей прокси"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                secret TEXT NOT NULL,
                status TEXT DEFAULT 'testing',
                last_checked REAL,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                ping INTEGER,
                tspu INTEGER,
                rank_score REAL
            )
        """)
        await db.commit()


async def save_proxy(proxy_data):
    """Сохранить или обновить прокси в базе данных"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO proxies
            (id, server, port, secret, status, last_checked, success_count, fail_count, ping, tspu, rank_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            proxy_data['id'],
            proxy_data['server'],
            proxy_data['port'],
            proxy_data['secret'],
            'active',
            time.time(),
            proxy_data.get('success_count', 1),
            proxy_data.get('fail_count', 0),
            proxy_data.get('ping'),
            proxy_data.get('tspu'),
            proxy_data.get('rank')
        ))
        await db.commit()


async def get_live_proxies(limit=30):
    """Получить активные прокси отсортированные по рейтингу"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            SELECT id, server, port, secret, ping, tspu, rank_score
            FROM proxies
            WHERE status = 'active'
            ORDER BY rank_score ASC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [
            {
                'id': row[0],
                'server': row[1],
                'port': row[2],
                'secret': row[3],
                'ping': row[4],
                'tspu': row[5],
                'rank': row[6]
            }
            for row in rows
        ]


async def mark_dead(proxy_id, duration_seconds=7200):
    """Отметить прокси как неработающий на определённое время"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            UPDATE proxies
            SET status = 'dead', last_checked = ?
            WHERE id = ?
        """, (time.time() + duration_seconds, proxy_id))
        await db.commit()


async def cleanup_dead_proxies():
    """Восстановить прокси, время блокировки которых истекло"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            UPDATE proxies
            SET status = 'active'
            WHERE status = 'dead' AND last_checked < ?
        """, (time.time(),))
        await db.commit()


async def get_proxy_by_id(proxy_id):
    """Получить информацию о прокси по ID"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            SELECT id, server, port, secret, status, ping, tspu
            FROM proxies
            WHERE id = ?
        """, (proxy_id,))
        row = await cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'server': row[1],
                'port': row[2],
                'secret': row[3],
                'status': row[4],
                'ping': row[5],
                'tspu': row[6]
            }
        return None


async def delete_proxy(proxy_id):
    """Удалить прокси из базы данных"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
        await db.commit()
