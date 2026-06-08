import sqlite3
import logging
import time
import asyncio
from pathlib import Path

logger = logging.getLogger(__name__)

# Путь к базе данных прокси
DB_PATH = Path("proxies.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


async def init_db():
    """Инициализация базы данных с таблицей прокси"""
    def sync_init():
        with _connect() as db:
            db.execute("""
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
            db.commit()

    await asyncio.to_thread(sync_init)


async def save_proxy(proxy_data):
    """Сохранить или обновить прокси в базе данных"""
    def sync_save():
        with _connect() as db:
            db.execute("""
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
            db.commit()

    await asyncio.to_thread(sync_save)


async def get_live_proxies(limit=30):
    """Получить активные прокси отсортированные по рейтингу"""
    def sync_get():
        with _connect() as db:
            cursor = db.execute("""
                SELECT id, server, port, secret, ping, tspu, rank_score
                FROM proxies
                WHERE status = 'active'
                ORDER BY rank_score ASC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
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

    return await asyncio.to_thread(sync_get)


async def mark_dead(proxy_id, duration_seconds=7200):
    """Отметить прокси как неработающий на определённое время"""
    def sync_mark():
        with _connect() as db:
            db.execute("""
                UPDATE proxies
                SET status = 'dead', last_checked = ?
                WHERE id = ?
            """, (time.time() + duration_seconds, proxy_id))
            db.commit()

    await asyncio.to_thread(sync_mark)


async def cleanup_dead_proxies():
    """Восстановить прокси, время блокировки которых истекло"""
    def sync_cleanup():
        with _connect() as db:
            db.execute("""
                UPDATE proxies
                SET status = 'active'
                WHERE status = 'dead' AND last_checked < ?
            """, (time.time(),))
            db.commit()

    await asyncio.to_thread(sync_cleanup)


async def get_proxy_by_id(proxy_id):
    """Получить информацию о прокси по ID"""
    def sync_get():
        with _connect() as db:
            cursor = db.execute("""
                SELECT id, server, port, secret, status, ping, tspu
                FROM proxies
                WHERE id = ?
            """, (proxy_id,))
            row = cursor.fetchone()
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

    return await asyncio.to_thread(sync_get)


async def delete_proxy(proxy_id):
    """Удалить прокси из базы данных"""
    def sync_delete():
        with _connect() as db:
            db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
            db.commit()

    await asyncio.to_thread(sync_delete)
