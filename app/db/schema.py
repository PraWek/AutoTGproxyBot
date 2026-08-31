"""
db_schema.py — Схема PostgreSQL и слой доступа к данным.

Таблицы:
  proxies              — прокси-серверы (проверенные, с метриками)
  users                — аккаунты (логин + пароль + опциональный telegram_id как PK)
  pending_registrations — временные записи регистрации (пока не привязан TG)
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.auth import hash_password, password_needs_rehash, verify_password

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# DDL — proxies
# ──────────────────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS proxies (
    id           TEXT        PRIMARY KEY,
    host         TEXT        NOT NULL,
    port         INTEGER     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    secret       TEXT        NOT NULL DEFAULT '',
    kind         TEXT        NOT NULL DEFAULT 'mtproto'
                             CHECK (kind IN ('mtproto', 'socks5')),
    generation   TEXT        NOT NULL DEFAULT 'unknown'
                             CHECK (generation IN ('plain', 'randpad', 'faketls', 'unknown')),
    sni_domain   TEXT        NOT NULL DEFAULT '',
    category     TEXT        NOT NULL DEFAULT 'EU'
                             CHECK (category IN ('RU', 'EU')),
    ping_ms      INTEGER     NOT NULL DEFAULT 0,
    tspu_score   INTEGER     NOT NULL DEFAULT 0 CHECK (tspu_score BETWEEN 0 AND 100),
    stability    INTEGER     NOT NULL DEFAULT 0 CHECK (stability BETWEEN 0 AND 100),
    rank         INTEGER     NOT NULL DEFAULT 9999,
    is_alive     BOOLEAN     NOT NULL DEFAULT FALSE,
    admin_recommended BOOLEAN NOT NULL DEFAULT FALSE,
    admin_recommended_at TIMESTAMPTZ,
    checked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxies_alive_rank
    ON proxies (is_alive, rank)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_category
    ON proxies (category, rank)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_generation
    ON proxies (generation)
    WHERE is_alive = TRUE;

CREATE INDEX IF NOT EXISTS idx_proxies_updated
    ON proxies (updated_at DESC);
"""

CREATE_PROXY_FEEDBACK_SQL = """
CREATE TABLE IF NOT EXISTS proxy_feedback (
    proxy_id      TEXT        NOT NULL,
    telegram_id   BIGINT      NOT NULL,
    works_in_ru   BOOLEAN     NOT NULL,
    network_type  TEXT        NOT NULL DEFAULT 'unknown'
                              CHECK (network_type IN ('unknown', 'mobile', 'home', 'work')),
    operator_name TEXT        NOT NULL DEFAULT '',
    reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (proxy_id, telegram_id)
);
CREATE INDEX IF NOT EXISTS idx_proxy_feedback_recent
    ON proxy_feedback (proxy_id, reported_at DESC);
"""

# ──────────────────────────────────────────────────────────────────────────────
# DDL — users (новая схема для чистой установки)
# ──────────────────────────────────────────────────────────────────────────────

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    telegram_id   BIGINT      PRIMARY KEY,
    account_login TEXT        NOT NULL DEFAULT '',
    password_hash  TEXT        NOT NULL DEFAULT '',
    username       TEXT        NOT NULL DEFAULT '',
    first_name    TEXT        NOT NULL DEFAULT '',
    last_name     TEXT        NOT NULL DEFAULT '',
    photo_url     TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_AUTH_TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS auth_tokens (
    token       TEXT        PRIMARY KEY,
    telegram_id BIGINT      REFERENCES users(telegram_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);
"""

# ──────────────────────────────────────────────────────────────────────────────
# DDL — pending_registrations (временные записи до привязки Telegram)
# ──────────────────────────────────────────────────────────────────────────────

CREATE_PENDING_REG_SQL = """
CREATE TABLE IF NOT EXISTS pending_registrations (
    token         TEXT        PRIMARY KEY,
    account_login TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    telegram_id   BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_reg_expires ON pending_registrations(expires_at);
"""


# ──────────────────────────────────────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────────────────────────────────────

def make_proxy_id(host: str, port: int) -> str:
    return hashlib.md5(f"{host}:{port}".encode()).hexdigest()[:8]


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _gen_password(length: int = 10) -> str:
    """Генерирует случайный пароль из букв и цифр."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _gen_login(telegram_id: int, username: str = "") -> str:
    """Логин = TG username (без @), если задан; иначе user{id}."""
    return username.lower() if username else f"user{telegram_id}"


# ──────────────────────────────────────────────────────────────────────────────
# ProxyRepository
# ──────────────────────────────────────────────────────────────────────────────

class ProxyRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def migrate(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_TABLE_SQL)
            await conn.execute(CREATE_PROXY_FEEDBACK_SQL)
            await conn.execute(
                "ALTER TABLE proxies ADD COLUMN IF NOT EXISTS "
                "admin_recommended BOOLEAN NOT NULL DEFAULT FALSE"
            )
            await conn.execute(
                "ALTER TABLE proxies ADD COLUMN IF NOT EXISTS "
                "admin_recommended_at TIMESTAMPTZ"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_proxies_admin_recommended "
                "ON proxies (admin_recommended DESC, admin_recommended_at DESC) "
                "WHERE admin_recommended = TRUE"
            )
        logger.info("db: таблицы proxies/proxy_feedback — миграция завершена")

    async def record_feedback(
        self,
        proxy_id: str,
        telegram_id: int,
        works_in_ru: bool,
        *,
        network_type: str = "unknown",
        operator_name: str = "",
    ) -> None:
        if network_type not in {"unknown", "mobile", "home", "work"}:
            network_type = "unknown"
        operator_name = operator_name.strip()[:64]
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO proxy_feedback
                    (proxy_id, telegram_id, works_in_ru, network_type, operator_name, reported_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (proxy_id, telegram_id) DO UPDATE SET
                    works_in_ru   = EXCLUDED.works_in_ru,
                    network_type  = EXCLUDED.network_type,
                    operator_name = EXCLUDED.operator_name,
                    reported_at   = NOW()
                """,
                proxy_id, telegram_id, works_in_ru, network_type, operator_name,
            )

    async def get_feedback_summaries(self, proxy_ids: list[str]) -> dict[str, dict[str, int]]:
        if not proxy_ids:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT proxy_id,
                       COUNT(*) FILTER (WHERE works_in_ru)     AS successes,
                       COUNT(*) FILTER (WHERE NOT works_in_ru) AS failures
                FROM proxy_feedback
                WHERE proxy_id = ANY($1::text[])
                  AND reported_at > NOW() - INTERVAL '14 days'
                GROUP BY proxy_id
                """,
                proxy_ids,
            )
        return {
            row["proxy_id"]: {
                "successes": int(row["successes"] or 0),
                "failures": int(row["failures"] or 0),
            }
            for row in rows
        }

    async def purge_old_feedback(self, days: int = 30) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM proxy_feedback WHERE reported_at < NOW() - INTERVAL '1 day' * $1",
                days,
            )
        return int(result.split()[-1])

    async def upsert_proxy(self, record: dict[str, Any]) -> None:
        proxy_id = make_proxy_id(record["host"], record["port"])
        now = utcnow()
        sql = """
            INSERT INTO proxies (
                id, host, port, secret, kind, generation,
                sni_domain, category, ping_ms, tspu_score,
                stability, rank, is_alive, checked_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16
            )
            ON CONFLICT (id) DO UPDATE SET
                secret      = EXCLUDED.secret,
                kind        = EXCLUDED.kind,
                generation  = EXCLUDED.generation,
                sni_domain  = EXCLUDED.sni_domain,
                category    = EXCLUDED.category,
                ping_ms     = EXCLUDED.ping_ms,
                tspu_score  = EXCLUDED.tspu_score,
                stability   = EXCLUDED.stability,
                rank        = EXCLUDED.rank,
                is_alive    = EXCLUDED.is_alive,
                checked_at  = EXCLUDED.checked_at,
                updated_at  = EXCLUDED.updated_at
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                sql,
                proxy_id, record["host"], record["port"],
                record.get("secret", ""), record.get("kind", "mtproto"),
                record.get("generation", "unknown"), record.get("sni_domain", ""),
                record.get("category", "EU"), record.get("ping_ms", 0),
                record.get("tspu_score", 0), record.get("stability", 0),
                record.get("rank", 9999), record.get("is_alive", False),
                record.get("checked_at", now), now, now,
            )

    async def upsert_many(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        now = utcnow()

        def _s(v: Any) -> str:
            """Строка без null-байтов — PostgreSQL UTF8 их не принимает."""
            return str(v or "").replace("\x00", "")

        rows = []
        for r in records:
            rows.append((
                make_proxy_id(r["host"], r["port"]),
                _s(r["host"]), r["port"],
                _s(r.get("secret", "")), _s(r.get("kind", "mtproto")),
                _s(r.get("generation", "unknown")), _s(r.get("sni_domain", "")),
                _s(r.get("category", "EU")), r.get("ping_ms", 0),
                r.get("tspu_score", 0), r.get("stability", 0),
                r.get("rank", 9999), r.get("is_alive", False),
                r.get("checked_at", now), now, now,
            ))
        sql = """
            INSERT INTO proxies (
                id, host, port, secret, kind, generation,
                sni_domain, category, ping_ms, tspu_score,
                stability, rank, is_alive, checked_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16
            )
            ON CONFLICT (id) DO UPDATE SET
                secret     = EXCLUDED.secret,
                generation = EXCLUDED.generation,
                sni_domain = EXCLUDED.sni_domain,
                category   = EXCLUDED.category,
                ping_ms    = EXCLUDED.ping_ms,
                tspu_score = EXCLUDED.tspu_score,
                stability  = EXCLUDED.stability,
                rank       = EXCLUDED.rank,
                is_alive   = EXCLUDED.is_alive,
                checked_at = EXCLUDED.checked_at,
                updated_at = EXCLUDED.updated_at
        """
        async with self._pool.acquire() as conn:
            await conn.executemany(sql, rows)
        logger.info("db: upsert_many %d записей", len(rows))

    async def get_best(
        self,
        *,
        category: str | None = None,
        generation: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        conditions = ["is_alive = TRUE"]
        params: list[Any] = []
        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        where = " AND ".join(conditions)
        params.append(limit)
        sql = f"""
            SELECT p.id, p.host, p.port, p.secret, p.kind, p.generation,
                   p.sni_domain, p.category, p.ping_ms, p.tspu_score,
                   p.stability, p.rank, p.is_alive, p.checked_at,
                   p.admin_recommended, p.admin_recommended_at,
                   COALESCE(f.successes, 0)::int AS ru_successes,
                   COALESCE(f.failures, 0)::int AS ru_failures
            FROM proxies p
            LEFT JOIN (
                SELECT proxy_id,
                       COUNT(*) FILTER (WHERE works_in_ru) AS successes,
                       COUNT(*) FILTER (WHERE NOT works_in_ru) AS failures
                FROM proxy_feedback
                WHERE reported_at > NOW() - INTERVAL '14 days'
                GROUP BY proxy_id
            ) f ON f.proxy_id = p.id
            WHERE {where.replace('is_alive', 'p.is_alive').replace('category', 'p.category').replace('generation', 'p.generation')}
            ORDER BY
                p.admin_recommended DESC,
                p.admin_recommended_at DESC NULLS LAST,
                ((COALESCE(f.successes, 0) + 2.0) /
                 (COALESCE(f.successes, 0) + COALESCE(f.failures, 0) + 4.0)) DESC,
                (COALESCE(f.successes, 0) + COALESCE(f.failures, 0)) DESC,
                p.rank ASC
            LIMIT ${len(params)}
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def mark_dead(self, proxy_ids: list[str]) -> None:
        if not proxy_ids:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE proxies SET is_alive = FALSE, updated_at = NOW() "
                "WHERE id = ANY($1::text[])",
                proxy_ids,
            )

    async def set_admin_recommendation(self, proxy_id: str, recommended: bool) -> dict[str, Any] | None:
        """Устанавливает высший ручной приоритет для живого прокси."""
        async with self._pool.acquire() as conn:
            if recommended:
                row = await conn.fetchrow(
                    """
                    UPDATE proxies
                    SET admin_recommended = TRUE,
                        admin_recommended_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1 AND is_alive = TRUE
                    RETURNING id, admin_recommended, admin_recommended_at
                    """,
                    proxy_id,
                )
            else:
                row = await conn.fetchrow(
                    """
                    UPDATE proxies
                    SET admin_recommended = FALSE,
                        admin_recommended_at = NULL,
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING id, admin_recommended, admin_recommended_at
                    """,
                    proxy_id,
                )
        return dict(row) if row else None

    async def get_admin_recommendations(self, proxy_ids: list[str]) -> dict[str, Any]:
        if not proxy_ids:
            return {}
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, admin_recommended_at
                FROM proxies
                WHERE id = ANY($1::text[]) AND admin_recommended = TRUE
                """,
                proxy_ids,
            )
        return {row["id"]: row["admin_recommended_at"] for row in rows}

    async def purge_old_dead(self, days: int = 7) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM proxies "
                "WHERE is_alive = FALSE "
                "  AND admin_recommended = FALSE "
                "  AND updated_at < NOW() - INTERVAL '1 day' * $1",
                days,
            )
        deleted = int(result.split()[-1])
        logger.info("db: purge_old_dead удалено %d строк", deleted)
        return deleted

    async def cap_proxies(self, max_rows: int = 3000) -> int:
        """
        Оставляет только max_rows прокси с лучшим рангом.
        Сначала сохраняет живые, затем добирает мёртвые до лимита.
        Возвращает число удалённых строк.
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                DELETE FROM proxies
                WHERE id NOT IN (
                    SELECT id FROM proxies
                    ORDER BY
                        admin_recommended DESC,
                        is_alive DESC,
                        rank      ASC,
                        updated_at DESC
                    LIMIT $1
                )
                """,
                max_rows,
            )
        deleted = int(result.split()[-1])
        if deleted:
            logger.info("db: cap_proxies удалено %d прокси (лимит %d)", deleted, max_rows)
        return deleted

    async def get_db_size_mb(self) -> float:
        """Возвращает размер текущей БД в МБ."""
        async with self._pool.acquire() as conn:
            size = await conn.fetchval(
                "SELECT pg_database_size(current_database())"
            )
        return round((size or 0) / (1024 * 1024), 1)

    async def stats(self) -> dict[str, int]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    COUNT(*)                                                         AS total,
                    COUNT(*) FILTER (WHERE is_alive)                                AS alive,
                    COUNT(*) FILTER (WHERE NOT is_alive)                            AS dead,
                    COUNT(*) FILTER (WHERE admin_recommended)                      AS admin_recommended,
                    COUNT(*) FILTER (WHERE category = 'RU' AND is_alive)            AS ru,
                    COUNT(*) FILTER (WHERE category = 'EU' AND is_alive)            AS eu,
                    COUNT(*) FILTER (WHERE generation = 'faketls' AND is_alive)     AS faketls,
                    COUNT(*) FILTER (WHERE generation = 'randpad' AND is_alive)     AS randpad,
                    COUNT(*) FILTER (WHERE generation = 'plain'   AND is_alive)     AS plain,
                    COUNT(*) FILTER (WHERE category = 'RU' AND generation = 'faketls' AND is_alive) AS ru_faketls,
                    COALESCE(AVG(ping_ms) FILTER (WHERE is_alive AND category = 'RU'), 0)::int AS avg_ping_ru,
                    COALESCE(AVG(ping_ms) FILTER (WHERE is_alive AND category = 'EU'), 0)::int AS avg_ping_eu,
                    COALESCE(AVG(tspu_score) FILTER (WHERE is_alive), 0)::int       AS avg_tspu,
                    COUNT(*) FILTER (WHERE is_alive AND checked_at > NOW() - INTERVAL '10 minutes') AS fresh_10m,
                    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS added_24h
                FROM proxies
            """)
        return dict(row)

    async def list_proxies(
        self,
        *,
        page: int = 1,
        limit: int = 50,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> tuple[list[dict], int]:
        """Возвращает (список прокси, total) для управления через админку."""
        conditions: list[str] = []
        params: list[Any] = []

        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        if alive_only is True:
            conditions.append("is_alive = TRUE")
        elif alive_only is False:
            conditions.append("is_alive = FALSE")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params_count = list(params)
        params_count_all = list(params)

        params.append(limit)
        params.append((page - 1) * limit)

        sql = f"""
            SELECT id, host, port, secret, generation, sni_domain,
                   category, ping_ms, tspu_score, stability, rank,
                   is_alive, admin_recommended, admin_recommended_at,
                   checked_at, updated_at
            FROM proxies
            {where}
            ORDER BY admin_recommended DESC,
                     admin_recommended_at DESC NULLS LAST,
                     rank ASC, updated_at DESC
            LIMIT ${len(params)-1} OFFSET ${len(params)}
        """
        sql_count = f"SELECT COUNT(*) FROM proxies {where}"

        async with self._pool.acquire() as conn:
            rows  = await conn.fetch(sql, *params)
            total = await conn.fetchval(sql_count, *params_count_all)
        return [dict(r) for r in rows], int(total or 0)

    async def delete_by_ids(self, ids: list[str]) -> int:
        """Удаляет прокси по списку ID. Возвращает число удалённых записей."""
        if not ids:
            return 0
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM proxies WHERE id = ANY($1::text[])", ids
            )
        return int(result.split()[-1])

    async def delete_by_filter(
        self,
        *,
        sni_contains: str | None = None,
        host_contains: str | None = None,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> int:
        """
        Удаляет прокси по фильтру. Возвращает число удалённых записей.
        Хотя бы один фильтр должен быть задан.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if sni_contains:
            params.append(f"%{sni_contains.lower()}%")
            conditions.append(f"LOWER(sni_domain) LIKE ${len(params)}")
        if host_contains:
            params.append(f"%{host_contains.lower()}%")
            conditions.append(f"LOWER(host) LIKE ${len(params)}")
        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        if alive_only is True:
            conditions.append("is_alive = TRUE")
        elif alive_only is False:
            conditions.append("is_alive = FALSE")

        if not conditions:
            raise ValueError("delete_by_filter: нужен хотя бы один фильтр")

        where = " AND ".join(conditions)
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                f"DELETE FROM proxies WHERE {where}", *params
            )
        deleted = int(result.split()[-1])
        logger.info("db: delete_by_filter удалено %d прокси (filter=%r)", deleted, conditions)
        return deleted

    async def count_by_filter(
        self,
        *,
        sni_contains: str | None = None,
        host_contains: str | None = None,
        category: str | None = None,
        generation: str | None = None,
        alive_only: bool | None = None,
    ) -> int:
        """Предварительный подсчёт числа прокси под фильтр (без удаления)."""
        conditions: list[str] = []
        params: list[Any] = []

        if sni_contains:
            params.append(f"%{sni_contains.lower()}%")
            conditions.append(f"LOWER(sni_domain) LIKE ${len(params)}")
        if host_contains:
            params.append(f"%{host_contains.lower()}%")
            conditions.append(f"LOWER(host) LIKE ${len(params)}")
        if category:
            params.append(category)
            conditions.append(f"category = ${len(params)}")
        if generation:
            params.append(generation)
            conditions.append(f"generation = ${len(params)}")
        if alive_only is True:
            conditions.append("is_alive = TRUE")
        elif alive_only is False:
            conditions.append("is_alive = FALSE")

        if not conditions:
            return 0

        where = " AND ".join(conditions)
        async with self._pool.acquire() as conn:
            return int(await conn.fetchval(f"SELECT COUNT(*) FROM proxies WHERE {where}", *params) or 0)


# ──────────────────────────────────────────────────────────────────────────────
# UserRepository
# ──────────────────────────────────────────────────────────────────────────────

class UserRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def migrate(self) -> None:
        """
        Создаёт/мигрирует все таблицы.
        Безопасно для повторного запуска (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
        """
        async with self._pool.acquire() as conn:
            # Базовые таблицы
            await conn.execute(CREATE_USERS_SQL)
            # Платёжная система удалена: стираем оставшиеся служебные таблицы
            # старых развёртываний вместе с хранившейся в них историей.
            await conn.execute("DROP TABLE IF EXISTS da_payments")
            await conn.execute("DROP TABLE IF EXISTS payments")
            await conn.execute("DROP INDEX IF EXISTS idx_users_subscribed")
            await conn.execute("ALTER TABLE users DROP COLUMN IF EXISTS is_subscribed")
            await conn.execute("ALTER TABLE users DROP COLUMN IF EXISTS sub_expires")
            await conn.execute(CREATE_AUTH_TOKENS_SQL)
            await conn.execute(CREATE_PENDING_REG_SQL)

            # ── Миграция существующей таблицы users ──────────────────────────
            # Добавляем новые колонки (для существующих БД)
            await conn.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "account_login TEXT NOT NULL DEFAULT ''"
            )
            await conn.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                "password_hash TEXT NOT NULL DEFAULT ''"
            )
            # Заполняем account_login для существующих пользователей без логина
            await conn.execute(
                "UPDATE users SET account_login = 'user' || telegram_id::text "
                "WHERE account_login = '' OR account_login IS NULL"
            )

            # Старые версии сохраняли пароль открытым текстом. Удаляем столбец
            # вместе с накопленными значениями; для входа нужен только хеш.
            await conn.execute(
                "ALTER TABLE users DROP COLUMN IF EXISTS plain_password"
            )
            # Уникальный индекс на account_login (CREATE UNIQUE INDEX IF NOT EXISTS)
            await conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_login "
                "ON users(account_login)"
            )

        logger.info("db: миграция users/pending_reg — завершена")

    # ── Пользователи ──────────────────────────────────────────────────────────

    async def register_existing_telegram_user(
        self,
        account_login: str,
        plain_password: str,
    ) -> dict:
        """Set site credentials only for a Telegram user already known to the bot."""
        login = account_login.strip().lstrip("@").lower()
        existing = await self.get_user_by_login(login)
        if not existing or int(existing["telegram_id"]) <= 0:
            raise ValueError(
                "Telegram username не найден. Сначала откройте бота в Telegram и нажмите /start."
            )
        if existing.get("password_hash"):
            raise ValueError("Аккаунт уже зарегистрирован. Войдите или сбросьте пароль в боте.")

        phash = hash_password(plain_password)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE users
                SET account_login = $2,
                    password_hash = $3,
                    updated_at = NOW()
                WHERE telegram_id = $1
                RETURNING *
                """,
                existing["telegram_id"], login, phash,
            )
        logger.info("db: site credentials set login=%s id=%d", login, existing["telegram_id"])
        return dict(row)

    async def create_web_user(
        self,
        account_login: str,
        plain_password: str,
    ) -> dict:
        """
        Создаёт нового пользователя через веб-регистрацию (без Telegram).
        Использует отрицательный случайный ID как временный telegram_id.
        Возвращает dict с данными пользователя или выбрасывает ValueError при конфликте.
        """
        import random as _random
        # Проверяем доступность логина
        existing = await self.get_user_by_login(account_login)
        if existing:
            raise ValueError("Логин уже занят.")

        # Генерируем уникальный отрицательный ID для веб-пользователей
        for _ in range(10):
            fake_id = -_random.randint(1_000_000_000, 9_999_999_999)
            async with self._pool.acquire() as conn:
                exists = await conn.fetchval(
                    "SELECT 1 FROM users WHERE telegram_id=$1", fake_id
                )
            if not exists:
                break
        else:
            raise RuntimeError("Не удалось сгенерировать уникальный ID.")

        phash = hash_password(plain_password)
        async with self._pool.acquire() as conn:
            try:
                await conn.execute(
                    """
                    INSERT INTO users
                        (telegram_id, account_login, password_hash)
                    VALUES ($1, $2, $3)
                    """,
                    fake_id, account_login, phash,
                )
            except Exception as exc:
                if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                    raise ValueError("Логин уже занят.")
                raise

        logger.info("db: web-регистрация login=%s id=%d", account_login, fake_id)
        return {"telegram_id": fake_id, "account_login": account_login}


    async def ensure_user(self, telegram_id: int, username: str = "") -> None:
        """Создаёт пустую запись пользователя, если её ещё нет."""
        login = _gen_login(telegram_id, username)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO users (telegram_id, account_login)
                VALUES ($1, $2)
                ON CONFLICT (telegram_id) DO NOTHING
                """,
                telegram_id, login,
            )

    async def upsert_user(
        self,
        telegram_id: int,
        *,
        username: str = "",
        first_name: str = "",
        last_name: str = "",
        photo_url: str = "",
    ) -> None:
        """Создаёт пользователя или обновляет профиль.
        account_login устанавливается из TG username при создании;
        для существующих — обновляется только если он ещё стандартный user{id}.
        """
        login        = _gen_login(telegram_id, username)
        default_login = f"user{telegram_id}"
        async with self._pool.acquire() as conn:
            # Создаём запись (account_login = username или user{id})
            await conn.execute(
                """
                INSERT INTO users (telegram_id, account_login, username,
                                   first_name, last_name, photo_url)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (telegram_id) DO UPDATE SET
                    username   = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    last_name  = EXCLUDED.last_name,
                    photo_url  = EXCLUDED.photo_url,
                    updated_at = NOW()
                """,
                telegram_id, login, username, first_name, last_name, photo_url,
            )
            # Обновляем account_login если он ещё стандартный placeholder
            if username:
                try:
                    await conn.execute(
                        """
                        UPDATE users SET account_login = $2, updated_at = NOW()
                        WHERE telegram_id = $1 AND account_login = $3
                        """,
                        telegram_id, login, default_login,
                    )
                except Exception:
                    pass  # username уже занят другим аккаунтом — оставляем как есть

    async def get_user(self, telegram_id: int) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE telegram_id = $1", telegram_id
            )
        return dict(row) if row else None

    async def get_user_by_login(self, account_login: str) -> Optional[dict[str, Any]]:
        """Возвращает пользователя по username (= TG username, без учёта регистра).
        Запасной вариант: поиск по account_login для обратной совместимости."""
        async with self._pool.acquire() as conn:
            # Сначала ищем по username (TG username = логин на сайте)
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE LOWER(username) = LOWER($1)",
                account_login,
            )
            if not row:
                # Запасной поиск по account_login
                row = await conn.fetchrow(
                    "SELECT * FROM users WHERE LOWER(account_login) = LOWER($1)",
                    account_login,
                )
        return dict(row) if row else None

    async def login_user(
        self, account_login: str, plain_password: str
    ) -> Optional[dict[str, Any]]:
        """
        Проверяет логин + пароль.
        Возвращает запись пользователя при успехе, иначе None.
        """
        user = await self.get_user_by_login(account_login)
        if not user:
            return None
        if not user.get("password_hash"):
            return None
        if not verify_password(plain_password, user["password_hash"]):
            return None
        if password_needs_rehash(user["password_hash"]):
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET password_hash=$2, updated_at=NOW() WHERE telegram_id=$1",
                    user["telegram_id"], hash_password(plain_password),
                )
        return user

    async def set_credentials(
        self, telegram_id: int, account_login: str, plain_password: str
    ) -> None:
        """Устанавливает / обновляет логин и пароль пользователя."""
        phash = hash_password(plain_password)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE users
                SET account_login  = $2,
                    password_hash  = $3,
                    updated_at     = NOW()
                WHERE telegram_id = $1
                """,
                telegram_id, account_login, phash,
            )

    async def ensure_credentials(self, telegram_id: int) -> tuple[str, str]:
        """
        Гарантирует, что у пользователя есть пароль.
        Если нет — генерирует автоматически.
        Возвращает (account_login, plain_password).
        Если пароль уже был установлен — возвращает (account_login, "") чтобы не пересылать его.
        """
        user = await self.get_user(telegram_id)
        if not user:
            await self.ensure_user(telegram_id)
            user = await self.get_user(telegram_id)

        if user and user.get("password_hash"):
            return user["account_login"], ""

        # Генерируем пароль, логин берём уже установленный (username или user{id})
        login    = user["account_login"] if user else _gen_login(telegram_id)
        password = _gen_password(10)
        await self.set_credentials(telegram_id, login, password)
        return login, password

    async def link_tg_to_existing(
        self,
        telegram_id: int,
        account_login: str,
        plain_password: str,
        username: str = "",
        first_name: str = "",
        last_name: str = "",
    ) -> bool:
        """
        Привязывает реальный Telegram ID к существующему аккаунту (проверяет логин+пароль).
        Удаляет временный bot-аккаунт текущего пользователя (без пароля), если есть.
        Возвращает True при успехе.
        """
        web_user = await self.get_user_by_login(account_login)
        if not web_user:
            return False
        if not web_user.get("password_hash"):
            return False
        if not verify_password(plain_password, web_user["password_hash"]):
            return False

        old_id = web_user["telegram_id"]
        if old_id == telegram_id:
            return True  # уже привязан

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Удаляем временный bot-аккаунт (если существует и без пароля)
                await conn.execute(
                    "DELETE FROM users WHERE telegram_id=$1 AND (password_hash='' OR password_hash IS NULL)",
                    telegram_id,
                )
                # Обновляем FK-ссылки во всех дочерних таблицах
                await conn.execute(
                    "UPDATE auth_tokens SET telegram_id=$1 WHERE telegram_id=$2", telegram_id, old_id
                )
                # Обновляем PK + TG-профиль
                await conn.execute(
                    """
                    UPDATE users SET
                        telegram_id = $1,
                        username    = $3,
                        first_name  = CASE WHEN $4 <> '' THEN $4 ELSE first_name END,
                        last_name   = CASE WHEN $5 <> '' THEN $5 ELSE last_name  END,
                        updated_at  = NOW()
                    WHERE telegram_id = $2
                    """,
                    telegram_id, old_id, username, first_name, last_name,
                )
        logger.info(
            "db: link_tg_to_existing — telegram_id=%d linked to login=%s (was %d)",
            telegram_id, account_login, old_id,
        )
        return True

    async def register_web_user(
        self, account_login: str, plain_password: str
    ) -> int:
        """Регистрация через сайт отключена — используйте Telegram-бота."""
        raise NotImplementedError("Регистрация только через Telegram-бота.")

    # ── Pending registrations (веб-регистрация до привязки Telegram) ──────────

    async def create_pending_reg(
        self, account_login: str, plain_password: str, ttl_minutes: int = 15
    ) -> str:
        """
        Создаёт временную запись регистрации.
        Возвращает одноразовый токен.
        """
        token      = secrets.token_urlsafe(24)
        phash      = hash_password(plain_password)
        expires_at = utcnow() + timedelta(minutes=ttl_minutes)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO pending_registrations
                    (token, account_login, password_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                """,
                token, account_login, phash, expires_at,
            )
        return token

    async def get_pending_reg(self, token: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM pending_registrations WHERE token = $1 "
                "AND expires_at > NOW()",
                token,
            )
        return dict(row) if row else None

    async def consume_pending_reg(
        self,
        token: str,
        telegram_id: int,
        first_name: str = "",
        last_name: str = "",
    ) -> Optional[dict[str, Any]]:
        """
        Привязывает telegram_id к pending-записи.
        Создаёт/обновляет пользователя в users.
        Возвращает запись pending_reg или None если токен не найден.
        """
        row = await self.get_pending_reg(token)
        if not row:
            return None

        account_login = row["account_login"]
        password_hash = row["password_hash"]

        async with self._pool.acquire() as conn:
            # Создаём пользователя (или обновляем, если уже есть)
            await conn.execute(
                """
                INSERT INTO users
                    (telegram_id, account_login, password_hash, first_name, last_name)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (telegram_id) DO UPDATE SET
                    account_login = EXCLUDED.account_login,
                    password_hash = EXCLUDED.password_hash,
                    first_name    = EXCLUDED.first_name,
                    last_name     = EXCLUDED.last_name,
                    updated_at    = NOW()
                """,
                telegram_id, account_login, password_hash, first_name, last_name,
            )
            # Отмечаем pending как выполненный
            await conn.execute(
                "UPDATE pending_registrations SET telegram_id = $2 WHERE token = $1",
                token, telegram_id,
            )
        logger.info(
            "db: pending_reg consumed — telegram_id=%d login=%s", telegram_id, account_login
        )
        return row

    async def cleanup_expired(self) -> dict:
        """
        Очистка временных токенов и незавершённых регистраций.
        Возвращает словарь с числом удалённых строк по каждой таблице.
        """
        async with self._pool.acquire() as conn:
            r1 = await conn.execute(
                "DELETE FROM auth_tokens WHERE expires_at < NOW()"
            )
            r2 = await conn.execute(
                "DELETE FROM pending_registrations WHERE expires_at < NOW()"
            )
        counts = {
            "auth_tokens":  int(r1.split()[-1]),
            "pending_regs": int(r2.split()[-1]),
        }
        if any(counts.values()):
            logger.info("db: cleanup_expired: %s", counts)
        return counts

    async def table_sizes(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    relname AS table_name,
                    pg_total_relation_size(relid) AS bytes,
                    pg_size_pretty(pg_total_relation_size(relid)) AS size
                FROM pg_catalog.pg_statio_user_tables
                ORDER BY pg_total_relation_size(relid) DESC
                """
            )
        return [dict(row) for row in rows]

    async def cleanup_pending_regs(self) -> None:
        """Удаляет просроченные pending-записи."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM pending_registrations WHERE expires_at < NOW()"
            )

    # ── Auth tokens (legacy, не используются для логина) ──────────────────────

    async def create_auth_token(self, token: str, expires_at: datetime) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO auth_tokens (token, expires_at) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING",
                token, expires_at,
            )

    async def get_auth_token(self, token: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM auth_tokens WHERE token = $1 AND expires_at > NOW()",
                token,
            )
        return dict(row) if row else None

    async def consume_auth_token(
        self,
        token: str,
        telegram_id: int,
        username: str = "",
        first_name: str = "",
        last_name: str = "",
    ) -> bool:
        row = await self.get_auth_token(token)
        if not row:
            return False
        async with self._pool.acquire() as conn:
            await self.upsert_user(
                telegram_id,
                username=username, first_name=first_name, last_name=last_name,
            )
            await conn.execute(
                "UPDATE auth_tokens SET telegram_id = $2 WHERE token = $1",
                token, telegram_id,
            )
        return True
