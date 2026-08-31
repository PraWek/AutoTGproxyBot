"""Единая типизированная конфигурация приложения из переменных окружения."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int = 65535) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} должен быть целым числом") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} должен быть в диапазоне {minimum}..{maximum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    bot_token: str
    bot_username: str
    tg_webhook_secret: str
    database_url: str
    secret_key: str
    base_url: str
    admin_password: str
    admin_path: str
    probe_region: str
    port: int

    @classmethod
    def from_env(cls) -> "Settings":
        base_url = os.getenv("BASE_URL", os.getenv("RENDER_EXTERNAL_URL", "")).strip().rstrip("/")
        return cls(
            bot_token=os.getenv("BOT_TOKEN", "").strip(),
            bot_username=os.getenv("BOT_USERNAME", "autotgproxysuperbot").strip().lstrip("@"),
            tg_webhook_secret=os.getenv("TG_WEBHOOK_SECRET", "").strip(),
            database_url=os.getenv("DATABASE_URL", "").strip(),
            secret_key=os.getenv("SECRET_KEY", "").strip(),
            base_url=base_url,
            admin_password=os.getenv("ADMIN_PASSWORD", "").strip(),
            admin_path=os.getenv("ADMIN_PATH", "admin").strip().strip("/") or "admin",
            probe_region=os.getenv("PROBE_REGION", "us-oregon").strip() or "us-oregon",
            port=_env_int("PORT", 5000),
        )

    @property
    def use_webhook(self) -> bool:
        return bool(self.bot_token and self.base_url.startswith("https://"))
