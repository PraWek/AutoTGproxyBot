import asyncio
import os
from aiohttp import web
from aiogram import Bot, Dispatcher
from config import BOT_TOKEN
from handlers import router
from worker import proxy_updater_worker


async def main():
    """Главная функция - запуск бота и воркера обновления прокси"""
    # Инициализируем бота и диспетчер команд
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    # Создаём микро-веб-сервер для Render (иначе платформа не разрешает запуск)
    app = web.Application()
    app.router.add_get('/', lambda r: web.Response(text="Бот работает и чувствует себя отлично!"))

    runner = web.AppRunner(app)
    await runner.setup()

    # Render предоставляет PORT через переменную окружения
    port = int(os.getenv("PORT", 10000))
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    print(f"Микро-сервер запущен на порту {port}. Render доволен.")

    # Запускаем полинг Telegram и воркер обновления прокси одновременно
    await asyncio.gather(
        dp.start_polling(bot),
        proxy_updater_worker()
    )


if __name__ == "__main__":
    asyncio.run(main())
