import asyncio
from aiogram import Bot, Dispatcher
from config import BOT_TOKEN
from handlers import router
from worker import proxy_updater_worker

async def main():
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await asyncio.gather(dp.start_polling(bot), proxy_updater_worker())

if __name__ == "__main__":
    asyncio.run(main())