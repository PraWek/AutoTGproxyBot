import asyncio, re, time, hashlib, logging
from aiohttp import ClientSession
from config import BOT_TOKEN

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Хранилища
CACHED_BEST_PROXIES = []
banned_proxies = {}
proxy_reports = {}

CHANNELS = ["ProxyMTProto", "MTProto_Proxy", "proxymtproto_ru", "VipProxyMTProto"]
PROXY_REGEX = r"tg://proxy\?server=([^&\"]+)&(?:amp;)?port=([0-9]+)&(?:amp;)?secret=([^&\"\s<]+)"


def calculate_tspu_score(port, secret):
    score = 50
    if len(secret) == 32:
        score -= 40
    elif secret.startswith('ee'):
        score += 40
    elif secret.startswith('dd'):
        score += 30
    if port == '443':
        score += 10
    elif secret.startswith('ee') or secret.startswith('dd'):
        score -= 30
    return min(max(score, 0), 100)


async def check_proxy(server, port, secret):
    pid = hashlib.md5(f"{server}:{port}".encode()).hexdigest()[:8]
    if pid in banned_proxies and time.time() < banned_proxies[pid]: return None

    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, int(port)), timeout=1.0)
        writer.write(b'\x00');
        await writer.drain()
        await asyncio.sleep(0.05)
        ping = int((time.time() - start) * 1000)
        tspu = calculate_tspu_score(port, secret)
        return {"id": pid, "server": server, "port": port, "secret": secret, "ping": ping, "tspu": tspu,
                "rank": ping + (100 - tspu) * 5}
    except:
        return None
    finally:
        if 'writer' in locals(): writer.close()


async def proxy_updater_worker():
    global CACHED_BEST_PROXIES
    while True:
        async with ClientSession() as session:
            found = set()
            for ch in CHANNELS:
                try:
                    resp = await session.get(f"https://t.me/s/{ch}")
                    html = await resp.text()
                    found.update(re.findall(PROXY_REGEX, html))
                except:
                    continue

            tasks = [check_proxy(s, p, sec) for s, p, sec in found]
            results = await asyncio.gather(*tasks)
            live = sorted([r for r in results if r], key=lambda x: x['rank'])
            CACHED_BEST_PROXIES = live[:15]
        await asyncio.sleep(300)