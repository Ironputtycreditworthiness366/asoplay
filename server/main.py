# -*- coding: utf-8 -*-
"""
AnimeViev — proprietary. (c) Chepela Daniel Maximovich (x0doit, https://crazydev.pro/).
All rights reserved. See /COPYRIGHT for full terms.

FastAPI wiring. The heavy lifting lives in sibling modules:

    vpn_bridge.py     — xray launcher (started from FastAPI lifecycle, not imports)
    proxies.py        — Jikan/AniList/Shiki/translate/img with shared disk cache
    animesocial.py    — DB bridge + auth (/auth/*)
    account_api.py    — authenticated favorites/history/progress/ratings (/account/*)
    title_pages.py    — canonical /anime/{id}-{slug}/ SSR + sitemap + robots
    animevost.py      — native client to api.animevost.org
    oldyummy.py       — native client to old.yummyani.me/api

This file owns: env loading, CORS, startup/shutdown hooks, source registry
(anicli-api + native sources), and the search/episodes/dubs/videos routes that
every source plugin shares.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random as _random
import re as _re
import time
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger("animeviev")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    load_dotenv(_PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass  # python-dotenv is optional; plain env vars still work

# VPN must not start during import — that was the old bug. We arm it from the
# FastAPI startup event below. Importing the module is cheap and side-effect
# free.
from server import (
    vpn_bridge, proxies, animesocial, account_api,
    title_pages, user_lists, activity_log, profile_pages, adblock, player_proxy,
    source_health,
)


import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

# Sources live next to main.py; when running as `uvicorn server.main:app` the
# package layout picks them up. Both import styles are tried for resilience.
try:
    from server.animevost import Animevost
    from server.oldyummy import OldYummy
except ImportError:
    from animevost import Animevost  # type: ignore
    from oldyummy import OldYummy  # type: ignore


# ---------- source registry ----------
SOURCES: dict[str, Any] = {}
NATIVE_SOURCES: dict[str, Any] = {}


def _register(name: str, import_paths: list[str]) -> None:
    for path in import_paths:
        try:
            module = __import__(path, fromlist=["Extractor"])
            cls = getattr(module, "Extractor", None)
            if cls is None:
                continue
            SOURCES[name] = cls()
            log.info("source loaded: %s (%s)", name, path)
            return
        except Exception as exc:
            log.debug("skip %s (%s): %s", name, path, exc)
    log.warning("source not available: %s", name)


for _name in (
    "yummy_anime",
    "animego",
    "yummy_anime_org",
    "dreamcast",
    "anilibria",
    "anilibme",
    "sameband",
):
    _register(_name, [f"anicli_api.source.{_name}"])

try:
    NATIVE_SOURCES["oldyummy"] = OldYummy()
    log.info("source loaded: oldyummy (native)")
except Exception as exc:
    log.warning("native oldyummy failed to load: %s", exc)
try:
    NATIVE_SOURCES["animevost"] = Animevost()
    log.info("source loaded: animevost (native)")
except Exception as exc:
    log.warning("native animevost failed to load: %s", exc)

if not SOURCES:
    log.error("ни один источник anicli-api не загрузился. pip install anicli-api")


# ---------- app ----------
_DEFAULT_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8787",
    "http://localhost:8787",
]
_allowed = os.environ.get("AV_ALLOWED_ORIGINS", "").strip()
if _allowed == "*":
    ALLOWED_ORIGINS: list[str] = ["*"]
elif _allowed:
    ALLOWED_ORIGINS = [o.strip() for o in _allowed.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = _DEFAULT_ORIGINS
log.info("CORS allowed origins: %s", ALLOWED_ORIGINS)

app = FastAPI(title="AnimeViev Backend", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


@app.middleware("http")
async def _player_proxy_null_origin_cors(request: Request, call_next):
    # Proxied players run inside a sandbox without allow-same-origin. Browser
    # fetch/XHR requests from that frame therefore use Origin: null. Keep this
    # exception scoped to /player/proxy so account/auth APIs are not exposed to
    # arbitrary opaque-origin documents.
    if (
        (request.url.path.startswith("/player/proxy") or request.url.path.startswith("/player/cvh-api"))
        and request.headers.get("origin") == "null"
    ):
        if request.method == "OPTIONS":
            return Response(headers={
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": request.headers.get("access-control-request-headers", "*"),
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "600",
            })
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "null"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
        return response
    return await call_next(request)


# ---------- lifecycle ----------
@app.on_event("startup")
async def _startup() -> None:
    # Start xray here, not at import time — tests and tooling can now import
    # the server module without spawning processes.
    if vpn_bridge.activate():
        log.info("VPN bridge active via %s", vpn_bridge.VPN_PROXY_URL)
    else:
        log.info("VPN bridge not active — falling back to direct outbound")
    vpn_bridge.start_watchdog()
    await proxies.startup()
    await adblock.startup()
    await player_proxy.startup()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await player_proxy.shutdown()
    await adblock.shutdown()
    await proxies.shutdown()
    vpn_bridge.shutdown()


# ---------- in-memory key cache for source objects ----------
_CACHE: dict[str, Any] = {}


def _put(obj: Any) -> str:
    k = uuid.uuid4().hex
    _CACHE[k] = obj
    if len(_CACHE) > 4000:
        for old in list(_CACHE.keys())[:1000]:
            _CACHE.pop(old, None)
    return k


def _get(key: str) -> Any:
    obj = _CACHE.get(key)
    if obj is None:
        raise HTTPException(410, "объект устарел, повторите поиск")
    return obj


def _get_extractor(source: str):
    if source not in SOURCES:
        raise HTTPException(400, f"source '{source}' недоступен. Доступные: {list(SOURCES)}")
    return SOURCES[source]


async def _run(fn, *args, **kwargs):
    if asyncio.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    return await asyncio.to_thread(fn, *args, **kwargs)


def _all_sources() -> list[str]:
    return list(SOURCES) + list(NATIVE_SOURCES)


def _source_unavailable(source: str) -> HTTPException:
    wait = source_health.cooldown_remaining(source)
    return HTTPException(
        503,
        f"source '{source}' is cooling down after repeated failures; retry in {wait}s",
    )


async def _guard_source(source: str, op: str, awaitable, timeout: float):
    if not source_health.is_available(source):
        cancel = getattr(awaitable, "cancel", None)
        close = getattr(awaitable, "close", None)
        if callable(cancel):
            cancel()
        elif callable(close):
            close()
        raise _source_unavailable(source)
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(awaitable, timeout=timeout)
    except HTTPException:
        raise
    except asyncio.TimeoutError as exc:
        source_health.mark_failure(source, f"{op} timeout after {timeout}s")
        raise HTTPException(504, f"{op} timeout") from exc
    except Exception as exc:
        source_health.mark_failure(source, exc)
        raise
    else:
        elapsed = int((time.perf_counter() - started) * 1000)
        source_health.mark_success(source, elapsed)
        return result


# ---------- status endpoints ----------
@app.get("/health")
def health():
    active_sources = source_health.available_sources(_all_sources())
    return {
        "ok": True,
        "sources": active_sources,
        "vpn": vpn_bridge.is_active(),
        "db": animesocial.health(),
        "adblock": adblock.status(),
        "source_health": source_health.snapshot(_all_sources()),
    }


@app.get("/sources")
def sources():
    return source_health.available_sources(_all_sources())


@app.get("/source-health")
def source_health_status():
    return source_health.snapshot(_all_sources())


@app.get("/adblock/status")
def adblock_status():
    return adblock.status()


@app.get("/adblock/check")
def adblock_check(url: str = Query(..., min_length=4)):
    blocked, reason = adblock.should_block(url)
    return {"blocked": blocked, "reason": reason}


# ---------- source-based search / episodes / dubs / videos ----------
def _filter_by_year(results: list[dict], year: int | None) -> list[dict]:
    if not year:
        return results

    def _y(x):
        try:
            return int(str(x.get("year") or 0))
        except (TypeError, ValueError):
            return 0

    filtered = [r for r in results if _y(r) == 0 or abs(_y(r) - year) <= 1]
    return filtered or results


@app.get("/src/search")
async def search(
    q: str = Query(..., min_length=1),
    source: str = "anilibria",
    year: int | None = None,
    mal_id: int | None = None,
):
    if source in NATIVE_SOURCES:
        try:
            results = await _guard_source(
                source,
                "search",
                _native_search(source, q, mal_id=mal_id),
                timeout=10.0,
            )
        except Exception as exc:
            log.info("search failed on %s: %s (returning empty)", source, exc)
            return []
        return _filter_by_year(results, year)

    ext = _get_extractor(source)
    try:
        results = await _guard_source(source, "search", _run(ext.search, q), timeout=10.0)
    except Exception as exc:
        # Source-скрейперы anicli-api (animego, dreamcast, yummy_anime_org…)
        # регулярно падают: у них сайт-цель или блокирует запрос, или сменил
        # вёрстку, или rate-limit'ит. Плеер перебирает источники в цепочку и
        # уже обрабатывает «пусто» как «иду дальше» — ему не нужен 502.
        # Возвращаем [] вместо throw, чтобы browser-консоль не пестрила
        # красным. Причину по-прежнему видно в server-логе.
        log.info("search failed on %s: %s (returning empty)", source, exc)
        return []

    out = []
    for r in results[:20]:
        title = getattr(r, "title", None) or getattr(r, "name", None) or str(r)
        thumb = getattr(r, "thumbnail", None) or getattr(r, "poster", None) or getattr(r, "image", None)
        url = getattr(r, "url", None)

        item_year = None
        mal_id_hit = None
        raw_data = getattr(r, "data", None)
        if isinstance(raw_data, dict):
            for k in ("year", "release_year", "releasedOn"):
                v = raw_data.get(k)
                if v:
                    try:
                        item_year = int(str(v)[:4])
                        break
                    except (TypeError, ValueError):
                        pass
            ri = raw_data.get("remote_ids")
            if isinstance(ri, dict):
                mal_id_hit = ri.get("myanimelist_id") or ri.get("mal_id")
                try:
                    mal_id_hit = int(mal_id_hit) if mal_id_hit else None
                except (TypeError, ValueError):
                    mal_id_hit = None
        if item_year is None:
            for attr in ("year", "release_year"):
                v = getattr(r, attr, None)
                if v:
                    try:
                        item_year = int(str(v)[:4])
                        break
                    except (TypeError, ValueError):
                        pass

        out.append({
            "title": title,
            "title_en": getattr(r, "title_english", None) or getattr(r, "alt_title", None),
            "thumbnail": thumb,
            "url": url,
            "year": item_year,
            "key": _put(r),
            "source": source,
            "mal_id": mal_id_hit,
        })
    return _filter_by_year(out, year)


@app.get("/src/episodes")
async def episodes(key: str, source: str = "anilibria"):
    if source in NATIVE_SOURCES:
        return await _guard_source(
            source,
            "episodes",
            _native_episodes(source, key),
            timeout=12.0,
        )

    search_result = _get(key)
    try:
        get_anime = getattr(search_result, "a_get_anime", None) or search_result.get_anime
        anime = await _guard_source(source, "anime", _run(get_anime), timeout=12.0)
        get_eps = getattr(anime, "a_get_episodes", None) or anime.get_episodes
        episodes_list = await _guard_source(source, "episodes", _run(get_eps), timeout=12.0)
    except HTTPException:
        raise
    except Exception as exc:
        log.exception("episodes failed")
        raise HTTPException(502, f"episodes failed: {exc}")

    out = []
    for idx, e in enumerate(episodes_list):
        num = getattr(e, "num", None) or getattr(e, "number", None) or idx + 1
        title = getattr(e, "title", None) or getattr(e, "name", None) or f"Эпизод {num}"
        out.append({"num": num, "title": title, "key": _put(e)})
    return out


def _norm_dub_name(name: str) -> str:
    s = (name or "").lower().strip()
    for prefix in ("озвучка ", "субтитры ", "оригинал ", "original ", "voice ", "sub "):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = _re.sub(r"\((ru|en|jp|ja|рус|русс?кий|англ\w*|яп\w*)\)", "", s)
    s = _re.sub(r"[^\w\s]+", " ", s)
    s = _re.sub(r"\s+", " ", s).strip()
    return s


def _iframe_preference_score(url: str) -> int:
    value = (url or "").lower()
    if "iframecvh.html" in value:
        return 30
    if "kodikplayer.com" in value:
        return 20
    if "alloha.yani.tv" in value:
        return 10
    return 0


@app.get("/src/dubs")
async def dubs_for_episode(key: str, source: str = "anilibria"):
    if source in NATIVE_SOURCES:
        return await _guard_source(
            source,
            "dubs",
            _native_dubs(source, key),
            timeout=12.0,
        )

    episode = _get(key)
    try:
        get_sources = getattr(episode, "a_get_sources", None) or episode.get_sources
        sources_list = await _guard_source(source, "dubs", _run(get_sources), timeout=12.0)
    except HTTPException:
        raise
    except Exception as exc:
        log.exception("sources failed")
        raise HTTPException(502, f"sources failed: {exc}")

    seen: dict[str, dict] = {}
    for s in sources_list:
        name = getattr(s, "title", None) or getattr(s, "name", None) or "—"
        norm = _norm_dub_name(name)
        if not norm or norm in seen:
            continue
        kind = "sub" if "субтитры" in name.lower() or "sub" in name.lower() else "voice"
        seen[norm] = {"name": name.strip(), "norm": norm, "kind": kind, "key": _put(s)}
    return list(seen.values())


@app.get("/src/videos")
async def videos(key: str, source: str = "anilibria"):
    if source in NATIVE_SOURCES:
        vids = await _guard_source(
            source,
            "videos",
            _native_videos(source, key),
            timeout=15.0,
        )
        return await adblock.filter_videos(vids)

    obj = _get(key)
    if hasattr(obj, "get_videos") or hasattr(obj, "a_get_videos"):
        name = getattr(obj, "title", None) or getattr(obj, "name", None)
        iframe_url = getattr(obj, "url", None) or ""

        if iframe_url.startswith("http"):
            return await adblock.filter_videos([{
                "url": iframe_url, "quality": None, "type": "iframe",
                "headers": {}, "source_name": name,
            }])

        out: list[dict] = []
        try:
            get_videos = getattr(obj, "a_get_videos", None) or obj.get_videos
            vids = await _guard_source(source, "videos", _run(get_videos), timeout=15.0)
            for v in vids:
                url = getattr(v, "url", None) or str(v)
                if not url:
                    continue
                out.append({
                    "url": url, "quality": getattr(v, "quality", None),
                    "type": getattr(v, "type", None) or ("m3u8" if ".m3u8" in url else "mp4"),
                    "headers": getattr(v, "headers", None) or {},
                    "source_name": name,
                })
        except Exception as exc:
            log.debug("videos extract failed: %s", exc)
        return await adblock.filter_videos(out)

    # Legacy branch — extractor gave us an Episode, we'd enumerate sources × videos.
    episode = obj
    try:
        get_sources = getattr(episode, "a_get_sources", None) or episode.get_sources
        sources_list = await _guard_source(source, "video sources", _run(get_sources), timeout=12.0)

        sem = asyncio.Semaphore(8)

        async def fetch_one(s):
            async with sem:
                try:
                    get_videos = getattr(s, "a_get_videos", None) or s.get_videos
                    vids = await asyncio.wait_for(_run(get_videos), timeout=8.0)
                except Exception as exc:
                    log.debug("source videos skipped: %s", exc)
                    return []
                out = []
                name = getattr(s, "title", None) or getattr(s, "name", None)
                for v in vids:
                    url = getattr(v, "url", None) or str(v)
                    if not url:
                        continue
                    quality = getattr(v, "quality", None)
                    vtype = getattr(v, "type", None) or ("m3u8" if ".m3u8" in url else "mp4")
                    headers = getattr(v, "headers", None) or {}
                    out.append({"url": url, "quality": quality, "type": vtype,
                                "headers": headers, "source_name": name})
                return out

        grouped = await _guard_source(
            source,
            "videos",
            asyncio.gather(*[fetch_one(s) for s in sources_list], return_exceptions=True),
            timeout=15.0,
        )
        all_videos: list[dict] = []
        for g in grouped:
            if isinstance(g, list):
                all_videos.extend(g)
    except HTTPException:
        raise
    except Exception as exc:
        log.exception("videos failed")
        raise HTTPException(502, f"videos failed: {exc}")

    def score(v):
        q = v.get("quality") or 0
        try:
            q = int(str(q).replace("p", ""))
        except ValueError:
            q = 0
        return (1 if v["type"] == "m3u8" else 0, q)

    all_videos.sort(key=score, reverse=True)
    return await adblock.filter_videos(all_videos)


# ---------- native source glue ----------
async def _native_search(source: str, q: str, mal_id: int | None = None):
    if source == "animevost":
        vost: Animevost = NATIVE_SOURCES["animevost"]
        results = await vost.search(q, limit=20)
        out = []
        for item in results:
            k = _put({
                "type": "anime", "source": "animevost",
                "vost_id": item["id"], "title": item["title_ru"] or item["title"],
            })
            out.append({
                "title": item["title_ru"] or item["title"],
                "title_en": item.get("title_en"),
                "thumbnail": item.get("image"),
                "url": f"https://animevost.org/tip/tv/{item['id']}-x.html",
                "key": k, "source": "animevost",
                "year": item.get("year"), "note": item.get("note"),
            })
        return out

    if source == "oldyummy":
        oy: OldYummy = NATIVE_SOURCES["oldyummy"]
        results = await oy.search(q, limit=20)
        if mal_id:
            exact = [r for r in results if r.get("mal_id") == mal_id]
            if exact:
                results = exact + [r for r in results if r not in exact]
        out = []
        for item in results:
            k = _put({
                "type": "anime", "source": "oldyummy",
                "anime_id": item["id"], "title": item["title"],
                "mal_id": item.get("mal_id"),
            })
            out.append({
                "title": item["title"],
                "title_en": item.get("title_en"),
                "thumbnail": item.get("thumbnail"),
                "url": f"https://old.yummyani.me/catalog/item/{item.get('alias','')}",
                "key": k, "source": "oldyummy",
                "year": item.get("year"),
                "mal_id": item.get("mal_id"),
            })
        return out

    raise HTTPException(400, f"unknown native source {source}")


async def _native_episodes(source: str, key: str):
    obj = _get(key)

    if source == "animevost" and obj.get("source") == "animevost":
        vost: Animevost = NATIVE_SOURCES["animevost"]
        eps = await vost.episodes(obj["vost_id"])
        out = []
        for e in eps:
            ek = _put({"type": "episode", "source": "animevost", "qualities": e["qualities"]})
            out.append({"num": e["num"], "title": e["name"], "key": ek, "preview": e.get("preview")})
        return out

    if source == "oldyummy" and obj.get("source") == "oldyummy":
        oy: OldYummy = NATIVE_SOURCES["oldyummy"]
        raw = await oy.videos(obj["anime_id"])
        by_num: dict[int, list[dict]] = {}
        for v in raw:
            try:
                num = int(str(v.get("number") or "0").strip() or 0)
            except (TypeError, ValueError):
                num = 0
            if not num:
                continue
            by_num.setdefault(num, []).append(v)
        out = []
        for num in sorted(by_num.keys()):
            dubs = by_num[num]
            ek = _put({"type": "episode", "source": "oldyummy", "dubs": dubs})
            out.append({"num": num, "title": None, "key": ek, "preview": None})
        return out

    raise HTTPException(400, "bad episode source")


async def _native_dubs(source: str, key: str):
    obj = _get(key)
    if source == "oldyummy" and obj.get("source") == "oldyummy":
        seen: dict[str, dict] = {}
        for v in obj.get("dubs", []):
            d = v.get("data") or {}
            name = (d.get("dubbing") or d.get("player") or "—").strip()
            norm = _norm_dub_name(name)
            if not norm:
                continue
            iframe_url = v.get("iframe_url") or ""
            score = _iframe_preference_score(iframe_url)
            if norm in seen and score <= seen[norm].get("_score", -1):
                continue
            kind = "sub" if "субтитры" in name.lower() else "voice"
            dk = _put({"type": "dub", "source": "oldyummy",
                       "iframe_url": iframe_url, "name": name})
            seen[norm] = {"name": name, "norm": norm, "kind": kind, "key": dk, "_score": score}
        return [
            {item_key: item_value for item_key, item_value in item.items() if item_key != "_score"}
            for item in seen.values()
        ]
    return []


async def _native_videos(source: str, key: str):
    obj = _get(key)

    if source == "animevost" and obj.get("source") == "animevost":
        return [
            {"url": q["url"], "quality": q.get("quality"), "type": q.get("type", "mp4"),
             "headers": {}, "source_name": "Animevost"}
            for q in obj.get("qualities", [])
        ]

    if source == "oldyummy" and obj.get("source") == "oldyummy":
        iframe = obj.get("iframe_url") or ""
        if iframe.startswith("//"):
            iframe = "https:" + iframe
        return [{
            "url": iframe, "quality": None, "type": "iframe",
            "headers": {}, "source_name": obj.get("name", "OldYummy"),
        }]

    raise HTTPException(400, "bad video source")


# ---------- random watchable ----------
_OLDYUMMY_CATALOG_MAX = 10000


@app.get("/random/watchable")
async def random_watchable():
    client = await proxies.get_client()
    tried: set[int] = set()
    for _ in range(15):
        offset = _random.randint(0, _OLDYUMMY_CATALOG_MAX - 1)
        if offset in tried:
            continue
        tried.add(offset)
        try:
            r = await client.get(
                f"https://old.yummyani.me/api/anime?limit=1&offset={offset}",
                timeout=8, headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code != 200:
                continue
            data = r.json()
            resp = data.get("response")
            items = resp if isinstance(resp, list) else (resp or {}).get("data", [])
            if not items:
                continue
            a = items[0]
            mal_id = (a.get("remote_ids") or {}).get("myanimelist_id")
            if not mal_id:
                continue
            type_alias = (a.get("type") or {}).get("alias", "")
            if type_alias in ("music", "cm", "pv"):
                continue
            dur = a.get("duration", 0) or 0
            if type_alias == "movie" and dur and dur < 40 * 60:
                continue
            if type_alias != "movie" and dur and dur < 8 * 60:
                continue
            rating = (a.get("rating") or {}).get("average", 0) or 0
            if rating and rating < 6:
                continue
            try:
                check = await client.get(
                    f"https://api.jikan.moe/v4/anime/{mal_id}", timeout=5,
                )
                if check.status_code != 200:
                    continue
            except httpx.HTTPError:
                continue
            return {
                "mal_id": int(mal_id),
                "anime_id": a.get("anime_id"),
                "title": a.get("title"),
                "year": a.get("year"),
                "type": type_alias,
            }
        except httpx.HTTPError as exc:
            log.debug("random watchable attempt failed: %s", exc)
            continue
    raise HTTPException(502, "random pool unreachable")


# ---------- register sibling routers ----------
app.include_router(proxies.router)
app.include_router(animesocial.router)
app.include_router(account_api.router)
app.include_router(user_lists.router)
app.include_router(activity_log.router)
app.include_router(profile_pages.router)
app.include_router(player_proxy.router)
app.include_router(player_proxy.kodik_router)
app.include_router(title_pages.router)


# ---------- static assets + SPA shell ----------
# app.js, /js/*.js, styles.css are served from the project root as-is so the
# dev workflow (open index.html via Live Server) and the production workflow
# (uvicorn serving everything) stay on the same file tree.
class _StaticAssets(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        if resp.status_code == 200:
            # Long cache for static assets; index.html (served via title_pages
            # / shell routes) has its own short TTL.
            if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico")):
                resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp


_ASSET_DIRS = [
    ("/styles.css", _PROJECT_ROOT / "styles.css"),
    ("/app.js", _PROJECT_ROOT / "app.js"),
]


def _file_route(app: FastAPI, route: str, path: Path, media: str | None = None) -> None:
    @app.get(route, include_in_schema=False)
    def _serve():
        if not path.is_file():
            raise HTTPException(404)
        data = path.read_bytes()
        ct = media or (
            "text/css" if path.suffix == ".css"
            else "application/javascript" if path.suffix == ".js"
            else "application/octet-stream"
        )
        return Response(
            data, media_type=ct,
            headers={"Cache-Control": "public, max-age=60"},
        )


for _route, _path in _ASSET_DIRS:
    _file_route(app, _route, _path)

# Serve the whole /js/ directory if present (split frontend modules live here).
_JS_DIR = _PROJECT_ROOT / "js"
if _JS_DIR.is_dir():
    app.mount("/js", _StaticAssets(directory=str(_JS_DIR)), name="js")

# Brand assets: logos, icons. Directory is created on startup so /assets always
# resolves (empty 404 until files are added).
_ASSETS_DIR = _PROJECT_ROOT / "assets"
_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/assets", _StaticAssets(directory=str(_ASSETS_DIR)), name="assets")

# Shell routes (home, catalog, trending, account...) go LAST so they don't
# eat API routes like /search or /episodes.
title_pages.register_shell_routes(app)


if __name__ == "__main__":
    host = os.environ.get("AV_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("AV_BIND_PORT", "8787"))
    uvicorn.run(app, host=host, port=port, log_level="info")
