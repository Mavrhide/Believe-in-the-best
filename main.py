import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
HASH_RE = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")

app = FastAPI(title="Верьте в лучшее")


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "index.html")


@app.get("/api/check/{file_hash}")
async def check(file_hash: str):
    key = os.getenv("VT_API_KEY", "API...")
    if not key:
        raise HTTPException(500, "Не задан VT_API_KEY")
    if not HASH_RE.match(file_hash):
        raise HTTPException(400, "Нужен MD5, SHA-1 или SHA-256 хеш")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(VT_URL.format(file_hash), headers={"x-apikey": key})

    if r.status_code == 404:
        raise HTTPException(404, "VirusTotal не знает такой файл")
    if r.status_code == 429:
        raise HTTPException(429, "Лимит бесплатного ключа (4 запроса в минуту). Подождите минуту")
    if r.status_code != 200:
        raise HTTPException(502, f"VirusTotal ответил {r.status_code}")

    attrs = r.json()["data"]["attributes"]
    s = attrs["last_analysis_stats"]
    malicious = s.get("malicious", 0) + s.get("suspicious", 0)
    silent = s.get("harmless", 0) + s.get("undetected", 0)

    if silent > 0:
        verdict, message = "safe", "Файл безопасен! Верьте в лучшее."
    elif malicious > 0:
        verdict, message = "doomed", "Все единогласно против. Тут даже верить не во что."
    else:
        verdict, message = "unknown", "Антивирусы пока не определились."

    return {
        "verdict": verdict,
        "message": message,
        "malicious": malicious,
        "silent": silent,
        "total": malicious + silent,
        "name": attrs.get("meaningful_name"),
    }