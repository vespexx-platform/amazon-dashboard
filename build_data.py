#!/usr/bin/env python3
"""Make Data Store의 'latest'(최근 창)를 읽어, 레포에 암호화 저장된 기존
히스토리(site/data.js)와 **병합**해 누적한다. 결과를 다시 AES-GCM으로 암호화해
site/data.js 로 저장(공개 Pages에 암호문만 노출) → 워크플로가 커밋해 영속화.

이 구조 덕분에 Make 스토어는 최근 창만 유지(1MB 제한 회피)하고, 전체 히스토리는
레포에 암호문으로 무한 누적된다.

환경변수:
  MAKE_API_TOKEN, MAKE_ZONE, MAKE_STORE_ID   Make 데이터 접근
  DASHBOARD_PASSWORD                          열람/암복호화 비밀번호
"""

import base64
import datetime as dt
import json
import os
import urllib.request
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAKE_ZONE = os.environ.get("MAKE_ZONE", "us2.make.com")
MAKE_TOKEN = os.environ["MAKE_API_TOKEN"]
STORE_ID = os.environ["MAKE_STORE_ID"]
PASSWORD = os.environ["DASHBOARD_PASSWORD"]
TZ = ZoneInfo(os.environ.get("REPORT_TZ", "America/Los_Angeles"))
PBKDF2_ITERS = 200_000
DATA_JS = "site/data.js"


def read_latest():
    req = urllib.request.Request(
        f"https://{MAKE_ZONE}/api/v2/data-stores/{STORE_ID}/data",
        headers={"Authorization": f"Token {MAKE_TOKEN}", "User-Agent": "amazon-dashboard/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read().decode())
    for rec in d.get("records", []):
        if rec.get("key") == "latest":
            return json.loads(base64.b64decode(rec["data"]["blob"]).decode())
    raise RuntimeError("'latest' 레코드 없음")


def series(report):
    out = []
    for r in report.get("salesAndTrafficByDate", []):
        s, t = r["salesByDate"], r["trafficByDate"]
        out.append({
            "date": r["date"],
            "sales": round(s["orderedProductSales"]["amount"], 2),
            "units": s["unitsOrdered"], "items": s["totalOrderItems"],
            "refunded": s["unitsRefunded"], "refundRate": round(s["refundRate"], 2),
            "pageViews": t["pageViews"], "sessions": t["sessions"],
            "conv": round(t["unitSessionPercentage"], 2), "buybox": round(t["buyBoxPercentage"], 2),
            "feedback": t["feedbackReceived"], "negFeedback": t["negativeFeedbackReceived"],
        })
    return out


def _key(salt):
    return PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS).derive(PASSWORD.encode())


def encrypt(plaintext: str) -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(salt)).encrypt(iv, plaintext.encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"salt": b(salt), "iv": b(iv), "iters": PBKDF2_ITERS, "ct": b(ct)}


def load_history():
    """레포에 커밋된 site/data.js를 복호화해 기존 series 반환(없거나 실패 시 빈 리스트)."""
    if not os.path.exists(DATA_JS):
        return []
    try:
        txt = open(DATA_JS).read()
        enc = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
        key = PBKDF2HMAC(algorithm=SHA256(), length=32,
                         salt=base64.b64decode(enc["salt"]), iterations=enc["iters"]).derive(PASSWORD.encode())
        pt = AESGCM(key).decrypt(base64.b64decode(enc["iv"]), base64.b64decode(enc["ct"]), None)
        return json.loads(pt.decode()).get("series", [])
    except Exception as e:  # 비밀번호 변경/손상 시 히스토리 리셋(최근 창으로 복구)
        print(f"warning: 기존 히스토리 로드 실패({e}) — 최근 데이터로 재구성")
        return []


def main():
    recent = series(read_latest())
    by_date = {r["date"]: r for r in load_history()}
    by_date.update({r["date"]: r for r in recent})  # 최근 값이 동일 날짜를 갱신
    merged = sorted(by_date.values(), key=lambda x: x["date"])

    payload = {
        "generated": dt.datetime.now(TZ).strftime("%Y-%m-%d %H:%M %Z"),
        "tz": "US 태평양시", "series": merged,
    }
    os.makedirs("site", exist_ok=True)
    with open(DATA_JS, "w") as f:
        f.write("window.__ENC__ = " + json.dumps(encrypt(json.dumps(payload, ensure_ascii=False))) + ";\n")
    print(f"data.js written — 누적 {len(merged)}일 (최근 {len(recent)}일 병합)")


if __name__ == "__main__":
    main()
