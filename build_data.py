#!/usr/bin/env python3
"""Make Data Store의 'latest'를 읽어 대시보드용 시계열로 가공하고,
비밀번호로 AES-GCM 암호화해 data.js 로 저장한다(공개 Pages에 암호문만 노출).

환경변수:
  MAKE_API_TOKEN, MAKE_ZONE, MAKE_STORE_ID   Make 데이터 접근
  DASHBOARD_PASSWORD                          대시보드 열람 비밀번호
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


def read_latest():
    req = urllib.request.Request(
        f"https://{MAKE_ZONE}/api/v2/data-stores/{STORE_ID}/data",
        headers={"Authorization": f"Token {MAKE_TOKEN}",
                 "User-Agent": "amazon-dashboard/1.0"})
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
            "units": s["unitsOrdered"],
            "items": s["totalOrderItems"],
            "refunded": s["unitsRefunded"],
            "refundRate": round(s["refundRate"], 2),
            "pageViews": t["pageViews"],
            "sessions": t["sessions"],
            "conv": round(t["unitSessionPercentage"], 2),
            "buybox": round(t["buyBoxPercentage"], 2),
            "feedback": t["feedbackReceived"],
            "negFeedback": t["negativeFeedbackReceived"],
        })
    out.sort(key=lambda x: x["date"])
    return out


def encrypt(plaintext: str, password: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ITERS).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)  # tag가 ct 끝에 포함
    b64 = lambda b: base64.b64encode(b).decode()
    return {"salt": b64(salt), "iv": b64(iv), "iters": PBKDF2_ITERS, "ct": b64(ct)}


def main():
    report = read_latest()
    payload = {
        "generated": dt.datetime.now(TZ).strftime("%Y-%m-%d %H:%M %Z"),
        "tz": "US 태평양시",
        "series": series(report),
    }
    enc = encrypt(json.dumps(payload, ensure_ascii=False), PASSWORD)
    os.makedirs("site", exist_ok=True)
    with open("site/data.js", "w") as f:
        f.write("window.__ENC__ = " + json.dumps(enc) + ";\n")
    print(f"data.js written — {len(payload['series'])} days, encrypted")


if __name__ == "__main__":
    main()
