#!/usr/bin/env python3
"""Check OpenAI key from OPENAI_API_KEY env."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

key = (os.getenv("OPENAI_API_KEY") or "").strip()
if not key:
    print("missing_OPENAI_API_KEY")
    sys.exit(2)

# models list is a light auth check
req = urllib.request.Request(
    "https://api.openai.com/v1/models",
    headers={"Authorization": f"Bearer {key}"},
    method="GET",
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
except urllib.error.HTTPError as e:
    print("auth_fail", e.code, e.reason)
    try:
        print(e.read().decode()[:800])
    except Exception:
        pass
    sys.exit(1)

ids = {m.get("id") for m in (body.get("data") or [])}
print("auth_ok", "n_models=", len(ids))
for want in ("gpt-4-turbo", "gpt-4o-mini", "gpt-4-turbo-2024-04-09"):
    print(f"  has_{want}=", want in ids)

payload = json.dumps(
    {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        "max_tokens": 5,
        "temperature": 0,
    }
).encode()
req2 = urllib.request.Request(
    "https://api.openai.com/v1/chat/completions",
    data=payload,
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req2, timeout=60) as resp:
        comp = json.loads(resp.read().decode())
    msg = (((comp.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    print("chat_ok", "model=", comp.get("model"), "reply=", repr(msg[:80]))
except urllib.error.HTTPError as e:
    print("chat_fail", e.code, e.reason)
    try:
        print(e.read().decode()[:800])
    except Exception:
        pass
    sys.exit(1)
