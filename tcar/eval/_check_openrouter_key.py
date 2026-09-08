#!/usr/bin/env python3
"""Check OpenRouter key from OPENROUTER_API_KEY env (do not hardcode)."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
if not key:
    print("missing_OPENROUTER_API_KEY")
    sys.exit(2)

req = urllib.request.Request(
    "https://openrouter.ai/api/v1/auth/key",
    headers={"Authorization": f"Bearer {key}"},
    method="GET",
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
except urllib.error.HTTPError as e:
    print("auth_fail", e.code, e.reason)
    try:
        print(e.read().decode()[:500])
    except Exception:
        pass
    sys.exit(1)
except Exception as e:
    print("auth_fail", type(e).__name__, e)
    sys.exit(1)

data = body.get("data") or body
out = {
    k: data.get(k)
    for k in (
        "label",
        "is_free_tier",
        "limit",
        "limit_remaining",
        "usage",
        "usage_daily",
        "usage_monthly",
        "rate_limit",
    )
    if data.get(k) is not None
}
print("auth_ok")
print(json.dumps(out, indent=2))

# Tiny completion probe with a cheap model if auth ok
payload = json.dumps(
    {
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        "max_tokens": 5,
        "temperature": 0,
    }
).encode()
req2 = urllib.request.Request(
    "https://openrouter.ai/api/v1/chat/completions",
    data=payload,
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/local/cti-chatbot",
        "X-Title": "CTI-Chatbot-key-check",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req2, timeout=60) as resp:
        comp = json.loads(resp.read().decode())
    msg = (((comp.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    model = comp.get("model")
    print("chat_ok", "model=", model, "reply=", repr(msg[:80]))
except urllib.error.HTTPError as e:
    print("chat_fail", e.code, e.reason)
    try:
        print(e.read().decode()[:500])
    except Exception:
        pass
    sys.exit(1)
