"""Policy layer between Gemini and the tools. The model can be fooled; this code can't."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.parse
from datetime import datetime

from .tools import JOBS, OUTPUT, PROFILE, RULES

AUDIT = OUTPUT / "audit.jsonl"
SENSITIVE_VALUES = [v for v in PROFILE["SENSITIVE"].values()]
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){3,7}[A-Z0-9]{1,4}\b")


def _audit(event, tool, args, detail, ctx):
    with open(AUDIT, "a") as f:
        f.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), "agent": ctx.agent_name,
                            "event": event, "tool": tool, "args": {k: str(v)[:80] for k, v in args.items()},
                            "detail": detail}, ensure_ascii=False) + "\n")


def _user_text(ctx) -> str:
    uc = getattr(ctx, "user_content", None)  # the HUMAN's own message, the model can't forge it
    return " ".join(p.text for p in (uc.parts if uc and uc.parts else []) if getattr(p, "text", None))


def _deny(tool, args, reason, ctx):
    _audit("DENIED", tool.name, args, reason, ctx)
    return {"status": "DENIED_BY_POLICY", "reason": reason, "instruction": "Do not retry. Explain this to the user."}


def policy_before_tool(tool, args, tool_context):
    ctx = tool_context
    if not ctx.state.get("secure_mode", True):
        _audit("ALLOWED_NO_POLICY", tool.name, args, "guardrails off", ctx)
        return None

    if tool.name == "read_job_page":
        # 0) SSRF protection: a URL from a chat/posting must never make the agent touch internal systems
        url = str(args.get("url", ""))
        u = urllib.parse.urlparse(url)
        if u.scheme != "https" or not u.hostname:
            return _deny(tool, args, "Only https:// links to public websites are allowed.", ctx)
        try:
            ips = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, 443)}
        except Exception:
            return _deny(tool, args, f"Cannot resolve {u.hostname}", ctx)
        for ip in ips:
            a = ipaddress.ip_address(ip)
            if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
                return _deny(tool, args, f"{u.hostname} resolves to internal address {ip} (SSRF attempt blocked).", ctx)

    if tool.name == "save_application_draft":
        job_id = args.get("job_id", "")
        if job_id not in JOBS:
            return _deny(tool, args, f"Unknown job {job_id!r}", ctx)
        # 1) Evidence-bound: no draft without a suspicion check
        s = ctx.state.get("suspicion", {}).get(job_id)
        if not s:
            return _deny(tool, args, "Run suggest_jobs first so this job gets a suspicion check.", ctx)
        # 2) Hard block on scams, whatever the model or the posting says
        if s["suspicion_score"] >= RULES["scam_block_threshold"]:
            return _deny(tool, args, f"{job_id} is {s['suspicion_meter']} ({s['verdict']}). Red flags: {s['red_flags'][:3]}", ctx)
        # 3) Data-leak prevention: no IBAN / ID / birthdate / address in any draft text
        blob = " ".join(str(v) for v in args.values())
        if IBAN_RE.search(blob) or any(v in blob for v in SENSITIVE_VALUES):
            return _deny(tool, args, "Draft contains sensitive personal data (IBAN/ID/birthdate/address). "
                                     "Legit employers ask for these only after a signed contract, via HR.", ctx)

    if tool.name == "approve_application":
        job_id = args.get("job_id", "")
        if not ctx.state.get("draft_versions", {}).get(job_id):
            return _deny(tool, args, f"No draft exists for {job_id}.", ctx)
        # 4) Human-in-the-loop: approval token must be in the user's own message
        if f"APPROVE {job_id}" not in _user_text(ctx):
            return _deny(tool, args, f"Only the user can approve. Ask them to review/edit, then reply exactly: APPROVE {job_id}", ctx)
        _audit("APPROVED_BY_USER", tool.name, args, "token found in user message", ctx)
    return None


def audit_after_tool(tool, args, tool_context, tool_response):
    status = tool_response.get("status", "ok") if isinstance(tool_response, dict) else "ok"
    _audit("EXECUTED", tool.name, args, str(status)[:120], tool_context)
    return None
