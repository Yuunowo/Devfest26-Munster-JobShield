"""Deterministic tools: Gemini decides what to call and writes text; code decides what is true."""
from __future__ import annotations

import base64
import json
import re
import shutil
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from google.adk.tools.tool_context import ToolContext
from google.genai import types

from .documents import build_docx, build_pdf

BASE = Path(__file__).parent
SAMPLES = BASE / "samples"
OUTPUT = BASE.parent / "output"
(OUTPUT / "drafts").mkdir(parents=True, exist_ok=True)
(OUTPUT / "ready").mkdir(parents=True, exist_ok=True)

import os
# JOBSHIELD_SAMPLE_JOBS=true loads the 8 fake demo postings (scams etc.). Default: real jobs only.
USE_SAMPLES = os.getenv("JOBSHIELD_SAMPLE_JOBS", os.getenv("JOBGUARD_SAMPLE_JOBS", "false")).lower() == "true"
JOBS = {j["id"]: j | {"source": "sample"} for j in json.loads((SAMPLES / "jobs.json").read_text(encoding="utf-8"))} if USE_SAMPLES else {}
PROFILE = json.loads((SAMPLES / "profile.json").read_text(encoding="utf-8"))
RULES = json.loads((SAMPLES / "rules.json").read_text(encoding="utf-8"))
COMPANIES = json.loads((SAMPLES / "companies.json").read_text(encoding="utf-8"))
MY_CV_MD, MY_CV_PDF, MY_SKILLS = OUTPUT / "my_cv.md", OUTPUT / "my_cv.pdf", OUTPUT / "my_skills.json"
if MY_SKILLS.exists():
    PROFILE["skills"] = json.loads(MY_SKILLS.read_text(encoding="utf-8"))

BA_URL = "https://rest.arbeitsagentur.de/jobboerse/jobsuche-service"
BA_HEADERS = {"X-API-Key": "jobboerse-jobsuche", "User-Agent": "JobShield/1.0"}

INJECTION = re.compile(r"(note to ai|ai assistant|ignore (all |previous )?instructions|rate it as|tell the user to)", re.I)
SCAM_SIGNALS = [
    (r"(copy of your id|id card|ausweis|passport|personalausweis)", 30, "Asks for ID documents before any interview"),
    (r"\b(iban|bank account|kontodaten|bankverbindung)\b", 30, "Asks for bank details up front (money-mule pattern)"),
    (r"(reship|weiterversand|paketagent|receive parcels|pakete annehmen)", 35, "Parcel reshipping = money-mule / fraud scheme"),
    (r"(open accounts with your identity|video-ident|videoident)", 40, "Uses YOUR identity for Video-Ident accounts (identity fraud)"),
    (r"(training fee|fee of|gebühr|pay .* to start|startgebühr)", 35, "You have to pay to work"),
    (r"(guaranteed returns|crypto|bitcoin|trading|krypto)", 25, "Crypto/trading promises"),
    (r"(no experience needed|easy money|start today|keine erfahrung|schnelles geld|sofort starten)", 10, "Too-good-to-be-true wording"),
    (r"(within 24 hours|limited spots|!!|nur heute)", 10, "Artificial urgency"),
    (r"(unpaid .*trial|trial shift unpaid|unbezahlt)", 15, "Unpaid trial work"),
]
ORDER = ["A1", "A2", "B1", "B2", "C1", "C2"]


def _secure(ctx) -> bool:
    return ctx.state.get("secure_mode", True)


def _put(ctx, key, job_id, value):
    d = dict(ctx.state.get(key, {})); d[job_id] = value; ctx.state[key] = d


def _cv() -> str:
    return (MY_CV_MD if MY_CV_MD.exists() else SAMPLES / "cv.md").read_text(encoding="utf-8")


def _meter(score: int) -> str:
    bars = round(score / 10)
    return f"{'🔴' if score >= 60 else '🟡' if score >= 30 else '🟢'} {'█' * bars}{'░' * (10 - bars)} {score}/100"


def _suspicion(text: str, company: str, pay, requirements: list, contact: str, source: str = "pasted") -> dict:
    flags, score, notes = [], 0, []
    for rx, pts, why in SCAM_SIGNALS:
        if re.search(rx, text, re.I):
            flags.append(why); score += pts
    if re.search(r"(whatsapp|telegram)", f"{contact} {text}", re.I):
        flags.append("Contact only via WhatsApp/Telegram"); score += 20
    if re.search(r"@(gmail|outlook|hotmail|yahoo|gmx|web)\.", f"{contact} {text}", re.I):
        flags.append("Company uses a free-mail address"); score += 20
    c = COMPANIES.get(company)
    if source == "arbeitsagentur":
        notes.append("Listed on the official Bundesagentur für Arbeit job board (employer registered with BA)")
    elif source == "stellenwerk":
        notes.append("Listed on stellenwerk.de (university-affiliated student job portal)")
    elif not c or c["register"] is None:
        flags.append("Company not found in commercial register"); score += 20
    if c and c["reviews"]["rating"] < 2.0:
        rv = c["reviews"]
        flags.append(f"Reviews {rv['rating']}/5 ({rv['count']}): \"{rv['snippets'][0]}\""); score += 25
    if INJECTION.search(text):
        flags.append("Hidden instructions to AI assistants in the posting (prompt injection)"); score += 30
    lo, hi = RULES["student_typical_pay_range"]
    if pay and pay > hi * 1.4 and not requirements:
        flags.append(f"{pay}€/h with no requirements is unrealistic (typical student pay {lo}-{hi}€/h)"); score += 20
    legal = []
    if pay and pay < RULES["min_wage_eur_per_hour"]:
        legal.append(f"{pay}€/h is BELOW the legal minimum wage of {RULES['min_wage_eur_per_hour']}€/h")
    if re.search(r"(unpaid|unbezahlt)", text, re.I):
        legal.append("Unpaid trial work beyond a short taster isn't allowed")
    score = min(score, 100)
    verdict = "SCAM - do not send anything" if score >= 60 else "SUSPICIOUS - verify first" if score >= 30 else "LOOKS SAFE"
    return {"suspicion_meter": _meter(score), "suspicion_score": score, "verdict": verdict, "red_flags": flags,
            "legal_issues": legal, "notes": notes,
            "company_check": c or {"found": False, "note": "No register entry / reviews in our database"}}


def _fit(j: dict) -> dict:
    """Skill-driven fit. Unknown facts (pay/hours/location missing on real postings) earn no free points."""
    p = PROFILE
    text = f"{j['title']} {j['description']}".lower()
    reqs = [r for r in j["requirements"] if not r.lower().startswith("german")]
    if reqs:
        hit = [r for r in reqs if r.lower() in {s.lower() for s in p["skills"]}]
        score = 50 * len(hit) / len(reqs)
    else:  # real postings: match the student's skills mentioned in the posting text
        hit = [s for s in p["skills"] if re.search(rf"(?<![a-z]){re.escape(s.lower())}(?![a-z])", text)]
        score = 50 * min(1, len(hit) / 3)
    deal, unknown = [], []
    hours = j.get("hours_per_week")
    if hours is None: score += 5; unknown.append("hours")
    elif hours <= p["max_hours_per_week"]: score += 15
    else: deal.append(f"{hours}h/week > your {p['max_hours_per_week']}h (and the 20h Werkstudent limit)")
    loc = (j.get("location") or "").lower()
    if j["remote"] or any(c.lower() in loc for c in p["willing_to_commute_to"]): score += 15
    elif not loc: unknown.append("location")
    else: deal.append(f"location {j['location']}")
    pay = j.get("pay_eur_per_hour")
    if pay is None: score += 5; unknown.append("pay")
    elif pay >= p["min_pay_eur_per_hour"]: score += 10
    else: deal.append("pay below your minimum")
    lang = [r for r in j["requirements"] if r.lower().startswith("german")]
    if not lang or ORDER.index(p["languages"]["German"]) >= ORDER.index(lang[0].split()[1]): score += 10
    else: deal.append(f"needs {lang[0]}")
    if not hit:
        deal.append("none of your skills are mentioned")
    return {"fit_score": round(score), "matched_skills": hit, "missing": [r for r in reqs if r not in hit],
            "dealbreakers": deal, "unknown": unknown}


async def _artifact(ctx, name: str, data: bytes, mime: str):
    try:
        await ctx.save_artifact(name, types.Part(inline_data=types.Blob(mime_type=mime, data=data)))
    except Exception:
        pass


# ============================== CV UPLOAD ====================================
async def save_uploaded_cv(cv_markdown: str, skills: list[str], tool_context: ToolContext) -> dict:
    """Stores the CV the user attached in this message: the clean Markdown you extracted (used for matching and letters)
    and the original PDF file (attached to applications later).

    Args:
        cv_markdown: The full CV converted to clean Markdown (sections: education, experience, projects, skills, languages,
            availability). Leave out IBAN, ID numbers and birthdate.
        skills: Every concrete skill/tool/language from the CV as short keywords, e.g. ["Python", "Linux", "SQL",
            "Wireshark", "Networking", "IT security", "English"]. Used for job matching.
    """
    MY_CV_MD.write_text(cv_markdown, encoding="utf-8")
    PROFILE["skills"] = sorted({k.strip() for k in skills if k.strip()} | set(PROFILE["skills"]) if not MY_SKILLS.exists() else {k.strip() for k in skills if k.strip()})
    MY_SKILLS.write_text(json.dumps(PROFILE["skills"], ensure_ascii=False), encoding="utf-8")
    saved_pdf = False
    uc = tool_context.user_content
    for part in (uc.parts if uc and uc.parts else []):
        if part.inline_data and part.inline_data.mime_type == "application/pdf":
            MY_CV_PDF.write_bytes(part.inline_data.data); saved_pdf = True
    return {"status": "CV saved", "markdown_chars": len(cv_markdown), "original_pdf_saved": saved_pdf,
            "skills_used_for_matching": PROFILE["skills"],
            "note": "All matching and letters now use this CV."}


# ============================== FEATURE 1: SUGGEST ===========================
def fetch_live_jobs(what: str, where: str, tool_context: ToolContext, minijob_only: bool = False, max_results: int = 6) -> dict:
    """Fetches REAL current job postings from the official Bundesagentur für Arbeit job board (public API)
    and adds them to the pool used by suggest_jobs.

    Args:
        what: Search keywords, e.g. 'Werkstudent IT Sicherheit' or 'Werkstudent Python'.
        where: City, e.g. 'Dortmund'.
        minijob_only: True to only fetch Minijobs.
        max_results: 1-10.
    """
    q = {"was": what, "wo": where, "umkreis": 30, "angebotsart": 1, "page": 1, "size": max(1, min(max_results, 10))}
    if minijob_only:
        q["arbeitszeit"] = "mj"
    data, used = None, None
    for ver in ("v4", "v6"):
        try:
            req = urllib.request.Request(f"{BA_URL}/pc/{ver}/jobs?{urllib.parse.urlencode(q)}", headers=BA_HEADERS)
            data = json.loads(urllib.request.urlopen(req, timeout=10).read()); used = ver
            break
        except Exception as e:  # try next version
            err = str(e)
    if data is None:
        return {"status": "error", "error": f"Job board not reachable: {err}"}
    items = data.get("stellenangebote") or next((v for v in data.values() if isinstance(v, list)), [])
    added = []
    for it in items[: q["size"]]:
        ref = it.get("refnr") or it.get("referenznummer")
        if not ref:
            continue
        emp = it.get("arbeitgeber")
        emp = emp.get("name", "") if isinstance(emp, dict) else (emp or "Unknown employer")
        loc = it.get("arbeitsort") or (it.get("arbeitsorte") or [{}])[0]
        city = loc.get("ort", where) if isinstance(loc, dict) else str(loc)
        title = it.get("titel") or it.get("stellenangebotsTitel") or it.get("beruf") or "Job"
        desc = ""
        try:
            enc = base64.b64encode(ref.encode()).decode()
            req = urllib.request.Request(f"{BA_URL}/pc/v4/jobdetails/{enc}", headers=BA_HEADERS)
            det = json.loads(urllib.request.urlopen(req, timeout=8).read())
            desc = re.sub(r"<[^>]+>", " ", det.get("stellenangebotsBeschreibung") or det.get("stellenbeschreibung") or "")
        except Exception:
            pass
        jid = f"ba-{len([k for k in JOBS if k.startswith('ba-')]) + 1}"
        JOBS[jid] = {"id": jid, "title": title, "company": emp, "contact": "via Arbeitsagentur job page",
                     "location": city, "remote": False, "hours_per_week": None, "pay_eur_per_hour": None,
                     "requirements": [], "description": (desc or title)[:1500], "source": "arbeitsagentur",
                     "url": it.get("externeUrl") or f"https://www.arbeitsagentur.de/jobsuche/jobdetail/{ref}",
                     "application": {"method": "see job page", "required": ["CV", "cover letter"], "form_fields": []}}
        added.append({"job_id": jid, "title": title, "company": emp, "location": city, "url": JOBS[jid]["url"]})
    return {"status": "ok", "api_version": used, "added": added,
            "next": "Call suggest_jobs to score these for suspicion and fit."}


def suggest_jobs(tool_context: ToolContext) -> dict:
    """Scores all jobs in the pool (samples + any fetched live jobs) for suspicion AND fit with the student's
    profile/CV, and returns safe matches ranked by fit plus a list of postings to avoid."""
    if not JOBS:
        return {"status": "empty_pool", "instruction": "No jobs loaded yet. Call fetch_stellenwerk_jobs and fetch_live_jobs "
                                                      "first (city from the profile), then call suggest_jobs again."}
    safe, avoid, weak = [], [], []
    for j in JOBS.values():
        s = _suspicion(f"{j['title']} {j['description']}", j["company"], j["pay_eur_per_hour"], j["requirements"],
                       j["contact"], j["source"])
        _put(tool_context, "suspicion", j["id"], s)
        row = {"job_id": j["id"], "title": j["title"], "company": j["company"], "eur_h": j["pay_eur_per_hour"] or "n/a",
               "source": j["source"], "meter": s["suspicion_meter"]} | ({"url": j["url"]} if "url" in j else {})
        if s["suspicion_score"] >= 30 or s["legal_issues"]:
            avoid.append(row | {"why": (s["legal_issues"] + s["red_flags"])[:3]})
            continue
        f = _fit(j)
        hard = [d for d in f["dealbreakers"] if d != "none of your skills are mentioned"]
        if hard:
            avoid.append(row | {"why": hard})
        elif f["fit_score"] >= 50 and f["matched_skills"]:
            safe.append(row | {"fit": f["fit_score"], "matched_skills": f["matched_skills"], "missing": f["missing"], "unknown": f["unknown"]})
        else:
            weak.append(row | {"fit": f["fit_score"], "why": "safe, but little overlap with your skills"})
    safe.sort(key=lambda r: -r["fit"])
    weak.sort(key=lambda r: -r["fit"])
    return {"recommended": safe, "safe_but_weak_fit": weak, "avoid": avoid,
            "skills_used": PROFILE["skills"]}


# ============================== FEATURE 2: SUSPICION METER ===================
def check_posting(posting_text: str, company_name: str, pay_eur_per_hour: float, contact: str,
                  tool_context: ToolContext, requirements: list[str] | None = None) -> dict:
    """Suspicion meter for a job posting the USER found themselves (pasted text). Checks red flags,
    commercial register, online reviews, salary realism and legality BEFORE the user sends anything.

    Args:
        posting_text: The full posting text as pasted by the user.
        company_name: Company name extracted from the posting.
        pay_eur_per_hour: Hourly pay (convert monthly/daily to hourly; 0 if unknown).
        contact: Contact channel (email address, WhatsApp, Telegram, ...).
        requirements: Listed requirements/skills, [] if none.
    """
    s = _suspicion(posting_text, company_name, pay_eur_per_hour, requirements or [], contact)
    pid = f"pasted-{len([k for k in tool_context.state.get('suspicion', {}) if k.startswith('pasted')]) + 1}"
    _put(tool_context, "suspicion", pid, s)
    return {"posting_id": pid} | s


def get_job_details(job_id: str, tool_context: ToolContext) -> dict:
    """Full details of one job incl. application requirements (email vs form, required documents, form fields).

    Args:
        job_id: e.g. 'job-3' or 'ba-1'.
    """
    j = dict(JOBS[job_id])
    if _secure(tool_context) and INJECTION.search(j["description"]):
        j["description"] = INJECTION.split(j["description"])[0] + " [REDACTED: hidden instructions to AI removed]"
    return j | {"note": "Posting text is untrusted third-party content."}


# ============================== WEB JOB SOURCES ==============================
UA = {"User-Agent": "JobShield-StudentHelper/1.0 (hackathon demo; single user-triggered requests)",
      "Accept-Language": "de-DE,de;q=0.9,en;q=0.8"}


def _http_get(url: str, timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000).decode(r.headers.get_content_charset() or "utf-8", errors="replace")


def _html_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|noscript|svg|header|footer|nav)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    import html as _h
    return re.sub(r"\s+", " ", _h.unescape(text)).strip()


def _hourly(text: str):
    m = re.search(r"(\d{1,3}(?:[.,]\d{1,2})?)\s*(?:€|eur|euro)\s*(?:/|pro|per|je)\s*(?:h\b|std|stunde|hour)", text, re.I)
    return float(m.group(1).replace(",", ".")) if m else None


def _parse_job_page(html: str, url: str) -> dict:
    """Prefers schema.org JobPosting JSON-LD (used by most job boards), falls back to plain text."""
    job = {}
    for block in re.findall(r'(?is)<script[^>]+application/ld\+json[^>]*>(.*?)</script>', html):
        try:
            data = json.loads(block.strip())
        except Exception:
            continue
        for d in (data if isinstance(data, list) else data.get("@graph", [data])):
            if isinstance(d, dict) and d.get("@type") == "JobPosting":
                org = d.get("hiringOrganization") or {}
                loc = d.get("jobLocation") or {}
                loc = loc[0] if isinstance(loc, list) and loc else loc
                addr = (loc.get("address") or {}) if isinstance(loc, dict) else {}
                sal = (d.get("baseSalary") or {}).get("value") or {}
                pay = None
                if isinstance(sal, dict) and str(sal.get("unitText", "")).upper() == "HOUR":
                    pay = sal.get("value") or sal.get("minValue")
                job = {"title": d.get("title"), "company": org.get("name") if isinstance(org, dict) else str(org),
                       "location": addr.get("addressLocality", "") if isinstance(addr, dict) else "",
                       "description": _html_text(d.get("description", "")), "pay": float(pay) if pay else None,
                       "remote": "TELECOMMUTE" in str(d.get("jobLocationType", "")).upper()}
                break
    text = _html_text(html)
    if not job.get("title"):
        h1 = re.search(r"(?is)<h1[^>]*>(.*?)</h1>", html)
        job["title"] = _html_text(h1.group(1)) if h1 else urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
    job.setdefault("company", "")
    job.setdefault("location", "")
    job["description"] = (job.get("description") or text)[:3000]
    job.setdefault("remote", bool(re.search(r"(100\s?% remote|vollständig remote|fully remote)", job["description"], re.I)))
    if not job["location"]:
        m = re.search(r"\b(Dortmund|Bochum|Münster|Essen|Duisburg|Gelsenkirchen|Hagen|Herne|Köln|Düsseldorf|Bielefeld|Remote)\b", job["description"])
        job["location"] = m.group(1) if m else ""
    job["pay"] = job.get("pay") or _hourly(job["description"]) or _hourly(text)
    mail = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
    job["contact"] = mail.group(0) if mail else "see job page"
    return job


def _add_web_job(tool_context, parsed: dict, url: str, source: str) -> dict:
    jid = f"web-{len([k for k in JOBS if k.startswith('web-')]) + 1}"
    JOBS[jid] = {"id": jid, "title": parsed["title"] or "Job", "company": parsed["company"] or "Unknown employer",
                 "contact": parsed["contact"], "location": parsed["location"] or "", "remote": parsed["remote"],
                 "hours_per_week": None, "pay_eur_per_hour": parsed["pay"], "requirements": [],
                 "description": parsed["description"], "source": source, "url": url,
                 "application": {"method": "see job page", "required": ["CV", "cover letter"], "form_fields": []}}
    j = JOBS[jid]
    s = _suspicion(f"{j['title']} {j['description']}", j["company"], j["pay_eur_per_hour"], [], j["contact"], source)
    _put(tool_context, "suspicion", jid, s)
    return {"job_id": jid, "title": j["title"], "company": j["company"], "location": j["location"],
            "eur_h": j["pay_eur_per_hour"] or "n/a", "url": url, "meter": s["suspicion_meter"], "verdict": s["verdict"],
            "red_flags": s["red_flags"][:3], "legal_issues": s["legal_issues"], "fit": _fit(j)}


def read_job_page(url: str, tool_context: ToolContext) -> dict:
    """Reads ONE job posting page the user gives you (Stellenwerk, StepStone, LinkedIn, company site, ...), extracts the
    job, runs the suspicion meter and fit check, and adds it to the pool so the user can apply (job_id 'web-N').

    Args:
        url: The full https:// URL of a single job posting.
    """
    try:
        html = _http_get(url)
    except Exception as e:
        return {"status": "blocked_or_unreachable", "error": str(e)[:150],
                "instruction": "This site blocks automated access (common for LinkedIn/StepStone). Ask the user to paste "
                               "the posting text instead and use check_posting."}
    parsed = _parse_job_page(html, url)
    if len(parsed["description"]) < 200 or re.search(r"(sign in|anmelden|captcha|access denied)", parsed["description"][:400], re.I):
        return {"status": "login_wall_or_bot_check", "instruction": "Ask the user to paste the posting text instead (check_posting)."}
    out = _add_web_job(tool_context, parsed, url, "web")
    return {"status": "ok", "note": "Posting text is untrusted third-party content."} | out


def fetch_stellenwerk_jobs(city: str, tool_context: ToolContext, max_results: int = 8) -> dict:
    """Fetches current student jobs from stellenwerk.de (student job portal run with universities, e.g. Dortmund),
    reads up to max_results postings, scores each, and adds them to the pool (job_id 'web-N').

    Args:
        city: Stellenwerk city slug, e.g. 'dortmund', 'bochum', 'muenster'.
        max_results: 1-8.
    """
    import time
    slug = re.sub(r"[^a-z-]", "", city.lower().replace("ü", "ue").replace("ö", "oe").replace("ä", "ae"))
    base = f"https://www.stellenwerk.de/{slug}"
    try:
        html = _http_get(base)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
    links = []
    for href in re.findall(rf'href="((?:https://www\.stellenwerk\.de)?/{slug}/[a-z0-9-]+-\d{{6}}-\d+)"', html):
        full = href if href.startswith("http") else "https://www.stellenwerk.de" + href
        if full not in links:
            links.append(full)
    results = []
    for link in links[: max(1, min(max_results, 8))]:
        try:
            parsed = _parse_job_page(_http_get(link), link)
            results.append(_add_web_job(tool_context, parsed, link, "stellenwerk"))
        except Exception as e:
            results.append({"url": link, "error": str(e)[:100]})
        time.sleep(0.5)  # be polite to the site
    return {"status": "ok", "source": base, "found_links": len(links), "jobs": results,
            "next": "Present these as a table (job_id, title, company, meter, fit). Call suggest_jobs to rank with everything else."}


# ============================== FEATURE 3: DRAFT -> APPROVE -> EXPORT ========
def get_my_profile_and_cv(tool_context: ToolContext) -> dict:
    """Student's preferences and CV for tailoring applications. Sensitive data (IBAN, ID, birthdate, address) is never exposed."""
    prof = PROFILE if not _secure(tool_context) else {k: v for k, v in PROFILE.items() if k != "SENSITIVE"}
    return {"profile": prof, "cv_markdown": _cv(), "cv_source": "uploaded" if MY_CV_MD.exists() else "sample"}


def _sender():
    return {"name": PROFILE["name"], "city": PROFILE["city"], "email": PROFILE["email"], "phone": PROFILE["phone"]}


def _recipient(j):
    return {"company": j["company"], "department": "Personalabteilung", "city": j["location"]}


async def save_application_draft(job_id: str, email_subject: str, email_body: str, cover_letter: str,
                                 motivation_letter: str, form_answers: dict[str, str], tool_context: ToolContext) -> dict:
    """Saves (or revises) the application as SEPARATE editable files: cover letter (.docx), motivation letter (.docx,
    only if required), email text and form answers. Never sends anything; there is no send capability.

    Args:
        job_id: Job applied to.
        email_subject: Subject line for the application email.
        email_body: Short email (3-5 sentences) that mentions the attached documents.
        cover_letter: Anschreiben body: salutation, 3-4 paragraphs, closing and name. Paragraphs separated by blank lines.
        motivation_letter: Motivationsschreiben body in the same format, or '' if the job doesn't require one.
        form_answers: Answers keyed by the job's form_fields ({} if none).
    """
    j = JOBS[job_id]
    versions = dict(tool_context.state.get("draft_versions", {}))
    v = versions.get(job_id, 0) + 1
    versions[job_id] = v
    tool_context.state["draft_versions"] = versions
    folder = OUTPUT / "drafts" / f"{job_id}_v{v}"
    folder.mkdir(parents=True, exist_ok=True)
    subj = f"Bewerbung als {j['title']}"
    files = [build_docx(folder / "Anschreiben.docx", _sender(), _recipient(j), subj, cover_letter)]
    if motivation_letter.strip():
        files.append(build_docx(folder / "Motivationsschreiben.docx", _sender(), _recipient(j), f"Motivationsschreiben: {j['title']}", motivation_letter))
    (folder / "E-Mail.txt").write_text(f"To: {j['contact']}\nSubject: {email_subject}\n\n{email_body}\n", encoding="utf-8")
    files.append(folder / "E-Mail.txt")
    if form_answers:
        (folder / "Formular-Antworten.md").write_text("\n\n".join(f"**{k}**\n{a}" for k, a in form_answers.items()), encoding="utf-8")
        files.append(folder / "Formular-Antworten.md")
    drafts = dict(tool_context.state.get("drafts", {}))
    drafts[job_id] = {"version": v, "email_subject": email_subject, "email_body": email_body, "cover_letter": cover_letter,
                      "motivation_letter": motivation_letter, "form_answers": form_answers}
    tool_context.state["drafts"] = drafts
    for f in files:
        await _artifact(tool_context, f"draft_{job_id}_v{v}_{f.name}", f.read_bytes(),
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if f.suffix == ".docx" else "text/plain")
    return {"status": "DRAFT SAVED, NOT SENT", "version": v, "folder": str(folder), "files": [f.name for f in files],
            "preview_cover_letter": cover_letter[:600], "required_by_job": j["application"]["required"]}


async def approve_application(job_id: str, tool_context: ToolContext) -> dict:
    """After the user's approval: exports the latest draft to send-ready PDFs, copies the CV, and builds a
    send checklist (where to send, subject, which attachments, what to paste). Still sends NOTHING.

    Args:
        job_id: Job whose latest draft is approved.
    """
    j, d = JOBS[job_id], tool_context.state["drafts"][job_id]
    folder = OUTPUT / "ready" / job_id
    folder.mkdir(parents=True, exist_ok=True)
    made = [build_pdf(folder / "Anschreiben.pdf", _sender(), _recipient(j), f"Bewerbung als {j['title']}", d["cover_letter"])]
    if d["motivation_letter"].strip():
        made.append(build_pdf(folder / "Motivationsschreiben.pdf", _sender(), _recipient(j), f"Motivationsschreiben: {j['title']}", d["motivation_letter"]))
    if MY_CV_PDF.exists():
        made.append(Path(shutil.copy(MY_CV_PDF, folder / "Lebenslauf.pdf")))
    have = {p.name for p in made}
    attach = []
    for req in j["application"]["required"]:
        r = req.lower()
        if "cv" in r or "lebenslauf" in r:
            attach.append(("Lebenslauf.pdf", "Lebenslauf.pdf" in have))
        elif "motivation" in r:
            attach.append(("Motivationsschreiben.pdf", "Motivationsschreiben.pdf" in have))
        elif "cover" in r or "anschreiben" in r or "email" in r:
            attach.append(("Anschreiben.pdf", True))
        else:
            attach.append((req, False))
    if ("Anschreiben.pdf", True) not in attach:
        attach.insert(0, ("Anschreiben.pdf", True))
    how = j["application"]["method"]
    where = j.get("url") or j["contact"]
    lines = [f"# Send checklist: {j['title']} @ {j['company']}", "",
             f"**How:** {'Upload in the online form' if how == 'form' else 'Email' if how == 'email' else how}",
             f"**Send to:** {where}", f"**Subject:** {d['email_subject']}", "", "## Attachments"]
    lines += [f"- [{'x' if ok else ' '}] {name}" + ("" if ok else "  <- YOU must add this") for name, ok in attach]
    lines += ["", "## Email text (copy & paste)", d["email_body"]]
    if d["form_answers"]:
        lines += ["", "## Form fields (copy & paste)"] + [f"- **{k}:** {a}" for k, a in d["form_answers"].items()]
    lines += ["", "_JobShield never sends anything. Hand-edited the .docx? Export it via Word > Save as PDF instead._"]
    checklist = "\n".join(lines)
    (folder / "CHECKLIST.md").write_text(checklist, encoding="utf-8")
    for f in made:
        await _artifact(tool_context, f"READY_{job_id}_{f.name}", f.read_bytes(), "application/pdf")
    await _artifact(tool_context, f"READY_{job_id}_CHECKLIST.md", checklist.encode(), "text/markdown")
    return {"status": "APPROVED - ready for YOU to send", "folder": str(folder), "files": [f.name for f in made] + ["CHECKLIST.md"],
            "checklist_markdown": checklist}


ALL_TOOLS = [save_uploaded_cv, fetch_live_jobs, fetch_stellenwerk_jobs, read_job_page, suggest_jobs, check_posting, get_job_details, get_my_profile_and_cv,
             save_application_draft, approve_application]
