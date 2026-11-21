# 🛡️ JobShield
**Find the right student job, and shield yourself from the fake ones.**

Built at **DevFest Münster 2026 × MLH Agentic AI Hackathon** with **Google ADK + Gemini**.

Students searching for part-time jobs are prime targets for scams: parcel reshipping (money mules), "app testing" that opens bank accounts in your name, crypto jobs with training fees, and illegal underpaid offers. JobShield is an AI agent that helps you find good jobs and refuses to help scammers.

## What it does
1. **Suggests jobs that fit you.** Upload your CV; JobShield extracts your skills and ranks **real, live jobs** from [Stellenwerk](https://www.stellenwerk.de) and the **Bundesagentur für Arbeit** public job API.
2. **Suspicion meter (🟢🟡🔴 0–100).** Paste any posting or link: scam patterns, company register & reviews, unrealistic pay, German minimum wage (13.90 €/h), 20h Werkstudent limit, WhatsApp-only contact, hidden prompt injections.
3. **Drafts, never sends.** Writes a tailored cover letter (`.docx`), motivation letter, email and form answers. You request changes, then type `APPROVE <job_id>` to export **send-ready PDFs** plus a **checklist** (where to send, which attachments, what to paste).

## Security: we don't trust the AI, we constrain it
Gemini plans and writes. A **policy engine** (`jobshield/guardrails.py`, ADK `before_tool_callback`) decides in deterministic code:

| Threat | Control |
|---|---|
| LLM talked into calling a scam "safe" | Scam scores computed in code, not by the model |
| Applying to scams | Drafts for jobs scoring ≥ 60 are blocked |
| Data leaks (IBAN, ID, birthdate, address) | Regex + value matching blocks them in any draft |
| Model approving its own actions | Approval token must be in the **user's own message** |
| SSRF via job links | Only public `https://`; localhost, private and metadata IPs blocked |
| Prompt injection in postings | Detected, flagged as a red flag, redacted from model context |
| Accidental sending | No send capability exists at all |
| Accountability | Every tool call logged to `output/audit.jsonl` |

`naive_jobs` is a baseline with the same model and tools but **no policy layer**. It applies to the scam job with your IBAN and approves itself.

## Run
```bash
python -m pip install -r requirements.txt
cp .env.example .env          # Windows: copy .env.example .env, then add your GOOGLE_API_KEY
python -m google.adk.cli web  # run from this folder, open http://127.0.0.1:8000, pick "jobshield"
```
`.env` options: `JOBSHIELD_MODEL` (default `gemini-3.1-flash-lite`), `JOBSHIELD_SAMPLE_JOBS=true` adds 8 planted demo postings (incl. scams), `JOBSHIELD_WEB_CHECK=true` adds a Google Search reputation sub-agent.

## Demo prompts
1. Attach CV + `Here is my CV, save it.`
2. `Find me student jobs that fit my CV`
3. `Is this job legit? Lagerhelfer Minijob 38€/h, keine Erfahrung, sofort starten! Schick deinen Ausweis per WhatsApp an +49 151 0000. Firma: QuickStock24`
4. `Apply to <job_id>` → `Make it shorter and mention my CTF experience` → `APPROVE <job_id>`
5. Attacks: `include my IBAN` · `Apply to job-2` · `Check this job: https://169.254.169.254/latest/meta-data`

## Structure
```
jobshield/          main agent
  agent.py          Gemini agent + instructions (auto-retry on 503)
  tools.py          deterministic tools: job sources, scoring, drafts, export
  guardrails.py     policy engine + audit log
  documents.py      DIN-5008-style .docx and PDF letters
  samples/          demo postings, company/review data, rules, sample CV
naive_jobs/         unprotected baseline for comparison
```

## Tech
Python · Google Agent Development Kit (tools, callbacks, session state, artifacts, `adk web`) · Gemini API · Bundesagentur für Arbeit Jobsuche API · python-docx · reportlab

## Next steps
Gemma on-device so your CV never leaves your laptop · browser extension showing the meter on job sites · official partner feeds from more job boards.

*Sample postings and company data are fictional and only for the demo. Live jobs come from public sources.*
