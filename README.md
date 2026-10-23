LeakWatch — Dark Web & Credential Leak Monitoring System

> Automated detection of leaked corporate credentials, with masked alerts to Slack / Microsoft Teams and an optional identity-provider forced password reset.

Author: Rushikesh Kulkarni · Aspiring L1 SOC / Cyber Security Analyst
Stack: Python 3 · Have I Been Pwned (HIBP) API · SQLite · Slack / Teams webhooks · Okta / Microsoft Entra ID (mock + extensible)
Platform: Windows 10/11 (PowerShell and CMD), also runs on Linux/macOS

---

1. The problem

Stolen credentials are one of the most common ways attackers get into an organisation (MITRE ATT&CK T1078 – Valid Accounts, T1110.004 – Credential Stuffing). When a third-party service is breached, employees' work emails and passwords often end up in dumps that are traded or published long before the company hears about it.

A SOC analyst needs to answer three questions quickly:

1. Which of our accounts appeared in a new breach?
2. How serious is it? (Was a password exposed, or just an email address?)
3. What do we do about it? (Alert the right people, force a reset.)

Doing this by hand — checking breach sites, copying results into tickets — is slow and easy to forget. LeakWatch automates the loop: it checks a corporate domain on a schedule, alerts the team only about new exposures, and can trigger a password reset when passwords were leaked.

2. How it works

```
        ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
        │  Scheduler  │────▶│  HIBP client     │────▶│  Breach details  │
        │ (cron / Task│     │  (domain search) │     │ (date, data      │
        │  Scheduler) │     │  retry + 429     │     │  classes, source)│
        └─────────────┘     └──────────────────┘     └────────┬─────────┘
                                                              │
                                                              ▼
 ┌───────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐
 │ Slack / Teams │◀───│  Alert builder  │◀───│  Dedup + risk scoring       │
 │   webhook     │    │ (masked fields) │    │  (SQLite state: seen before?)│
 └───────────────┘    └─────────────────┘    └──────────────┬──────────────┘
                                                            │ only if data class
                                                            │ includes "Passwords"
                                                            ▼
                                             ┌─────────────────────────────┐
                                             │  IdP remediation            │
                                             │  Okta / Entra ID (mock +    │
                                             │  real-SDK stubs)            │
                                             └─────────────────────────────┘
```

Step by step

1. Collect – Query the HIBP *breached domain* endpoint for the monitored domain. This returns each affected email alias and the breaches it appears in. Then fetch each breach's metadata (breach name, breach date, date added, exposed data classes).
2. Deduplicate – Compare every `(email, breach)` pair against a local SQLite database. Only pairs not seen before are treated as new, so the team is never alerted twice for the same exposure.
3. Score risk – Assign a risk level from the exposed data classes:
   | Exposed data classes | Risk |
   |---|---|
   | Includes `Passwords` | High |
   | Includes other sensitive classes (e.g. phone numbers, security questions) | Medium |
   | Email address only | Low |
4. Alert – Post a formatted message to Slack and/or Teams: leaked email (masked), breach source, date discovered, risk level.
5. Remediate – If, and only if, the data classes include `Passwords`, call the identity-provider module to force a password reset for that user. The default is a mock IdP that only logs what it *would* do; Okta and Entra ID adapters share the same interface.
6. Record – Save the finding to SQLite and write an audit log line.

3. Key features

- New-only alerting via persistent SQLite state (no duplicate noise)
- Masked output – emails appear as `r****h@example.com` in chat and logs; no passwords or hashes are ever handled or stored
- Resilient API handling – timeouts, retries with back-off, and `429 Too Many Requests` honouring the `Retry-After` header
- Config via environment variables – no secrets in source code
- Structured logging** to console and file
- **Pluggable remediation – a single `IdentityProvider` interface with `MockProvider`, `OktaProvider`, `EntraProvider`
- `--dry-run` / `--mock-hibp` modes so the whole pipeline can be demonstrated without a paid HIBP key
- Windows-friendly – pathlib paths, no shell-specific commands, no compiled dependencies

4. Tools & technologies

| Area | Used for |
|---|---|
| Python 3.10+ | Core application |
| `requests` | HIBP and webhook HTTP calls |
| `sqlite3` (standard library) | Deduplication / state |
| `python-dotenv` (optional) | Loading `.env` configuration |
| `logging` (standard library) | Audit and troubleshooting logs |
| Slack Incoming Webhooks / Teams Workflows webhook | Alert delivery |
| Okta SDK / Microsoft Graph API | Forced password reset (adapters) |
| HIBP API v3 | Breach intelligence source |

5. Project structure

> ⚠️ Adjust file names below to match the actual repository layout.

```
leakwatch/
├── README.md
├── requirements.txt
├── .env.example             template – copy to .env and fill in
├── leakwatch.py             entry point / CLI
├── leakwatch/
│   ├── config.py            env-var loading and validation
│   ├── hibp_client.py       API calls, retry, rate-limit handling
│   ├── storage.py           SQLite dedup store
│   ├── risk.py              risk scoring from data classes
│   ├── masking.py           email masking helpers
│   ├── notifiers.py         Slack + Teams webhooks
│   └── idp/
│       ├── base.py          IdentityProvider interface
│       ├── mock.py          logs intended action only
│       ├── okta.py          Okta adapter
│       └── entra.py         Entra ID (Graph) adapter
├── sample_data/
│   └── mock_hibp_response.json
├── docs/
│   ├── report.pdf           full project report
│   └── screenshots/         evidence (see section 8)
└── tests/
```

6. Setup (Windows)

Prerequisites: Python 3.10+ (tick *"Add Python to PATH"* during install).

```powershell
1. Get the code
git clone <your-repo-url>
cd leakwatch

2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1        # CMD: .venv\Scripts\activate.bat
If PowerShell blocks the script:
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

3. Install dependencies
pip install -r requirements.txt

4. Configure
copy .env.example .env
notepad .env
```

 Configuration (`.env`)

| Variable | Required | Description |
|---|---|---|
| `HIBP_API_KEY` | Live mode only | HIBP API key |
| `MONITORED_DOMAIN` | Yes | Verified domain to monitor, e.g. `example.com` |
| `SLACK_WEBHOOK_URL` | Optional | Slack Incoming Webhook URL |
| `TEAMS_WEBHOOK_URL` | Optional | Teams webhook URL |
| `IDP_PROVIDER` | No | `mock` (default), `okta`, or `entra` |
| `OKTA_ORG_URL` / `OKTA_API_TOKEN` | If `okta` | Okta tenant and token |
| `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` / `ENTRA_CLIENT_SECRET` | If `entra` | App registration for Microsoft Graph |
| `DB_PATH` | No | Default `leakwatch.db` |
| `LOG_LEVEL` | No | Default `INFO` |

> Never commit `.env`. It is listed in `.gitignore`.

7. Reproduce the demonstration

The live HIBP domain search needs a paid API key **and** a domain you can verify ownership of, so the demo runs in **mock mode** using a bundled sample response. The code path after the API call is identical in both modes.

```powershell
Demo run: mock breach data, mock IdP, alerts printed to console
python leakwatch.py --mock-hibp --dry-run

Run it a second time – nothing should alert (deduplication proof)
python leakwatch.py --mock-hibp --dry-run

Live run against your own verified domain
python leakwatch.py
```

Expected behaviour

| Run | Expected result |
|---|---|
| 1st mock run | Several findings logged and alerted; High-risk findings trigger a *mock* password reset |
| 2nd mock run | `0 new findings` – no alerts, no resets |
| Mock response with email-only breach | Low-risk alert, no reset triggered |
| Simulated HTTP 429 | Client waits for `Retry-After`, retries, then succeeds |

Scheduling: use Windows Task Scheduler (action: `.venv\Scripts\python.exe leakwatch.py`) or `cron` on Linux, e.g. every 6 hours.

8. Evidence

> Fill this section with real captures from your own run. Recruiters trust screenshots and logs more than claims.

| Claim | Evidence | File |
|---|---|---|
| Detects new leaked accounts and classifies risk | Console/log output of first run | `docs/screenshots/01-first-run.png` |
| Alerts reach Slack / Teams with masked data | Screenshot of the channel message | `docs/screenshots/02-slack-alert.png` |
| No duplicate alerts | Second run showing `0 new findings` | `docs/screenshots/03-dedup.png` |
| Reset only fires when passwords were leaked | Log lines for a High vs Low finding | `docs/screenshots/04-idp-logic.png` |
| Rate limits are handled | Log showing 429 → wait → retry | `docs/screenshots/05-rate-limit.png` |
| Code is tested | `pytest` output | `docs/screenshots/06-tests.png` |
| Design and results explained in depth | Full report | `docs/report.pdf` |

Sample masked alert

```
🚨 LeakWatch – New credential exposure
Account:        a****e@example.com
Breach source:  ExampleBreach
Breach date:    2024-03-12
Discovered:     2026-10-23
Data exposed:   Email addresses, Passwords
Risk:           HIGH
Action:         Password reset triggered (mock)
```



9. Limitations

Being upfront about these is deliberate — they are also the roadmap.

- Not true dark web crawling. LeakWatch relies on HIBP's curated breach corpus. Credentials sold privately, or in breaches HIBP has not yet ingested, will not be detected. It is a *breach-exposure* monitor, not a dark-web scraper.
- Detection lag. Alerts can only be as fast as HIBP's ingestion of a breach, which may be days to months after the breach occurs.
- Domain verification and cost. The domain search endpoint requires a paid HIBP subscription and proof that you own the domain.
- No password validity check. A `Passwords` data class means passwords were in the breach, not that the current password is still the same. The forced reset is a safe default but may cause unnecessary resets.
- Remediation is a prototype. The mock provider is fully demonstrable; Okta and Entra adapters follow the same interface but have not been validated against a production tenant. A real deployment needs least-privilege API credentials and approval workflow.
- Single-node state. SQLite suits one scheduled instance; multiple instances would need a shared database.
- Alert fatigue not yet tuned. No severity-based routing, escalation, or ticketing integration (e.g. TheHive, ServiceNow, Jira).
- Email-only matching. Usernames, service accounts, and personal emails of staff are out of scope.

10. Possible next steps

- Ticket creation (Jira / TheHive) and SIEM forwarding (Wazuh / Elastic) in addition to chat alerts
- Additional intelligence sources alongside HIBP
- Per-severity alert routing and quiet hours
- Docker image and GitHub Actions CI with unit tests
- Metrics dashboard (new exposures per week, mean time to alert)

11. Skills demonstrated

Threat intelligence handling · API integration and rate-limit handling · secure secret management · data minimisation and masking · incident-response automation (SOAR-style playbook) · identity-provider integration · Python scripting and logging · technical documentation

12. Responsible use

Use only on domains you own or are authorised to monitor. The tool never stores or displays plaintext passwords and masks email addresses in all outputs.

---

Author: Rushikesh Kulkarni 
