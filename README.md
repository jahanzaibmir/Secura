<div align="center">

<img src="ui/assets/mark-light.svg" width="56" alt="">

# Secura

**A security scanner that explains every finding.**

Scan a GitHub repository, a folder, or a zip archive with five analysis engines.
Every issue comes with a plain-language explanation and a concrete fix, written by a
local or cloud AI model and grounded in a curated knowledge base that works offline.

[Live instance](https://secura-amber-two.vercel.app) ·
[Quick start](#quick-start) ·
[How it works](#how-it-works) ·
[API](#http-api) ·
[Configuration](#configuration)

![Python](https://img.shields.io/badge/python-3.11%2B-18181b)
![License](https://img.shields.io/badge/license-GPL--3.0-18181b)
![Tests](https://img.shields.io/badge/tests-224%20passing-18181b)

</div>

## Highlights

- **Five engines in one pass.** Python static analysis (Bandit), 25 JavaScript and TypeScript
  rules, secret detection for 25+ credential formats, dependency vulnerability audit against
  [OSV.dev](https://osv.dev) across six ecosystems and twelve lockfile formats, and Dockerfile
  hardening checks.
- **Explanations you can act on.** Each finding states why it matters and how to fix it,
  with corrected code. AI output is grounded in vetted guidance, and every finding falls back
  to the knowledge base when no model is available, so the tool never breaks.
- **Risk grade.** A 0 to 100 score and an A to F grade, weighted by severity and confidence.
- **Live progress.** Staged pipeline with real clone progress, per-engine status, and cancellation.
- **Exports.** JSON, Markdown, a self-contained printable HTML report, and SARIF 2.1.0 for
  GitHub code scanning.
- **Private by default.** Local AI through Ollama keeps code on your machine; uploads and
  clones are deleted after each scan; secrets are redacted in reports; API keys stay in memory.

## Quick start

```bash
git clone https://github.com/jahanzaibmir/Secura.git
cd Secura
./scripts/setup.sh
.venv/bin/python run_secura.py
```

Open <http://localhost:8501>. The API and its interactive docs run at <http://127.0.0.1:8642/docs>.

Requirements: Python 3.11 or newer and `git`. Optional local AI:

```bash
ollama pull mistral:7b
ollama serve
```

For fast cloud explanations, paste a Mistral, Groq, OpenAI or OpenRouter key under
**Settings**. The provider and the best available model are detected and verified live.

### Docker

```bash
docker build -t secura .
docker run -p 8501:8501 -v secura-data:/data secura
```

The image runs as an unprivileged user and stores reports in the `/data` volume.
Render and similar platforms work out of the box: the interface listens on `$PORT` when set.

### Vercel

Secura runs on Vercel's Container Runtime (beta) from `Dockerfile.vercel`.

1. Import the repository at [vercel.com/new](https://vercel.com/new).
2. Add the environment variable `PORT` with the value `8501`. Vercel routes traffic to port 80 unless `PORT` is set.
3. Optional: there is no Ollama on Vercel, so set `SECURA_AI_PROVIDER=openai`, `SECURA_AI_API_BASE`,
   `SECURA_AI_API_KEY` and `SECURA_AI_API_MODEL` to explain findings with a cloud model.
4. Deploy. Every push to `main` redeploys.

Vercel instances are stateless and sleep after five minutes without traffic, so stored reports and
keys pasted under Settings do not survive a restart. Uploads are limited to 4 MB per file, and live
connections reconnect every five minutes on the Hobby plan. For a persistent report history, use
Render or Docker with a volume.

## How it works

```
 Interface (Streamlit)  ──HTTP──▶  API (FastAPI)  ──▶  Scan queue (bounded workers)
                                                          │
            ┌─────────────────────────────────────────────┘
            ▼
  Validate ─▶ Fetch source ─▶ Index files ─▶ Run engines ─▶ Explain ─▶ Report
             git clone,        one walk,      isolated:       AI for the     score, grade,
             upload or zip     shared         one failure     most severe,   JSON on disk,
                               inventory      never sinks     knowledge      exports
                                              the scan        base for all
```

| Engine | Covers |
|---|---|
| Python SAST | Bandit: injection, unsafe deserialisation, weak crypto, risky APIs. Critical escalation for high-confidence code execution, noise reduction in tests. |
| JavaScript / TypeScript | DOM XSS sinks, command and SQL injection, `eval`, disabled TLS checks, JWT misuse, prototype pollution, open redirects, path traversal. Comments and string literals are understood. |
| Secrets | Cloud, VCS, payment, AI and messaging tokens, private keys, connection strings, `.env` files, and entropy-gated generic credentials. Values are redacted in every output. |
| Dependencies | Lockfiles for PyPI, npm, Go, crates.io, RubyGems and Packagist checked against OSV, with CVSS scoring and the nearest fixed version. |
| Dockerfile | Root user, unpinned base images, `curl \| sh`, secrets in `ENV`/`ARG`, remote `ADD`, world-writable permissions. |

## Project layout

```
backend/
  api/            routes, error handling, middleware
  core/           pipeline, job tracking, worker pool, validation, scoring, container
  sources/        GitHub (hardened git clone) and local or uploaded folders
  engines/        bandit, javascript, secrets, docker, dependencies/ (parsers, OSV, CVSS)
    rules/        rule catalogues for each engine
  ai/             analyzers (Ollama, OpenAI-compatible), provider manager, prompts, knowledge/
  storage/        report store, upload materialisation, exporters/ (md, html, sarif)
  schemas/        Pydantic models shared by the API and the interface
ui/
  views/          scan, report, reports, settings pages
  components/     cards, badges, finding list, summaries
  styles/         design tokens, chrome, components, report styles
tests/            unit, engines, ai, integration and ui suites
```

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Version, AI status, engine availability, queue depth |
| `POST` | `/api/scans` | Queue a scan: `{"target_type": "github_repo", "target": "owner/repo"}` |
| `POST` | `/api/scans/upload` | Multipart upload: `files` with `paths`, or a single `archive` (.zip) |
| `GET` | `/api/scans` | Recent scans with live progress |
| `GET` | `/api/scans/{job_id}` | One scan's stages, progress and result summary |
| `POST` | `/api/scans/{job_id}/cancel` | Cancel a queued or running scan |
| `GET` | `/api/reports` | Stored reports, newest first |
| `GET` | `/api/reports/{id}` | Full report |
| `GET` | `/api/reports/{id}/export?format=json\|md\|html\|sarif` | Download |
| `GET` | `/api/reports/{id}/view` | Printable HTML report |
| `DELETE` | `/api/reports/{id}` | Delete a report |
| `GET` / `PUT` | `/api/settings/ai` | Read or set the AI provider |
| `POST` | `/api/settings/ai/key` | Connect by pasting an API key |

Errors always use the shape `{"error": "<Name>", "detail": "<message>"}`.

## Configuration

Every setting is an environment variable. Legacy `VW_*` names from earlier releases are still accepted.

| Variable | Default | Purpose |
|---|---|---|
| `SECURA_DATA_DIR` | `./data` | Reports, temporary workspaces and logs |
| `SECURA_PORT` / `SECURA_UI_PORT` | `8642` / `8501` | API and interface ports (`PORT` also sets the interface port) |
| `SECURA_API_URL` | `http://127.0.0.1:8642` | Where the interface reaches the API |
| `SECURA_PUBLIC_API_URL` | unset | Browser-facing API origin, enables the printable report link when hosted |
| `SECURA_AI_ENABLED` | `1` | `0` uses the knowledge base only |
| `SECURA_AI_PROVIDER` | `ollama` | `ollama`, or `openai` together with the three API variables below |
| `SECURA_OLLAMA_URL` / `SECURA_OLLAMA_MODEL` | `http://127.0.0.1:11434` / `mistral:7b` | Local model |
| `SECURA_AI_API_BASE` / `SECURA_AI_API_KEY` / `SECURA_AI_API_MODEL` | Mistral defaults | Startup API provider |
| `SECURA_AI_MAX_FINDINGS` | `5` | How many of the most severe findings the AI explains |
| `SECURA_DEPENDENCY_AUDIT` | `1` | `0` skips the online OSV lookup |
| `SECURA_MAX_CONCURRENT_SCANS` / `SECURA_MAX_QUEUED_SCANS` | `2` / `16` | Worker pool and queue limits |
| `SECURA_ALLOW_LOCAL_PATHS` | `0` | `1` lets the API scan server folders; enable only on a trusted single-user machine |
| `SECURA_UPLOAD_MAX_FILES` / `SECURA_UPLOAD_MAX_TOTAL_BYTES` | `5000` / `200 MB` | Upload limits |
| `SECURA_CORS_ORIGINS` | localhost:8501 | Comma-separated allowed origins |

## Security model

- Cloned repositories never materialise symlinks, never prompt for credentials, and run with
  hooks and local transports disabled; every clone is time-limited and cancellable.
- Uploaded paths are sanitised against traversal, archives are size-checked before and while
  extracting, and symlink entries are skipped.
- Scanning arbitrary server paths through the API is disabled unless explicitly enabled.
- Detected secrets are redacted before they are stored or exported.
- AI keys are verified live, held in memory only, never logged, and only shown masked.
- In API mode, the text of explained findings, including code snippets, is sent to the chosen provider.

Scan only code you own or are authorised to test.

## Development

```bash
.venv/bin/python -m pytest        # 224 tests, about ten seconds, fully offline
.venv/bin/ruff check .            # lint
```

The test suite isolates itself from the environment: AI and network access are disabled, and
data goes to temporary directories, so a running Ollama or a flaky connection never changes a result.

## License

Secura is released under the [GNU General Public License v3.0](LICENSE).
