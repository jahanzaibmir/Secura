<div align="center">

# ⬛ Secura

A security scanner that explains itself.

Secura finds vulnerabilities in your code, and an open-weight AI (Mistral 7B)
explains every one in plain English: what is wrong, why it is dangerous,
and exactly how to fix it.

[![License](https://img.shields.io/badge/license-MIT-black)](LICENSE)
[![Model](https://img.shields.io/badge/AI-Mistral%207B-black)](https://ollama.com/library/mistral)
[![Python](https://img.shields.io/badge/python-3.12-black)](#setup)

</div>

## Setup

```bash
git clone https://github.com/jahanzaibmir/secura.git
cd secura

uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -r requirements.txt

python run_secura.py
```

Open http://localhost:8501

Local AI (optional):

```bash
ollama pull mistral:7b
ollama serve
```

Without Ollama, Secura still works. A built-in knowledge base explains
every finding. For fast cloud AI, paste an API key (Mistral, Groq,
OpenAI, OpenRouter) in the Settings tab.

## Usage

1. Scanner tab. Paste a public GitHub repository URL, or click
   Choose folder to upload a local codebase
2. Watch the live scan progress
3. Results tab. Read the report: severity, the offending code, why it
   is dangerous, how to fix it
4. Export as JSON, Markdown, or printable HTML
5. History tab. Every past scan

## How it works

Interface (Streamlit) -> Backend (FastAPI) -> Scanners (Bandit) -> AI (Mistral 7B) -> Report

- Scanners find real vulnerabilities: SQL injection, command injection,
  hardcoded secrets, weak crypto, and more
- Mistral 7B explains each finding, grounded with curated remediation
  guidance so it does not hallucinate fixes
- A knowledge base fallback answers everything when no AI is available,
  so the tool never breaks
- Every finding is labeled with its explanation source: AI or knowledge base

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VW_MAX_AI_FINDINGS` | `5` | how many top findings the AI explains |
| `VW_MISTRAL_MODEL` | `mistral:7b` | Ollama model |
| `VW_ENABLE_AI` | `1` | `0` = knowledge base only |

## Testing

```bash
python -m pytest -q
```

## License

MIT
