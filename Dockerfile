FROM python:3.12.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    SECURA_DATA_DIR=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 secura \
    && mkdir -p /data \
    && chown secura:secura /data

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=secura:secura . .

USER secura
VOLUME ["/data"]
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.getenv(\"PORT\", \"8501\")}/_stcore/health', timeout=4)"

CMD ["python", "run_secura.py"]
