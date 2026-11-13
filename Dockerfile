FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py guards.py okta_client.py settings.py shared_http.py shared_docs.py HOWTO.md ./
COPY templates ./templates

RUN chown -R appuser:appuser /app

RUN chgrp -R 0 /app && chmod -R g=u /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request as u; r = u.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8080'), timeout=3); raise SystemExit(0 if r.status == 200 else 1)" || exit 1

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 120 app:app"]
