FROM python:3.12-slim AS python-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip \
    && pip install .

FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POSTARA_CONFIG=/etc/postara/postara.toml \
    POSTARA_SECRETS_DIR=/etc/postara/secrets \
    HOST=0.0.0.0 \
    PORT=8000

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 postara \
    && useradd --uid 1000 --gid 1000 --home-dir /nonexistent --shell /usr/sbin/nologin postara \
    && mkdir -p /app /etc/postara/secrets \
    && chown -R postara:postara /app /etc/postara

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv
COPY --chown=postara:postara pyproject.toml README.md ./
COPY --chown=postara:postara src ./src
COPY --chown=postara:postara frontend/dist ./frontend/dist
COPY --chown=postara:postara frontend/dist-site ./frontend/dist-site
COPY --chown=postara:postara favicon.svg icon-app.svg ./
COPY --chown=postara:postara alembic.ini ./alembic.ini
COPY --chown=postara:postara migrations ./migrations
COPY scripts/postara-entrypoint.sh /usr/local/bin/postara-entrypoint
RUN chmod 0555 /usr/local/bin/postara-entrypoint

USER 1000:1000

EXPOSE 8000

ENTRYPOINT ["postara-entrypoint"]
CMD ["uvicorn", "postara.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
