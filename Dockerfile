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
    COURIER_CONFIG=/etc/courier/courier.toml \
    COURIER_SECRETS_DIR=/etc/courier/secrets \
    HOST=0.0.0.0 \
    PORT=8000

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 courier \
    && useradd --uid 1000 --gid 1000 --home-dir /nonexistent --shell /usr/sbin/nologin courier \
    && mkdir -p /app /etc/courier/secrets \
    && chown -R courier:courier /app /etc/courier

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv
COPY --chown=courier:courier pyproject.toml README.md ./
COPY --chown=courier:courier src ./src
COPY --chown=courier:courier frontend/dist ./frontend/dist
COPY --chown=courier:courier favicon.svg icon-app.svg ./
COPY --chown=courier:courier alembic.ini ./alembic.ini
COPY --chown=courier:courier migrations ./migrations
COPY scripts/docker-entrypoint.sh /usr/local/bin/courier-entrypoint
RUN chmod 0555 /usr/local/bin/courier-entrypoint

USER 1000:1000

EXPOSE 8000

ENTRYPOINT ["courier-entrypoint"]
CMD ["uvicorn", "courier.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
