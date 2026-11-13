# js-recon — interfaz web en contenedor.
#   docker compose up --build   ->   http://localhost:8000
# El modo --browser (Chrome visible) no está disponible dentro de Docker.

FROM python:3.12-slim

# uv fijado a una versión concreta (build reproducible).
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    JSRECON_IN_DOCKER=1 \
    JSRECON_HOST=0.0.0.0 \
    JSRECON_PORT=8000

WORKDIR /app

# 1) Dependencias primero: esta capa se cachea mientras no cambie el lock.
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --extra web --no-install-project

# 2) Código.
COPY config.py main.py ./
COPY core ./core
COPY utils ./utils
COPY web ./web

# Usuario sin privilegios; output/ es el volumen donde quedan los informes.
RUN useradd --create-home --uid 10001 recon \
    && mkdir -p /app/output \
    && chown -R recon:recon /app/output
USER recon

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/meta', timeout=2)" || exit 1

CMD ["python", "-m", "web.app"]
