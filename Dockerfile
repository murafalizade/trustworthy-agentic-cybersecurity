FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.9.13 /uv /uvx /usr/local/bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev


EXPOSE 8501

CMD ["uv", "run", "streamlit", "run", "src/cybersecurity_agent/ui/app.py", \
     "--server.address=0.0.0.0", "--server.headless=true"]
