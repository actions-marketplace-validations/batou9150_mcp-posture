# syntax=docker/dockerfile:1
# Multi-arch, distroless image: no shell, no package manager, runs as nonroot.
# The builder and runtime share the same Python minor (3.13) so compiled wheels match.

FROM python:3.13-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o requirements.txt \
 && uv pip install --python python3.13 --target /app --require-hashes -r requirements.txt \
 && uv build --wheel --out-dir /dist \
 && uv pip install --python python3.13 --target /app --no-deps /dist/*.whl

FROM gcr.io/distroless/python3-debian13:nonroot
LABEL org.opencontainers.image.title="mcp-posture" \
      org.opencontainers.image.description="Security posture scanner for remote MCP servers" \
      org.opencontainers.image.source="https://github.com/batou9150/mcp-posture" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /app /app
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /work
ENTRYPOINT ["/usr/bin/python3", "-m", "mcp_posture"]
CMD ["--help"]
