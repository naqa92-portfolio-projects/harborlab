# Built and run on the golden python image, which has no shell: every RUN is in exec form. uv, copied
# from its digest-pinned image, installs the locked runtime dependencies into a virtual environment; the
# final stage runs it with `python -m`.
FROM ghcr.io/naqa92-portfolio-projects/harborlab/golden/python@sha256:44440011a75ee28d9bbf977929288e1d9f907a2bc17ab2a1c67cd0e1fc7ad696 AS build
ENV UV_PROJECT_ENVIRONMENT=/tmp/venv \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
COPY pyproject.toml uv.lock /tmp/src/
COPY --from=ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 /uv /tmp/uv/bin/uv
RUN ["/tmp/uv/bin/uv", "sync", "--project", "/tmp/src", "--frozen", "--no-dev"]

FROM ghcr.io/naqa92-portfolio-projects/harborlab/golden/python@sha256:44440011a75ee28d9bbf977929288e1d9f907a2bc17ab2a1c67cd0e1fc7ad696
LABEL org.opencontainers.image.title="dt-bridge" \
      org.opencontainers.image.description="Forwards attested SBOMs and VEX documents of harborlab images to Dependency-Track"
COPY --from=build /tmp/venv /opt/dt-bridge/venv
COPY src/ /opt/dt-bridge/src/
ENV PATH=/opt/dt-bridge/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONPATH=/opt/dt-bridge/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "uvicorn", "dt_bridge.main:app", "--host", "0.0.0.0", "--port", "8080"]
