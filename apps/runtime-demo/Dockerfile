# Runtime-detection demo target, never an application base: the golden python image plus a static
# BusyBox installed as `sh`, the shell `task demo:runtime-shell` runs. The container itself only waits,
# so its Kubescape profile never records a shell.
FROM ghcr.io/naqa92-portfolio-projects/harborlab/golden/python@sha256:44440011a75ee28d9bbf977929288e1d9f907a2bc17ab2a1c67cd0e1fc7ad696
LABEL org.opencontainers.image.title="runtime-demo" \
      org.opencontainers.image.description="Shell-capable target of the harborlab runtime detection demo"
ADD --checksum=sha256:6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348 --chmod=0555 \
    https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox /usr/local/bin/sh
USER 65532:65532
ENTRYPOINT ["python3", "-c", "import signal; signal.pause()"]
