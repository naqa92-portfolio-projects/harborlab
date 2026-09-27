import json
import logging
import os
import queue
import threading
from contextlib import asynccontextmanager

import certifi
from fastapi import FastAPI, Request, Response

from dt_bridge.dt_client import DependencyTrackClient, DependencyTrackError
from dt_bridge.pipeline import Bridge, ImageRef, PendingVex, images_of_event
from dt_bridge.registry import Registry, RegistryError
from dt_bridge.sbom import AttestationError
from dt_bridge.vex import VexConversionError

# Bounds the work a burst of (possibly forged) webhook calls can queue; every job re-reads Harbor.
MAX_QUEUED_IMAGES = 200
LOG_FIELDS = ("image", "tag", "digest", "components", "vulnerabilities", "dhi", "error")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {"time": self.formatTime(record), "level": record.levelname, "logger": record.name}
        entry["message"] = record.getMessage()
        entry.update({field: getattr(record, field) for field in LOG_FIELDS if hasattr(record, field)})
        return json.dumps(entry)


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
log = logging.getLogger("dt_bridge")

jobs: queue.Queue[ImageRef] = queue.Queue(maxsize=MAX_QUEUED_IMAGES)
vex_jobs: queue.Queue[PendingVex] = queue.Queue()
pending: set[ImageRef] = set()
pending_lock = threading.Lock()


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"environment variable {name} is not set")
    return value


def build_bridge() -> Bridge:
    # Harbor is served with the local CA only, whose certificate has no keyUsage extension: Python's strict
    # X.509 checks are relaxed for that CA alone. dhi.io is served with a public CA.
    harbor = Registry(
        required_env("HARBOR_URL"),
        required_env("HARBOR_USERNAME"),
        required_env("HARBOR_PASSWORD"),
        ca_file=required_env("HARBOR_CA_FILE"),
        relax_x509_strict=True,
    )
    dhi = Registry(
        "https://dhi.io", os.environ.get("DHI_USERNAME"), os.environ.get("DHI_TOKEN"), ca_file=certifi.where()
    )
    dt = DependencyTrackClient(required_env("DT_URL"), required_env("DT_API_KEY"))
    return Bridge(harbor, dt, dhi)


FORWARDING_ERRORS = (
    AttestationError,
    DependencyTrackError,
    RegistryError,
    VexConversionError,
    TimeoutError,
    KeyError,
    ValueError,
)


def sbom_worker(bridge: Bridge) -> None:
    """Uploads SBOMs in arrival order; VEX documents wait for DT's analysis in the other worker."""
    while True:
        image = jobs.get()
        with pending_lock:
            pending.discard(image)
        try:
            vex = bridge.process(image)
            if vex is not None:
                vex_jobs.put(vex)
        except FORWARDING_ERRORS as error:
            log.error(
                "image not forwarded",
                extra={"image": image.path, "tag": image.tag, "error": f"{type(error).__name__}: {error}"},
            )


def vex_worker(bridge: Bridge) -> None:
    while True:
        vex = vex_jobs.get()
        try:
            bridge.apply_vex(vex)
        except FORWARDING_ERRORS as error:
            log.error(
                "VEX not applied",
                extra={
                    "image": vex.image.path,
                    "tag": vex.image.tag,
                    "error": f"{type(error).__name__}: {error}",
                },
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    app.state.governed_projects = set(os.environ.get("GOVERNED_PROJECTS", "golden,apps").split(","))
    bridge = build_bridge()
    threading.Thread(target=sbom_worker, args=(bridge,), daemon=True, name="sbom-worker").start()
    threading.Thread(target=vex_worker, args=(bridge,), daemon=True, name="vex-worker").start()
    yield


app = FastAPI(title="dt-bridge", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/harbor/events", status_code=202)
async def harbor_events(request: Request, response: Response) -> dict[str, int]:
    """Harbor webhook: the event only names images; their SBOM and VEX are read from the registries."""
    try:
        event = await request.json()
    except ValueError:
        response.status_code = 400
        return {"queued": 0}
    images = images_of_event(event if isinstance(event, dict) else {}, request.app.state.governed_projects)
    queued = 0
    for image in images:
        with pending_lock:
            if image in pending:
                continue
            try:
                jobs.put_nowait(image)
            except queue.Full:
                response.status_code = 503
                log.warning("queue full, event dropped", extra={"image": image.path, "tag": image.tag})
                break
            pending.add(image)
            queued += 1
    log.info(
        f"Harbor {event.get('type') if isinstance(event, dict) else None} event, {queued} image(s) queued"
    )
    return {"queued": queued}
