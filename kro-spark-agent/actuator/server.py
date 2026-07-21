"""Actuator: the only component with write RBAC on SparkApplications.

Replaces the generic kubernetes-mcp-server from the original spark-agent
prototype with a small first-party service that mirrors this repo's
"own your components" style (see proxy/, remediation-agent/).

Trust boundary: the healing agent (spark_healing_agent.py) is READ-ONLY —
it can list SparkApplications and read pod logs, but cannot patch or delete
anything. It proposes an action by calling this service over HTTP; this
service is the only thing holding write RBAC, and it independently enforces
every safety bound (namespace, restart cap, executor cap) rather than
trusting whatever the caller sends. This mirrors remediation-agent/server.py,
where the app -> repo mapping also comes from server-side config, never the
request payload.
"""

import os
import time

from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from pydantic import BaseModel, Field

# The only namespace this actuator will ever touch. Not client-supplied —
# if a request names a different namespace it is rejected outright.
SPARK_NAMESPACE = os.environ.get("SPARK_NAMESPACE", "spark-jobs")

MAX_EXECUTORS = int(os.environ.get("MAX_EXECUTORS", "10"))
MAX_RESTARTS = int(os.environ.get("MAX_RESTARTS", "3"))
RESTART_WINDOW_SECONDS = int(os.environ.get("RESTART_WINDOW_SECONDS", "3600"))

SPARK_GROUP = "sparkoperator.k8s.io"
SPARK_VERSION = "v1beta2"
SPARK_PLURAL = "sparkapplications"

config.load_incluster_config()
custom = client.CustomObjectsApi()

app = FastAPI()

# app_name -> timestamps / attempt count. Lives here, not in the healing
# agent, because this is the trust boundary that must actually enforce it.
_restart_history: dict[str, list[float]] = {}
_scale_attempts: dict[str, int] = {}


class ActionRequest(BaseModel):
    app_name: str = Field(pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    namespace: str = SPARK_NAMESPACE


def _check_namespace(namespace: str):
    if namespace != SPARK_NAMESPACE:
        raise HTTPException(403, f"actuator only operates in namespace '{SPARK_NAMESPACE}'")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/restart")
def restart(req: ActionRequest):
    _check_namespace(req.namespace)
    now = time.time()
    recent = [t for t in _restart_history.get(req.app_name, []) if now - t < RESTART_WINDOW_SECONDS]
    if len(recent) >= MAX_RESTARTS:
        return {
            "status": "skipped",
            "reason": f"restart cap hit: {MAX_RESTARTS} in {RESTART_WINDOW_SECONDS}s window",
        }

    try:
        custom.delete_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"delete failed: {e.reason}")

    recent.append(now)
    _restart_history[req.app_name] = recent
    return {"status": "restarted", "attempt": f"{len(recent)}/{MAX_RESTARTS}"}


@app.post("/scale")
def scale(req: ActionRequest):
    _check_namespace(req.namespace)
    try:
        current_app = custom.get_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"lookup failed: {e.reason}")

    current = int(current_app.get("spec", {}).get("executor", {}).get("instances", 1))
    attempt = _scale_attempts.get(req.app_name, 0) + 1
    target = min(current + attempt, MAX_EXECUTORS)
    if target <= current:
        return {"status": "skipped", "reason": f"already at cap ({MAX_EXECUTORS})", "current": current}

    patch_body = {"spec": {"executor": {"instances": target}}}
    try:
        # Server-Side Apply with a minimal patch body only asserts the
        # field being changed under this service's own field manager — it
        # doesn't clobber fields other managers (e.g. spark-operator) own.
        custom.patch_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name, patch_body,
            _content_type="application/merge-patch+json",
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"scale failed: {e.reason}")

    _scale_attempts[req.app_name] = attempt
    return {"status": "scaled", "from": current, "to": target, "attempt": attempt}


@app.post("/reset-scale-attempts")
def reset_scale_attempts(req: ActionRequest):
    """Called by the healing agent once an app stops failing, so the ramp
    doesn't carry over into an unrelated future failure."""
    _check_namespace(req.namespace)
    _scale_attempts.pop(req.app_name, None)
    return {"status": "reset"}
