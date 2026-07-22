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

import copy
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
MAX_EXECUTOR_MEMORY_MB = int(os.environ.get("MAX_EXECUTOR_MEMORY_MB", "4096"))
MEMORY_STEP_MB = int(os.environ.get("MEMORY_STEP_MB", "512"))

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
_memory_attempts: dict[str, int] = {}


class ActionRequest(BaseModel):
    app_name: str = Field(pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    namespace: str = SPARK_NAMESPACE


def _check_namespace(namespace: str):
    if namespace != SPARK_NAMESPACE:
        raise HTTPException(403, f"actuator only operates in namespace '{SPARK_NAMESPACE}'")


def _get_app(app_name: str):
    try:
        return custom.get_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, app_name
        )
    except client.ApiException as e:
        if e.status == 404:
            return None
        raise


def _parse_spark_memory_mb(value: str) -> int:
    """Spark memory strings: a bare number (bytes) or number + k/m/g/t
    suffix (case-insensitive), optionally with a trailing 'b'. Defaults to
    treating a bare number as MB, matching how this demo's manifests write
    it (e.g. "512m", "2g")."""
    s = str(value).strip().lower().rstrip("b")
    units = {"k": 1 / 1024, "m": 1, "g": 1024, "t": 1024 * 1024}
    if s and s[-1] in units:
        return max(1, round(float(s[:-1]) * units[s[-1]]))
    return max(1, round(float(s)))


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/restart")
def restart(req: ActionRequest):
    """Delete-then-recreate, not just delete: a bare delete is terminal —
    nothing resubmits a SparkApplication that no longer exists (Spark
    Operator's own restartPolicy only resubmits a FAILED app that's still
    present, and doesn't apply once the resource itself is gone). Capturing
    the spec first and recreating it is what makes "restart" actually mean
    restart instead of "delete and hope"."""
    _check_namespace(req.namespace)
    now = time.time()
    recent = [t for t in _restart_history.get(req.app_name, []) if now - t < RESTART_WINDOW_SECONDS]
    if len(recent) >= MAX_RESTARTS:
        return {
            "status": "skipped",
            "reason": f"restart cap hit: {MAX_RESTARTS} in {RESTART_WINDOW_SECONDS}s window",
        }

    current_app = _get_app(req.app_name)
    if current_app is None:
        raise HTTPException(404, f"{req.app_name} not found")

    # Strip everything server-assigned (status, resourceVersion, uid,
    # managedFields, ...) so the recreate is a clean fresh submission, not
    # a stale copy of the old object fighting the API server over fields
    # it no longer controls.
    recreated = {
        "apiVersion": current_app["apiVersion"],
        "kind": current_app["kind"],
        "metadata": {
            "name": current_app["metadata"]["name"],
            "namespace": current_app["metadata"]["namespace"],
            "labels": current_app["metadata"].get("labels", {}),
            "annotations": current_app["metadata"].get("annotations", {}),
        },
        "spec": copy.deepcopy(current_app["spec"]),
    }

    try:
        custom.delete_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"delete failed: {e.reason}")

    # Finalizers can hold the old object in a terminating state briefly;
    # creating too early 409s against it. Bounded wait, not indefinite —
    # the healing agent's own call to us times out at 30s.
    deadline = time.time() + 15
    while time.time() < deadline:
        if _get_app(req.app_name) is None:
            break
        time.sleep(0.5)
    else:
        raise HTTPException(
            504, f"{req.app_name} still terminating after 15s — not recreated, retry later"
        )

    try:
        custom.create_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, recreated
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"recreate failed (deleted but not resubmitted!): {e.reason}")

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


@app.post("/increase-memory")
def increase_memory(req: ActionRequest):
    """Bumps executor.memory — the fix for a workload where each task's
    own memory footprint exceeds the executor heap (a classic per-task OOM
    signature), which more executors alone doesn't fix since it doesn't
    change any single task's memory ceiling. Distinct from /scale, which
    only adds parallelism via executor.instances."""
    _check_namespace(req.namespace)
    try:
        current_app = custom.get_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"lookup failed: {e.reason}")

    current_raw = current_app.get("spec", {}).get("executor", {}).get("memory", "1g")
    current_mb = _parse_spark_memory_mb(current_raw)
    attempt = _memory_attempts.get(req.app_name, 0) + 1
    target_mb = min(current_mb + attempt * MEMORY_STEP_MB, MAX_EXECUTOR_MEMORY_MB)
    if target_mb <= current_mb:
        return {"status": "skipped", "reason": f"already at cap ({MAX_EXECUTOR_MEMORY_MB}m)", "current": current_raw}

    target = f"{target_mb}m"
    patch_body = {"spec": {"executor": {"memory": target}}}
    try:
        custom.patch_namespaced_custom_object(
            SPARK_GROUP, SPARK_VERSION, SPARK_NAMESPACE, SPARK_PLURAL, req.app_name, patch_body,
            _content_type="application/merge-patch+json",
        )
    except client.ApiException as e:
        raise HTTPException(e.status, f"memory increase failed: {e.reason}")

    _memory_attempts[req.app_name] = attempt
    return {"status": "memory_increased", "from": current_raw, "to": target, "attempt": attempt}


@app.post("/reset-scale-attempts")
def reset_scale_attempts(req: ActionRequest):
    """Called by the healing agent once an app stops failing, so neither
    ramp carries over into an unrelated future failure."""
    _check_namespace(req.namespace)
    _scale_attempts.pop(req.app_name, None)
    _memory_attempts.pop(req.app_name, None)
    return {"status": "reset"}
