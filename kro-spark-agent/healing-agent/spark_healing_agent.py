import json
import os
import secrets
import smtplib
import threading
import time
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse, request, error

from kubernetes import client, config
from openai import OpenAI

# This service is READ-ONLY on the Kubernetes API (see manifests/rgd.yaml —
# its ServiceAccount only gets get/list/watch on pods, pods/log, and
# sparkapplications). All mutating actions are delegated over HTTP to the
# actuator, the only component with write RBAC. See actuator/server.py.
ACTUATOR_URL = os.environ.get(
    "ACTUATOR_URL",
    "http://spark-actuator.kro-spark-agent.svc.cluster.local:8080",
)

SPARK_NAMESPACE = os.environ.get("SPARK_NAMESPACE", "spark-jobs")

# Optional: base URL of the remediation agent. When set, code/config
# diagnoses are handed off to it to open a PR; the PR review is the human
# approval gate for those. Restarts/scales keep the email approval gate.
REMEDIATION_URL = os.environ.get("REMEDIATION_URL")

# Email-based approval: restart/scale decisions are emailed as clickable
# approve/reject links instead of blocking on a terminal prompt (no TTY
# attach required). SMTP_PASSWORD is a Gmail App Password, not the account
# password. SMTP isn't HTTP, so it can't go through the credential-proxy's
# header-injection path — the container holds this secret directly.
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
APPROVAL_EMAIL_TO = os.environ.get("APPROVAL_EMAIL_TO", SMTP_USER)
APPROVAL_LINK_BASE = os.environ.get("APPROVAL_LINK_BASE", "http://localhost:8090")
APPROVAL_SERVER_PORT = int(os.environ.get("APPROVAL_SERVER_PORT", "8090"))
APPROVAL_TOKEN_TTL_SECONDS = int(os.environ.get("APPROVAL_TOKEN_TTL_SECONDS", "3600"))

# The diagnosis call goes through the proxy sidecar (see proxy/config.yaml —
# api.openai.com is credential-replace'd with OPENAI_API_KEY), so this
# container never holds the real key. See manifests/rgd.yaml proxy.domains.
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "FAKE_KEY_REPLACED_BY_PROXY"))

config.load_incluster_config()
v1 = client.CoreV1Api()
custom = client.CustomObjectsApi()


def get_spark_logs(app_name: str, namespace: str = SPARK_NAMESPACE):
    pods = v1.list_namespaced_pod(namespace, label_selector=f"spark-app-name={app_name}")
    if pods.items:
        try:
            return v1.read_namespaced_pod_log(
                name=pods.items[0].metadata.name,
                namespace=namespace,
                tail_lines=800,
            )
        except Exception:
            return "Log fetch failed"
    return "No driver pod found"


VALID_ACTIONS = {"restart", "scale", "increase_memory", "config_change", "code_fix", "no_action"}


def analyze_failure(logs: str):
    """Diagnose a failure. Returns a validated decision dict, or None if the
    model response is malformed — never trust it blindly, the logs it saw are
    untrusted input."""
    prompt = f"""Analyze Spark failure logs. Output valid JSON only:
{{
  "summary": "brief issue description",
  "root_cause": "...",
  "recommended_action": "restart|scale|increase_memory|config_change|code_fix|no_action"
}}

Action guide:
- "scale": too few executors for the workload's parallelism (e.g. tasks
  queued/pending, not enough resources to schedule work). Does NOT help a
  per-task memory error — adding executors increases parallelism, not any
  single executor's memory ceiling.
- "increase_memory": a single executor ran out of memory for its own task
  (OOMKilled, "Java heap space", "Container killed by YARN for exceeding
  memory limits", GC overhead limit exceeded). This is the fix when the
  failure is about one executor's memory being too small, not there being
  too few of them.
- "restart": transient/non-deterministic failure with no clear resource or
  code cause.
- "config_change" / "code_fix": the fix requires editing the job's source
  code or a config file outside the SparkApplication's executor sizing.

For "scale" and "increase_memory", the actual target value is computed by
the actuator from the SparkApplication's current spec, not chosen by you —
omit action_details.

Logs:
{logs[:7000]}"""

    response = openai_client.chat.completions.create(
        model=OPENAI_MODEL,
        max_tokens=1024,
        temperature=0.3,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.choices[0].message.content
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        print(f"Rejected diagnosis: no JSON object in response: {text[:200]!r}")
        return None
    try:
        decision = json.loads(text[start:end + 1])
    except json.JSONDecodeError as e:
        print(f"Rejected diagnosis: invalid JSON ({e})")
        return None
    if not isinstance(decision, dict) or decision.get("recommended_action") not in VALID_ACTIONS:
        print(f"Rejected diagnosis: unknown action {decision.get('recommended_action')!r}"
              if isinstance(decision, dict) else "Rejected diagnosis: not an object")
        return None
    return decision


# app_name -> token, so a still-FAILED job doesn't get a fresh approval
# email every poll cycle while one is already outstanding.
_pending_approvals: dict[str, dict] = {}
_pending_by_app: dict[str, str] = {}
_pending_lock = threading.Lock()


def send_approval_email(token: str, app_name: str, decision: dict):
    approve_url = f"{APPROVAL_LINK_BASE}/approve?token={token}"
    reject_url = f"{APPROVAL_LINK_BASE}/reject?token={token}"
    body = (
        f"SparkApplication: {app_name}\n\n"
        f"{json.dumps(decision, indent=2)}\n\n"
        f"Approve: {approve_url}\n"
        f"Reject:  {reject_url}\n\n"
        f"This link expires in {APPROVAL_TOKEN_TTL_SECONDS // 60} minutes."
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[spark-healing-agent] Approval needed: {app_name}"
    msg["From"] = SMTP_USER
    msg["To"] = APPROVAL_EMAIL_TO

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, [APPROVAL_EMAIL_TO], msg.as_string())


def request_approval(app_name: str, namespace: str, decision: dict):
    """Non-blocking: emails an approve/reject link and returns immediately.
    The actual healing action runs later, from the HTTP handler, when (if)
    the link is clicked."""
    with _pending_lock:
        existing = _pending_by_app.get(app_name)
        if existing and existing in _pending_approvals:
            print(f"Approval already pending for {app_name}; not re-sending")
            return

    print(f"\n=== Proposed Action for {app_name} ===")
    print(json.dumps(decision, indent=2))

    token = secrets.token_urlsafe(24)
    try:
        send_approval_email(token, app_name, decision)
    except Exception as e:
        # Send failed: nobody has this token, so don't register it — a
        # registered-but-undelivered entry would block every retry for
        # up to APPROVAL_TOKEN_TTL_SECONDS with no way to ever approve it.
        print(f"Failed to send approval email for {app_name}: {e}")
        return

    with _pending_lock:
        _pending_approvals[token] = {
            "app_name": app_name,
            "namespace": namespace,
            "decision": decision,
            "created": time.time(),
        }
        _pending_by_app[app_name] = token
    print(f"Approval email sent to {APPROVAL_EMAIL_TO} for {app_name}")


def _prune_expired_approvals():
    now = time.time()
    with _pending_lock:
        expired = [t for t, e in _pending_approvals.items()
                   if now - e["created"] > APPROVAL_TOKEN_TTL_SECONDS]
        for token in expired:
            entry = _pending_approvals.pop(token)
            _pending_by_app.pop(entry["app_name"], None)
            print(f"Approval for {entry['app_name']} expired unanswered")


class ApprovalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _respond(self, message: str):
        body = f"<html><body><p>{message}</p></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = parse.urlparse(self.path)
        if parsed.path not in ("/approve", "/reject"):
            self.send_response(404)
            self.end_headers()
            return

        token = parse.parse_qs(parsed.query).get("token", [None])[0]
        with _pending_lock:
            entry = _pending_approvals.pop(token, None) if token else None
            if entry:
                _pending_by_app.pop(entry["app_name"], None)

        if entry is None:
            self._respond("This approval link is invalid, already used, or expired.")
            return

        app_name, namespace, decision = entry["app_name"], entry["namespace"], entry["decision"]
        if parsed.path == "/approve":
            apply_healing(app_name, namespace, decision)
            self._respond(f"Approved — action applied for {app_name}.")
        else:
            print(f"Action rejected via email for {app_name}")
            self._respond(f"Rejected — no action taken for {app_name}.")


def start_approval_server():
    server = ThreadingHTTPServer(("0.0.0.0", APPROVAL_SERVER_PORT), ApprovalHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Approval HTTP server listening on :{APPROVAL_SERVER_PORT}")


def hand_off_to_remediation(app_name: str, namespace: str, decision: dict, logs: str):
    payload = {
        "app_name": app_name,
        "namespace": namespace,
        "summary": decision.get("summary", ""),
        "root_cause": decision.get("root_cause", ""),
        "recommended_action": decision.get("recommended_action", ""),
        "log_excerpt": logs[:4000],
    }
    req = request.Request(
        f"{REMEDIATION_URL}/remediate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read())
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"remediation returned HTTP {exc.code}: {body}")


def _call_actuator(path: str, app_name: str, namespace: str):
    req = request.Request(
        f"{ACTUATOR_URL}{path}",
        data=json.dumps({"app_name": app_name, "namespace": namespace}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except error.HTTPError as exc:
        raise RuntimeError(f"actuator returned HTTP {exc.code}: {exc.read().decode('utf-8')}")


def apply_restart(app_name: str, namespace: str, decision: dict):
    try:
        result = _call_actuator("/restart", app_name, namespace)
        print(f"Restart via actuator for {app_name}: {json.dumps(result)}")
    except Exception as e:
        print(f"Failed to restart via actuator: {e}")


def apply_scale(app_name: str, namespace: str, decision: dict):
    try:
        result = _call_actuator("/scale", app_name, namespace)
        print(f"Scale via actuator for {app_name}: {json.dumps(result)}")
    except Exception as e:
        print(f"Failed to scale via actuator: {e}")


def apply_increase_memory(app_name: str, namespace: str, decision: dict):
    try:
        result = _call_actuator("/increase-memory", app_name, namespace)
        print(f"Memory increase via actuator for {app_name}: {json.dumps(result)}")
    except Exception as e:
        print(f"Failed to increase memory via actuator: {e}")


HEALING_ACTIONS = {
    "restart": apply_restart,
    "scale": apply_scale,
    "increase_memory": apply_increase_memory,
}


def apply_healing(app_name: str, namespace: str, decision: dict):
    handler = HEALING_ACTIONS.get(decision.get("recommended_action"))
    if handler is None:
        print(f"No local handler for action {decision.get('recommended_action')!r}; ignoring")
        return
    handler(app_name, namespace, decision)


start_approval_server()

while True:
    try:
        _prune_expired_approvals()
        apps = custom.list_namespaced_custom_object(
            "sparkoperator.k8s.io", "v1beta2", SPARK_NAMESPACE, "sparkapplications"
        )

        failing_now = {
            app["metadata"]["name"] for app in apps.get("items", [])
            if app.get("status", {}).get("applicationState", {}).get("state")
            in ["FAILED", "UNKNOWN", "SUBMISSION_FAILED"]
        }

        for app in apps.get("items", []):
            app_name = app["metadata"]["name"]
            status = app.get("status", {}).get("applicationState", {}).get("state")
            if app_name not in failing_now:
                # No longer failing: let the actuator's ramp reset so a
                # future, unrelated failure starts from a clean scale step.
                try:
                    _call_actuator("/reset-scale-attempts", app_name, SPARK_NAMESPACE)
                except Exception:
                    pass
                continue

            if status in ["FAILED", "UNKNOWN", "SUBMISSION_FAILED"]:
                logs = get_spark_logs(app_name)
                decision = analyze_failure(logs)
                if decision is None:
                    continue

                action = decision.get("recommended_action")
                if action == "no_action":
                    continue
                if action in ("config_change", "code_fix") and REMEDIATION_URL:
                    # PR review is the human gate for code/config fixes.
                    try:
                        result = hand_off_to_remediation(app_name, SPARK_NAMESPACE, decision, logs)
                        print(f"Remediation handoff for {app_name}: {json.dumps(result)}")
                    except Exception as e:
                        print(f"Remediation handoff failed for {app_name}: {e}")
                else:
                    request_approval(app_name, SPARK_NAMESPACE, decision)
    except Exception as e:
        print(f"Loop error: {e}")

    time.sleep(int(os.environ.get("POLL_INTERVAL_SECONDS", "180")))
