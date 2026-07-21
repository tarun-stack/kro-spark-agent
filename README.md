# kro-spark-agent

Self-healing Spark jobs on Kubernetes: a single KRO `ResourceGraphDefinition`
generates an RBAC-split healing/actuator pair, a credential-replace proxy
sidecar for the diagnosis LLM call, and an optional OpenAI-driven remediation
agent that opens GitHub PRs for code/config fixes.

See [`kro-spark-agent/README.md`](kro-spark-agent/README.md) for the full
writeup (architecture, design decisions, step-by-step deploy) and
[`kro-spark-agent/commands.txt`](kro-spark-agent/commands.txt) for a
copy-pasteable from-scratch runbook.

## Layout

- `kro-spark-agent/` — the KRO RGD, the healing/actuator/remediation agent
  source, and all deploy manifests.
- `proxy/` — vendored copy of the transparent credential-replace proxy
  (originally from [csantanapr/kcd-new-york-k8s-claude](https://github.com/csantanapr/kcd-new-york-k8s-claude)'s
  `proxy/`) that `kro-spark-agent`'s healing-agent Deployment uses as a
  sidecar. Includes two fixes made while building this: CRLF line endings
  breaking the init scripts on a Windows checkout, and a real hang in
  `main.go`'s plain-HTTP passthrough detection (`br.Peek(4096)` blocking
  forever with no read deadline for any request shorter than 4096 bytes).
