# Safety and verdict semantics

PerfektBlue defaults to passive operation.

`confirmed-injectable` means a compatible module produced its required proof of control.
`blocked` means a known path was attempted and a mitigation rejected it. `no-known-path` means
the matched profile declares no installed path. `inconclusive` means prerequisites or evidence
were insufficient. `unsupported` means no profile matched.

None of these verdicts proves that a device is immune to unknown vulnerabilities.

Lab-active modules require:

1. Written authorization.
2. An isolated lab target.
3. An exact supported profile and sufficient confidence.
4. A declared service and transport.
5. An inert canary and explicit verification criteria.
6. Bounded timeout, cleanup, and stop behavior.

