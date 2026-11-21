# Resident models, fresh experiment processes (opt-in)

The standard `benchmark run` command and GitHub workflow retain cold,
per-scenario workers. The new `worker.execute_scenario(..., resident_pool=...)`
path has one trusted, serialized inference process per node pinned to its GPU;
HTTP protocol nodes and the coordinator still launch afresh per scenario.
Protocol processes have no visible GPU. Private endpoints bind loopback and
ephemeral ports, actual child PID, exact node, run UUID, activation epoch,
lease expiry and per-round task/question/seed; the control capability is passed
only through the launcher pipe. Closing the lease invalidates old requests.
There is no fallback to cold inference when the resident is unhealthy.

A model is loaded once per resident under one pinned snapshot/config/GPU map.
Each case uses a new run-scoped DedicatedModel wrapper and SQLite and records
real `model-runtime.json` for that UUID in the live path. Reuse is model
weights only, not a request cache, a conversation, or evolving reputation.
For explicit same-run recovery, the ordinary checkpoint/intent gates still
apply and the wrapper may reuse completed entries for that exact UUID.
A separated batch controller can never submit a new case from an interrupted
or unverified one. Keep a single sequence with independently verified R2 GET
receipts matching the actual sealed bytes. No transferable credentials are
available to the model or protocol subprocesses.

`warm_batch.run_qualified` joins the actual worker and SameHostBatch bridge.
This is disabled by default and has no CLI/Actions switch. A real deployment
must supply protected, independent provider observation/scheduler/fencing and
an independent transfer verifier. The journal must not be writable to
inference workers. A failure pauses the controller; an external watchdog must
stop and confirm the exact host while preserving its durable volume. Local
worker/resident shutdown does not itself stop billing. Never combine the
batch-owned watchdog with the old per-case Pod stop controller.

## Offline evidence

Use fresh output paths outside Git:
`python -B -m infra.runpod.n20.resident_smoke --output <new-scratch-dir>`
exercises actual HTTP/worker execution, with two 20 × 5 cases under separate
UUIDs and a controlled replay. One case uses a synthetic Gênese variant and
is not exported as production. The expected model is a pure CPU stand-in.

`python -B -m infra.runpod.n20.warm_controller_smoke --output <other-scratch-dir>`
exercises two genuine official case definitions (C15 and C13, 20 × 50 each)
via the worker and same-host controller, with the last two positions selected
after 15 controller-only fixture receipts. The provider and bucket are both
fake. The finalizer rejects a manifest labeled mock; the rest of the sealed
ZIP path is exercised in an explicitly temporary copy with instrumentation
replacing GPU counters, never a real report from an actual Smol. Receipt
failures use a small fake workload to test the lifecycle without repeating
large cases.

Not proven by these tests: simultaneous memory and generation peaks for 20
real SmolLM3 BF16 instances (10 per GPU), cache behavior and warm/cold latency
on that hardware, independent external supervisor and lease liveness,
network-volume persistence/fencing, real R2 authorization+GET and actual
provider shutdown. Qualify these in a separately authorized short GPU pilot
before arming live batch or resident restart.
