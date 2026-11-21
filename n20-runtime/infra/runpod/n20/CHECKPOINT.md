# N20: checkpoints and restart qualification

The same dedicated worker can seal both the 20 × 5 pilot and an official
20 × 50 case. The full restart proof below uses a deterministic CPU stand-in
in the actual HTTP node/coordinator processes; it is not a production or
cloud qualification.

## Durable frontier

After ordinary commit and any oracle/calibration, the worker verifies
loopback-only snapshots from all 20 nodes and checks the observed heads and
memberships. The checkpoint contains the complete replica chains and derived
state, membership and group allocation plus hashes and byte offsets of six
committed log prefixes (including applied-alpha events). It binds the run UUID,
scenario, seed, Git/model revisions, task fixture, schedule and exact effective
configuration. Atomic publication happens only after the logs have been
flushed. The highest contiguous validated marker is authoritative; neither a
CSV tail nor a failed attempt's outputs can advance it.

The coordinator only caches its own most recently sealed marker while it is
the fenced writer. A new process independently scans the immutable chain.
The store requires a filesystem with real locks, hard-link atomic publication
and sync semantics. This local test does not qualify a provider volume.

## Safe local continuation

1. The old attempt must be fenced and its loopback ports free. The Linux live
   path is also single-writer locked. It requires the exact original durable
   run directory/model path and a protected independent controller permit
   from another OS user, outside the code and data volumes. The short-lived
   permit binds the existing resource, run, case, Git/model revisions and the
   precise checkpoint digest. It attests fencing; the worker cannot prove
   provider-side fencing by itself.
2. Before changing active files, verify the checkpoint chain and prefixes plus
   all 20 SQLite databases. Check UUID, node/model identity, task ID and text
   hash, deterministic per-node seed, and consistency with committed and at
   most one uncommitted round. A cache cannot be silently created or reused
   from another run. A completed result is not restartable.
3. Preserve the previous logs and their hashes in a new immutable quarantine
   directory. Recover only verified prefixes and rebuild replicas plus
   coordinator groups. Pass only the exact bound marker to child processes.
   Normal startup refuses to overwrite an existing checkpointed scenario.
4. New generations first commit a SQLite intent with FULL synchronization,
   then commit a separate result after the model returns. A matching stored
   result is reused. A persisted intent without its result is ambiguous:
   abort rather than call the model again. This deliberately favors refusal
   over duplicates; it is not an exactly-once claim about a GPU call whose
   result cannot be recovered. The old format without intents is not
   automatically eligible for restart.

## Evidence and deployment boundary

Run into fresh output outside Git, with no model weights, Docker, GPU or R2:

    python -m infra.runpod.n20.resume_smoke run --output /new/offline-pilot-restart
    python -m infra.runpod.n20.resume_smoke run --scenario C13 --cut-round 17 --output /new/offline-c13-restart

The second test runs a clean C13 reference, captures a separate attempt of
the same 20 × 50 configuration, cuts before marker 17 after that round's 20
generation/response rows are durable, stops all old HTTP processes, and
restarts through the same worker and coordinator entry points. The
stand-in's internal append-and-sync log counts actual model calls, not merely
database rows: 340 before cut, zero new at round 17, and 660 new after;
1,000 total exactly matching the clean reference. All 20 final ledger/replica
states, six semantic logs and the analytical summary are compared, ignoring
only measured latency and unstable traversal-depth columns. The proof rejects
a wrong UUID and same-attempt reentry.

A future provider-qualified Linux launch may use the explicit
`--recovery-permit` path only after `TCC_N20_RECOVERY_QUALIFIED=true`,
the separate live/official gates, and preexisting watchdog authorization.
No GitHub Actions step sets this flag. Do not activate it without a protected
permit issuer, genuine prior-worker fencing, independently verified durable
filesystem and watchdog, hardware validation, and failure tests. This local
proof does not restore a lost host, qualify cloud/provider behavior, or wire
remote checkpoint copies into live recovery. After a final marker, verify
final artifacts separately instead of replaying the completed run.
