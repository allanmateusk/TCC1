# N20: durable round checkpoint capture

The HTTP pilot can capture verified checkpoints after each completed round.
The official 50-round runner does not enable checkpoints, and its CLI has
no resume option. A separate localhost stand-in harness tests actual restart. This change does not start a server or contact R2.

## Covered boundary

At each zero-based round boundary, a record names the full execution identity
(external run ID, internal experiment, scenario, seed, Git/model revision and
digests of effective config, tasks and audit plan). It also carries 20 replica
chains and states, membership and coordinator group allocation, and the size
and SHA-256 of each committed log prefix. Each replica chain must extend its
previous committed prefix and have one terminal round/void/calibration record
per completed round. The checkpoint file is the commit marker: its name first
becomes visible by atomic publication after data fsync. The highest contiguous
verified file is the restart frontier; no CSV length or partial temp file is
treated as completion. Replayed state uses the actual protocol Ledger and
apply_record to reproduce reputation trackers, presence, leader and rotation.
Membership is restored from the checkpoint separately because the ledger alone
does not reproduce refusals and forks.

The store assumes one fenced writer and local/durable filesystem semantics
including atomic hard links and directory fsync on POSIX. Validate these on
the chosen mount before claiming resilience to host loss. Untrusted workers
must not be able to overwrite committed checkpoints. Checksum chaining detects
corruption, not malicious replacement by an actor with access to the whole tree.

## Pilot capture and remaining resume changes

1. Pilot capture reads the 20 exact replicas over a loopback-only endpoint.
   The worker creates an ephemeral per-run authorization token; it is never
   saved in the checked-in config or result. Only export, not restore, is
   supported on that endpoint. Wait for ordinary commit and oracle/calibration;
   compare the exported head and membership to the coordinator's observed state.
2. Hash the six already-written logs, including the EMA update trace, after the
   complete audit event. Publish the immutable marker only after verification.
   The highest marker, not any CSV tail, defines progress. Failed or torn
   suffixes and committed node SQLite entries remain local. The log writer
   uses overwrite mode on normal runs; the offline harness alone can append from a verified prefix.
3. In a future explicit recovery entry point, validate the mount and exclusive
   lease, verify the committed prefixes, reconstruct and install all replicas
   from stored chains/config and memberships, restore coordinator counters and
   append at the next round. Reconstruct or clear process-local request memos
   at the exact boundary; hold the previous attempt until its provider resource
   is confirmed stopped so stale processes cannot write afterward.
4. Preserve each node's transactional SQLite under the same external run ID
   and immutable request identity. For a partially executed next round,
   consume only matching committed SQLite rows and never regenerate known
   responses. A GPU call lost before its database commit is ambiguous, so
   abort or explicitly classify it separately if no-repeat is a hard constraint.
   Never reuse another run's rows.
5. Extend the offline HTTP restart coverage to interruptions after
   per-node generation, subset commit, subset oracle, CSV suffix and checkpoint
   publication. Compare with an uninterrupted run and prove the raw model
   invocation count, ledger hashes, group membership, reputation and logs.
   Then benchmark storage and replay overhead for all 50 rounds. The immutable
   full-chain format favors verification over storage efficiency. The limit
   is 50 rounds per series and 16 MiB per checkpoint.

Local fixture tests cover the substrate and actual protocol replay.
To verify pilot capture without model weights, Docker, a GPU or cloud, use a
fresh output outside Git:

    python -m infra.runpod.n20.integration_smoke run --checkpoint --output /new/offline-test
    python -m infra.runpod.n20.integration_smoke run --checkpoint --interrupt-before-checkpoint 2 --output /new/interrupted-test

The second command stops the stand-in coordinator after writing the third
round's rows and before sealing that marker. The test expects only two
verified checkpoints and 20 already-durable synthetic generations from the
uncommitted next round. It does not restart workers or claim resume.


## Offline restart comparison

Run only in a fresh directory outside Git:

    python -m infra.runpod.n20.resume_smoke run --output /new/offline-restart

The harness runs a clean reference, then cuts a second pilot before marking
round 3 and stops the old service processes. It archives the first attempt's
logs and hashes, reinstates their two-round verified prefixes, restores the
20 replica chains/state/membership and group counter, and starts fresh
localhost stand-in processes under the same UUID and SQLite files. The
coordinator resumes at round 3, not at round 4: the third round's stored
generation/response rows are reused while its protocol is executed again.

A separate append-and-fsync log inside each stand-in sample() counts physical
calls, including duplicates if they occur; the final SQL count alone would
not prove that property. A pass requires 60 first-attempt calls, zero new
calls in round 3, 40 in rounds 4-5, and 100 in the clean run. It checks all
20 final ledgers and replayable replica states, the analytical summary,
audit and EMA history, and stable columns in the metric streams. Only
measured latency and schedule-dependent traversal hops are excluded from
the reference comparison. A mismatched UUID and a second local resume
claim are rejected.

This is not a paid-resume entry point and does not prove exactly-once if a
model call disappears before its SQLite commit. It does not restore from
C13 forks or a lost host, prove external fencing, or prove a real volume.
Fail closed on ambiguous in-flight generations before qualifying real resume.
