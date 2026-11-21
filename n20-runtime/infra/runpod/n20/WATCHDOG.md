# External N20 pilot watchdog (offline implementation)

This module does not contact a cloud provider. The compute runner must not own
the scheduler, watchdog state, or shutdown credentials. Deploy a supervised
scheduler separately only after the provider and budget have been approved.

- Provision exactly one dedicated resource and confirm its immutable resource
  ID and run ownership marker with the provider. Do not use names, discover
  resources, or accept a Pod ID supplied by the workload. Set a provider-native
  maximum uptime at creation, so a failure to arm the external watchdog still
  has a stop backstop. Do not release the runner until `arm()` has persisted
  the binding in an independent protected store. The provider timeout must
  include startup, run and a bounded upload allowance. Use credible, monitored
  UTC and ensure one scheduler writer per state file.
- On RunPod, the documented `runpodctl pod create --stop-after` option is a stop
  deadline, not a deletion deadline; confirm the option works for the chosen
  provisioning path. Stop does not necessarily eliminate storage charges.
  No Pod or volume deletion is part of this implementation.
- The scheduler calls `tick()` with its clock and trusted evidence for the
  bound run only: `live-run.json`, optional `heartbeat.json`, and the verified
  `r2-verified.json` from the independent authenticated R2 verifier. Evidence
  must be accessible outside the runner (a durable protected mount or scoped
  reader), not trusted merely because its JSON looks valid. Do not pass URL
  signatures, access credentials, or arbitrary resource IDs from artifacts.
- The adapter must perform authenticated exact-ID lookups and report the
  authorized resource ownership marker plus an authoritative phase. A bare
  request acknowledgment, authentication error or ambiguous not-found does not
  prove shutdown. Require bounded connect/read deadlines, an idempotent stop,
  and immutability or conditional ownership protection on the stop request.
  Do not add list, delete, or storage mutation capabilities to the adapter.
- `tick()` is dry-run by default. With an approved adapter, attest a matching
  verified receipt and local completion before stopping on success. Terminal
  failure, explicit cancel, missed heartbeats or the absolute deadline can
  stop without an R2 receipt. Best-effort partial upload/checkpoints must not
  delay the cutoff. Alert on unknown ownership/phase or exhausted retries,
  and keep checking exact status. Record confirmed stopped/terminated state
  independently of data verification; do not silently declare both successful.
- Before a paid 20 x 5 pilot, test the chosen adapter and its native cutoff in
  an authorized environment, including runner loss, upload failure, cancellation,
  delayed confirmation and shutdown credentials failure. No adapter, scheduler,
  credentials, bucket or GPU was provisioned by these files.
