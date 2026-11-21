# N20 batch sequencing groundwork (offline only)

The module contains no provider, deployment, transfer or automatic restart
function. Put state on a protected, independent durable SQLite volume with
reliable file locking and fsync. Use an authenticated controller clock and
one immutable batch plan (Git SHA + profile digest, ordered `campaign.IDS`,
official phase, seed 0, 20 nodes x 50 rounds). This is one official campaign,
not the separate 20 x 5 pilot.

1. After the pilot and separate budget/production authorization, initialize
   the plan and set absolute batch and per-attempt cutoffs. Do not run live on
   the strength of this module, test fixtures or a reservation alone.
2. An external launcher may call `reserve` for one new unique UUID. Persisting
   the reservation does not create a machine. No later call can reissue the
   reservation. If the launcher crashes, `snapshot` identifies the outstanding
   attempt for reconciliation, not a new grant. On ambiguity, pause and verify
   exact provider ownership/cost before any human decision. Never retry blind.
3. From an independently authenticated provider lookup, bind the exact new
   dedicated resource to that ID. Arm the independent watchdog/cutoff before
   the runner begins. Do not use a shared GPU host with this per-run stop policy.
4. On locally verified output, a protected preparer seals archive SHA-256 and
   byte count before issuing upload grants. Pass to `finish` only the trusted
   independent verifier's receipt (not worker-authored JSON) and the
   independently observed stop state of that exact resource/owner. Both are
   required; phase, case ID, UUID, bucket/key, digest, size, and 20 x 50/1,000
   counts must match. No credentials or URLs belong in the state.
5. Preserve local diagnostics and leave previous verified results intact.
   Failure, cancellation, uncertainty, or an elapsed cutoff leaves the
   batch paused and later cases pending. Neither pause nor the database
   can stop a provider resource by itself: the separate watchdog must still
   operate even if the launcher or this controller stops. It must not wait
   indefinitely for R2 to recover. There is no unpause/retry operation.

Live integration still needs the independent scheduler, uploader/verifier,
provider adapter/approved cutoff, failure-injection tests and budget controls.
The current runner does not automatically execute or resume the 17 scenarios.
This journal deliberately gates on stopping the verified resource between
cases. Keeping one host alive across cases requires a different lifecycle
policy and has not been implemented or qualified.
