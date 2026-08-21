# DSIP v0.7 — assembly in progress

v0.6 (`../v0.6/`) remains the current published snapshot and the version the PoC is tagged
against (`poc-v0.6`). This folder collects the v0.7 inputs as they are drafted; the v0.7
specification document itself is assembled from them as a transcription job (plan §11).

Inputs:

| input | where | state |
|---|---|---|
| 22 disposed spec-gaps (what v0.7 must say, section by section) | `../impl/docs/spec-gaps.md` — "v0.7 worklist" table | all 22 disposed (adopt / adopt-with-change); gap 22 → (c): DID document authoritative + `KeyRotation` record |
| WebRTC Media Binding `transport:webrtc` 1.0 (spec-gap 16) | `dsip-webrtc-media-binding-v0.7-draft.md` | draft |
| DHT Reachability Hints Profile (Workstream D) | `../impl/docs/dht-hints-profile.md` | draft, with findings in `../impl/docs/dht-findings.md` |
| schema changes (record-level `integrity`, `provenance` message, `info.data` for webrtc) | `../v0.6/…/generate_schemas.py` → copied forward when the v0.7 folder is cut | pending |
| already-flagged editorial items (§15.3 codec strings, placeholder `$id`, prose ULIDs, §26 step 8) | `../impl/docs/spec-gaps.md` — "Already-flagged" | pending |

Rule 7 of `CLAUDE.md` applies: every v0.7 behavioural change lands as a vector change first,
then code, and `poc-v0.7` is tagged only when both runners are green on the v0.7 suite.
