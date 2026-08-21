# DSIP v0.7 — assembled (draft)

v0.7 is the current revision: `dsip_v_0_7_decentralized_session_initiation_protocol.md` transcribes the 22 spec-gap
dispositions (Appendix A.4), the companion documents below, and the v0.7 schema set. v0.6 (`../v0.6/`) is frozen; the
PoC is tagged `poc-v0.7` once both vector runners are green on this revision.

Inputs:

| input | where | state |
|---|---|---|
| 22 disposed spec-gaps (what v0.7 must say, section by section) | `../impl/docs/spec-gaps.md` — "v0.7 worklist" table | all 22 disposed (adopt / adopt-with-change); gap 22 → (c): DID document authoritative + `KeyRotation` record |
| WebRTC Media Binding `transport:webrtc` 1.0 (spec-gap 16) | `dsip-webrtc-media-binding-v0.7-draft.md` | draft; `info.data` schema in the schema set |
| DHT Reachability Hints Profile (Workstream D) | `dsip-dht-hints-profile-v0.7-draft.md` | draft (findings in `../impl/docs/dht-findings.md`); `reachability-hint` in the schema set |
| JSON Schema set v0.7 (record-level `integrity`, `provenance`, `key-rotation`, `reachability-hint`, `webrtc-info-data`) | `dsip-schemas-v0.7-draft/` | ✅ generated from `generate_schemas.py`; 40 samples |
| already-flagged editorial items (prose ULIDs, §26 step 8, §12.7 rule 6 order) | applied in the v0.7 text | ✅ (`$id` base stays a placeholder pending §24 governance) |

Rule 7 of `CLAUDE.md` applies: every v0.7 behavioural change lands as a vector change first,
then code, and `poc-v0.7` is tagged only when both runners are green on the v0.7 suite.
