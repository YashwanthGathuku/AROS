# Research loop

The campaign state machine is explicit (`CampaignState` in `aros-types`).
The deterministic mock researcher in `aros-core` exercises:

understand → model → hypothesize → experiment → observe → verify →
patch twin → re-attack → regression → learn (event ledger).

The LLM never authorizes. See `docs/AROS_MVP_SPEC.md` [SCIENTIFIC RESEARCH LOOP].
