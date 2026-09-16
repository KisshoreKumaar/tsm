# Five-minute demo

The nine beats below are the definition of done. They work with the LLM disabled; where AI adds something, the
fallback is called out so a dead endpoint never breaks the run.

## Before you start

```bash
make init-env     # once
make seed         # synthetic incidents, false-positive verdicts, a rule draft and a CERT-In draft
make dev          # API on :8000, UI on :5173
make token        # local-admin token to sign in with
```

Have a second terminal ready for `make token NAME=approver` — the approval beats need a different role, which is the
point of them. If you want AI answers, add a provider in **Settings → AI Providers** first and use **Test connection**;
on the self-hosted model an answer takes about a minute, so start it early or rely on the deterministic output.

Say once, at the start: *everything here is synthetic, containment is simulated, and the AI can only propose.*

## The nine beats

**1 · Where we are (20 s).** Overview. Point at the AI chip in the header: it says either the active model or
"deterministic mode". Both are fine; the product works either way.

**2 · Prediction flips live (60 s).** Demo scenarios → **attack-chain** → *Replay*. Open the incident, go to **Likely
next**. After the brute force and the successful login, `T1059.001 PowerShell` sits at WATCHING with its watch
signals. When the encoded-PowerShell event arrives it flips to **OBSERVED**, a live alert appears, and the incident
risk is re-scored. Say: the prediction was made before the event, and the flip is audited.

**3 · Campaigns (30 s).** Replay **lateral-movement** → **Campaigns**. Three incidents on three hosts, one campaign.
Open the graph and read a link reason aloud: same account and same external source IP within the window.

**4 · The story (40 s).** Incident → **Story**. Executive view for the five lines, analyst view for the detail. Click
a citation: it jumps to the exact events. Every FACT cites evidence; sentences about AEGIS's own records say so.

**5 · Grounded answers and injection (60 s).** **AI analyst** tab → *Is this a false positive?* The answer cites
events; with no LLM you get the deterministic template, which is still cited. Then replay **prompt-injection**: INJ-001
fires, the injected text appears only as quoted data, and the AI does not follow it. Open the **Agent** drawer and ask
for an incident update: it produces a **proposal**, not a change. Apply it as the analyst — that is the only way state
moves.

**6 · Detection engineering (45 s).** Incident → **Rule draft** → *Draft rule from this incident*. Open **Detection
engineering**: the draft is a JSON rule. **Backtest** it (alerts, overlap with existing rules, hits on benign data,
alerts/day), then approve and activate as the approver. Ingest again and the new rule fires alongside the built-ins.

**7 · Tuning (45 s).** **Tuning**. Three scanner incidents were closed as false positives, so AEGIS proposes a
suppression scoped to the scanner IP, with the simulation: three alerts removed, zero true positives lost. Approve it
as the approver. Run the scanner again: no incident. Run attack-chain: the discovery from a different IP is still
detected. Show the suppressed detections list — nothing was deleted.

**8 · CERT-In draft (45 s).** Incident → **CERT-In**. The deadline counts down from first detection. Fields are filled
from evidence with provenance badges and citations; impact is left to a human. Fill it, send for review, approve as the
approver, export Markdown (and the redacted variant). Say clearly: the template is **UNVERIFIED** until checked
against the official directions, and AEGIS never transmits — a human files it and records the reference.

**9 · Proof (35 s).** Request simulated containment, approve it as the approver, execute: the virtual endpoint reads
back ISOLATED. Then **Audit trail → Verify** (chain valid) and **Metrics** for prediction hit rate, false-positive
rate and AI grounding. Close with: every number is descriptive, every action is attributable, and the AI never had
write access.

## If something goes wrong

| Symptom | What to do |
|---|---|
| AI answer is slow | Say it is a 3.8B model on a small box; the deterministic answer is already on screen |
| Provider unreachable | The chip shows deterministic mode; nothing else changes |
| Replay looks stalled | The worker releases a step every few seconds; `AEGIS_REPLAY_INTERVAL_SECONDS` sets the pace |
| A demo run left clutter | Every run uses a fresh asset suffix; filter the incident queue by asset |
| Fresh machine | `make seed` gives you all of the above without replaying |
