# Security notes

This document states what Continuity Core assumes, what it defends against, and what it does not.
Claims here are limited to what the tests and the live Studio run in `proof.json` support.

## Trust assumptions

1. **The source is the trust root.** A verified evidence means "the source said this when it was
   checked". If the source is wrong, attacker-controlled, or edited by a third party, the contract
   inherits that.
2. **Validator majority is honest and independent.** Probe results are accepted by consensus among
   validators running different models. A shared bias of the majority passes through.
3. **The node owner is trusted for what they declare.** Owners choose sources, claims, golden cases
   and the parents of derived nodes. The contract does not check that an assertion follows from its
   parents.
4. **Transaction time is real UTC.** The contract reads `gl.message_raw["datetime"]`. In the live run
   the recorded timestamps matched wall-clock UTC and the 300 second lease arithmetic was exact.

## Threats and mitigations

| Threat | Mitigation | Evidence | Residual risk |
|---|---|---|---|
| Flooding a victim's evidence with dependents so that transitions fail | Pull-based trust: no write path iterates over dependents | test with 100 dependents | `children` lists grow (cost paid by the creator) |
| Rewriting a claim under existing dependents | `reclaim` is refused when the evidence has dependents | direct test, live rollback `HAS_DEPENDENTS_REGISTER_NEW_EVIDENCE` | none known |
| Activating a prompt on old test results | Results must be at most 3600 s old | direct test, live rollback `CASE_RESULT_STALE` | none known |
| Activating a regressed prompt | Every golden must `PASS`; the gate only blocks | direct test, live rollback `CASE_FAILED` | passes all goldens yet misbehaves elsewhere |
| Hard-coding golden answers into the prompt | A golden input may not occur verbatim in a prompt | direct test | paraphrased leakage is not detected |
| Empty or tiny test suite | At least 3 goldens, at most 8 | direct test | suite quality is owner-controlled |
| Re-rolling a failing case until it passes | One run per case per recertification cycle | direct test | a new cycle re-samples |
| Spamming LLM consensus | 300 s cooldown between attempts | direct test | none known |
| Using a stale or revalidated fact for an irreversible action | Optional `max_age_seconds` on actions | direct test | none known |
| Fetching internal addresses through validators | HTTPS only; no IP literals, localhost, `.local`, `.internal`, or credentials in the URL | direct test | DNS names that resolve to private ranges |
| Malformed leader output | Validator rejects non-dict or out-of-enum results | direct test (validator logic) | none known |
| Lying leader | Validators re-execute and compare verdict buckets | direct tests with mocks | not exercised live |
| Injection through source text | Prompt marks the source as untrusted data | none beyond the prompt | an injected page can still sway a model |
| A prompt that invites injection | Only goldens that exercise the behavior can block it | live: an injection-inviting prompt still passed the injection golden | the gate cannot see prompt intent, only behavior on its cases |
| Dependency on one model | Heterogeneous validator set | observed live | correlated model errors |

## Known residual risks

* **Irreversibility.** `EXECUTED` cannot be undone. Revoking evidence afterwards does not roll
  anything back. A consumer that moves value should add a hold or dispute window.
* **Owner compromise.** A compromised owner can propose a prompt that passes every golden. The suite
  is append-only and public, so the attack is limited to behavior outside the goldens.
* **Liveness under model disagreement.** Borderline claims produce leader rotations. The system
  fails closed (no trust is restored without a majority) but can be slow.
* **Cached states.** Derived node states are caches. Only `execute_action`, `get_state`,
  `get_blocker` and `can_execute` compute trust live. Do not read stored states for decisions.
* **Not verified live:** the `CHANGED` verdict, dishonest leaders, dishonest validators.

## Operational checklist

* Keep the two header lines exactly as in `contracts/continuity_core.py`.
* Use pinned HTTPS sources you control or trust; avoid sources that third parties can edit.
* Prefer short TTLs for facts that can be revoked.
* Use clear-cut golden cases. Borderline cases make consensus noisy.
* Set `max_age_seconds` on actions that cannot be undone.
* Treat `get_active_prompt` as untrusted unless `live` is true.
