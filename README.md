# Authority Trio

Three GenLayer Intelligent Contracts that decide **who may do what, when, and on which evidence**, using LLM validators for the parts that need judgment and plain deterministic code for everything else.

| Contract | Version | Role |
|---|---|---|
| `AuthorityLedger` | v0.5.0 | Registry of delegations, requests, AI verdicts and appeals. Any target system asks it one question: `check_authority`. |
| `ProtectedProtocol` | v0.4.0 | Demo target. Pauses itself on a verdict, runs a bonded guardian fast path with slashing, and guards a critical action with two independent controls. |
| `ContinuityCore` | v0.4.0 | Verified facts with expiry (evidence leases), a dependency graph of assertions and actions, and AI judges whose prompt versions must pass golden cases. |

## Status, stated plainly

- **Experimental. Not audited.** Do not hold real value in these contracts.
- The previous versions (Ledger v0.4.0, Protocol v0.3.1, ContinuityCore v0.3.0) were tested by hand on **GenLayer Studio** between 2026-10-12 and 2026-10-17: about 116 transactions, 21 of them reverts. Nothing ran on a public testnet.
- A hostile review of those versions found 3 critical and 9 major issues. This release fixes or mitigates all of them (see [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md)).
- **The hardened versions were verified offline and in part on Studio.** Offline: 27 unit tests and 142 scenario steps on a stand-in for GenVM. On Studio (deployed 2026-10-20): 92 of the 97 write steps of the scenarios ran, every one with the expected success or revert, 104 explorer rows, 17 reverts. Only 5 of the 17 revert reasons were captured, and 39 of 45 read results were not, so several negative checks (F1, F2, F9) reverted as expected but are not confirmed by reason. Details: [tests/results/studio-run-2-hardened.json](tests/results/studio-run-2-hardened.json).
- AI outcomes depend on the validator LLM set and are not bit for bit reproducible.

## How the pieces fit

```
 grantor ──create_delegation──> AuthorityLedger <──can_execute── ContinuityCore
                                   │   ▲                          (facts, gates)
        delegate ──create_request──┘   │ check_authority (view)
                  ──adjudicate (LLM)───┤
                                       ▼
                               ProtectedProtocol  (re-checks authority at execution,
                                                   keeps its own replay protection)
```

1. An owner approved grantor delegates a capability (for example `PAUSE_PROTOCOL`) to a delegate, with an intent text fixed by its hash. A redelegated child keeps the same intent.
2. The delegate files a request. Validators run an LLM over the intent, the justification and, for critical actions, the **exact action text**. The verdict is `IN_SCOPE`, `OUT_OF_SCOPE` or `INCONCLUSIVE`.
3. The target calls `check_authority` (a read only view) and applies its own deterministic rules: replay protection, accepted scope, trusted root grantor, guardian quorum.
4. Optional gates: a request can rest on an action node in `ContinuityCore`. The Ledger asks `can_execute` again on every check, so an expired fact closes the gate without any AI call.

Design rules that hold in the code: the owner can only raise a capability's consequence class and only switch gates on, never off; an expired or revoked parent invalidates its whole delegation chain; uncertainty never silently approves (strict mode treats doubt as refusal).

## What was verified on Studio

Phases 1 to 5 of the first [runbook](tests/RUNBOOK.md) were run on the previous versions: delegation limits, cascade revoke, committee approvals, cancel and audit reads, the routine class without any AI call, the critical threshold change (IN_SCOPE then two approvals), an out of scope refusal, emergency pause with ratification refusal, slashing and the sweep to the recipient, authority conflict detection and blocking, the full evidence lease cycle (verify, expire, revalidate, revoke, reclaim, execute), and a judge activated by three golden cases.

Run 2 repeated phases 0 to 6 on the hardened versions. 92 of the 97 write steps have a matching transaction and all 92 ended as expected, including the refusal flows, the slash and sweep, the conflict block, the evidence lifecycle and the judge activation. Not run: steps 1.6, 2.7, 4.13, 4.32 and 6.1. The explorer shows two native transfers and a Protocol balance of 0.80 GEN, which matches the bond accounting.

Machine readable records: [run 1](tests/results/studio-run-1-previous-versions.json), [run 2](tests/results/studio-run-2-hardened.json).

## What we found, and where it stands

A hostile review found 3 critical and 9 major issues in the first versions. Only K1 and K2 were observed on chain, the rest are code review results (the URL filter bypass was reproduced offline).

| ID | Severity | What | Now |
|---|---|---|---|
| F1 | CRITICAL | The root grantor is not authenticated, and the owner has no kill switch | FIXED |
| F2 | CRITICAL | Redelegation lets the delegate replace the grantor's intent | FIXED |
| F3 | CRITICAL | A plain guardian vote bypasses the critical threshold control | FIXED |
| F4 | MAJOR | The conflict check can be used to block anyone's new requests | MITIGATED |
| F5 | MAJOR | A ratification verdict is not bound to the pause, and it judges a story, not facts | MITIGATED |
| F6 | MAJOR | A pause can become unresolvable, and a bond can stay locked | FIXED |
| F7 | MAJOR | Gates prove freshness, not relevance, and anyone can build on anyone's evidence | MITIGATED |
| F8 | MAJOR | Evidence fetching: filter bypass, hidden text, delimiter breakout | MITIGATED |
| F9 | MAJOR | Capability grants are global across targets | PARTLY FIXED |
| F10 | MAJOR | Unbounded growth and linear scans | MITIGATED |
| F11 | MAJOR | Single owner key and one way setters | PARTLY FIXED |
| K1 | MINOR | Bond locked by an old unresolved pause | FIXED |
| K2 | MINOR | Storage read inside a non-deterministic block | FIXED |
| C1 | MAJOR | The web console keeps a private key in the browser | PARTLY FIXED |

Statuses: FIXED means the hole is closed in code. MITIGATED and PARTLY FIXED leave a stated residual risk, listed in [SECURITY.md](SECURITY.md). Verification is offline for all of them. On chain, only the positive paths of F5, F6 and F13 were seen working, and the F1, F2 and F9 reverts are unconfirmed by reason (see the results file).

## Results at a glance

| Run | Contracts | Rows | Reverts | Notes |
|---|---|---|---|---|
| 1, 2026-10-12 to 10-17 | Ledger v0.4.0, Protocol v0.3.1, ContinuityCore v0.3.0 | 116 | 21 | Found a leftover pause that kept a bond locked (K1) |
| 2, 2026-10-20 | Ledger v0.5.0, Protocol v0.4.0, ContinuityCore v0.4.0 | 104 | 17 | 92 of 97 write steps ran as expected. The bond was withdrawn after the pause was resolved. Protocol balance 0.80 GEN matches the bond accounting |

Files: [run 1](tests/results/studio-run-1-previous-versions.json), [run 2](tests/results/studio-run-2-hardened.json).

## Weak points that remain

- **Trust is still centralized.** One owner key per contract, no timelock on most owner actions. Use a multisig address as owner.
- **The AI is a judge, not a proof.** It judges the stated justification, not the facts. Prompt injection is reduced by fencing, not excluded. The appeal path was never exercised on chain.
- **Time makes the workflow fragile.** Severity snapshots live 10 minutes, verdicts one hour, evidence leases can be 60 seconds, ContinuityCore enforces a 5 minute cooldown.
- **Testing is thin.** One network, one operator, run by hand. The Node runner `tests/run.mjs` has never run against a network, and five scenario steps were skipped (1.6, 2.7, 4.13, 4.32, 6.1).
- **Gates prove freshness, not relevance,** and the URL filter cannot see DNS resolution.
- **Many failure reasons were never captured** (9 of 21 reverts in the first run, 12 of 17 in the second, marked `confirmed: false`). Studio keeps old values in its form fields, which caused seven mistaken transactions in the second run.

## Repository layout

```
contracts/    authority_ledger.py  protected_protocol.py  continuity_core.py
console/      index.html  vercel.json      (static web console, 118 methods)
tests/        scenarios.json  RUNBOOK.md  run.mjs  lib.mjs  offline/  results/ (two Studio runs)  tools/
.github/      workflows/offline.yml          (runs the offline checks on every push)
CHANGELOG.md  what changed in the hardening release, including breaking changes
DEPLOY.md     deployment and wiring
SECURITY.md   trust model, findings, reporting
```

## Quick start

1. Read [DEPLOY.md](DEPLOY.md) and deploy in the documented order.
2. Offline first: `cd tests/offline && python3 -m unittest && python3 run_scenarios.py`. Then on a network: `cd tests && npm install && npm run plan`, then `npm run test:fast` (phases 0 and 1, no AI calls).
3. Follow [tests/RUNBOOK.md](tests/RUNBOOK.md) by hand if you prefer Studio.

## License

No license file is included, so by default all rights are reserved. Add a `LICENSE` file before you make the repository public.
