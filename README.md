# Authority Trio

Three GenLayer Intelligent Contracts that decide **who may do what, when, and on which evidence**, using LLM validators for the parts that need judgment and plain deterministic code for everything else.

| Contract | Version | Role |
|---|---|---|
| `AuthorityLedger` | v0.5.0 | Registry of delegations, requests, AI verdicts and appeals. Any target system asks it one question: `check_authority`. |
| `ProtectedProtocol` | v0.4.0 | Demo target. Pauses itself on a verdict, runs a bonded guardian fast path with slashing, and guards a critical action with two independent controls. |
| `ContinuityCore` | v0.4.0 | Verified facts with expiry (evidence leases), a dependency graph of assertions and actions, and AI judges whose prompt versions must pass golden cases. |

## Status, stated plainly

- **Experimental. Not audited.** Do not hold real value in these contracts.
- **Verification:** unit tests in `tests/direct` (gltest direct mode) and a hand run on **GenLayer Studio** on 2026-10-20, recorded in [studio-run-hardened.json](studio-run-hardened.json). In that run 92 of 97 planned write steps were executed and all 92 ended as expected (104 explorer rows, 17 reverts). Only 5 of the 17 revert reasons were captured and most read results were not, so the negative checks for F1, F2 and F9 reverted as expected but are not confirmed by reason. The timeout, delay and cap paths were never run on chain. Nothing ran on a public testnet.
- An earlier round on the previous versions (Ledger v0.4.0, Protocol v0.3.1, ContinuityCore v0.3.0, Studio, 2026-10-12 to 2026-10-17) led to a hostile review, whose findings are listed below. Those versions are not part of this repository.
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

## Findings and where they stand

A hostile review of the earlier versions found 3 critical and 8 major issues. Only K1 and K2 were observed on chain, the rest are code review results (the URL filter bypass was reproduced offline). Problem, fix, residual risk and evidence for each are in [SECURITY.md](SECURITY.md).

| ID | Severity | What | Now |
|---|---|---|---|
| F1 | CRITICAL | The root grantor is not authenticated, and the owner has no kill switch | FIXED |
| F2 | CRITICAL | Redelegation lets the delegate replace the grantor's intent | FIXED |
| F3 | CRITICAL | A plain guardian vote bypasses the critical threshold control | FIXED |
| F4 | MAJOR | The conflict check can block anyone's new requests | MITIGATED |
| F5 | MAJOR | A ratification verdict is not bound to the pause, and it judges a story, not facts | MITIGATED |
| F6 | MAJOR | A pause can become unresolvable, and a bond can stay locked | FIXED |
| F7 | MAJOR | Gates prove freshness, not relevance, and anyone can build on anyone's evidence | MITIGATED |
| F8 | MAJOR | Evidence fetching: filter bypass, hidden text, delimiter breakout | MITIGATED |
| F9 | MAJOR | Capability grants are global across targets | PARTLY FIXED |
| F10 | MAJOR | Unbounded growth and linear scans | MITIGATED |
| F11 | MAJOR | Single owner key and one way setters | PARTLY FIXED |
| K1 | MINOR | Bond locked by an old unresolved pause (observed on chain) | FIXED |
| K2 | MINOR | Storage read inside a non-deterministic block (observed on chain) | FIXED |

FIXED means the hole is closed in code. MITIGATED and PARTLY FIXED leave a stated residual risk. The minor findings F12 to F15 are in SECURITY.md.

## Weak points that remain

- **Trust is still centralized.** One owner key per contract, no timelock on most owner actions. Use a multisig address as owner.
- **The AI is a judge, not a proof.** It judges the stated justification, not the facts. Prompt injection is reduced by fencing, not excluded. The appeal path was never exercised on chain.
- **Time makes the workflow fragile.** Severity snapshots live 10 minutes, verdicts one hour, evidence leases can be 60 seconds, ContinuityCore enforces a 5 minute cooldown.
- **Testing is thin.** One network, one operator, a hand run. Five planned steps were skipped, many revert reasons were not captured, and Studio keeping old values in its form fields caused seven mistaken transactions (all listed in the results file).
- **Gates prove freshness, not relevance,** and the URL filter cannot see DNS resolution.

## Repository layout

```
contracts/                 AuthorityLedger.py  ContinuityCore.py  ProtectedProtocol.py
tests/direct/              unit tests in gltest direct mode, one file per contract
scripts/                   patch_gltest_windows.py   (helper for running gltest on Windows)
studio-run-hardened.json   record of the hand run on Studio
SECURITY.md                trust model, findings, reporting
```

## Running the tests

```bash
pip install genlayer-test
gltest tests/direct
```

The first run downloads the GenVM SDK. If gltest fails on Windows, see `scripts/patch_gltest_windows.py`.

## License

No license file is included, so by default all rights are reserved. Add a `LICENSE` file before you make the repository public.
