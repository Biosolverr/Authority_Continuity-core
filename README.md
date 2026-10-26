Three GenLayer Intelligent Contracts that decide **who may do what, when, and on which evidence**. LLM validators handle the parts that need judgment. Plain deterministic code handles everything else.

| Contract | Version | File | Role |
|---|---|---|---|
| `AuthorityLedger` | v0.5.1 | `contracts/authority_ledger.py` | Registry of delegations, requests, AI verdicts and appeals. A target system asks it one question: `check_authority`. |
| `ProtectedProtocol` | v0.4.1 | `contracts/protected_protocol.py` | Demo target. Pauses itself on a verdict, runs a bonded guardian fast path with slashing, and guards a critical action with two independent controls. |
| `ContinuityCore` | v0.4.1 | `contracts/continuity_core.py` | Verified facts with expiry (evidence leases), a dependency graph of assertions and actions, and AI judges whose prompt versions must pass golden cases. |

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
2. The delegate files a request. Validators run an LLM over the intent, the justification and, for critical actions, the exact action text. The verdict is `IN_SCOPE`, `OUT_OF_SCOPE` or `INCONCLUSIVE`.
3. The target calls `check_authority` (a read only view) and applies its own deterministic rules: replay protection, accepted scope, trusted root grantor, guardian quorum.
4. Optional gates: a request can rest on an action node in `ContinuityCore`. The Ledger asks `can_execute` again on every check, so an expired fact closes the gate without any AI call.

## Wiring

Deploy all three (`ProtectedProtocol` takes the guardian threshold as its constructor argument), then wire them as the owner of each. `ContinuityCore` must already exist when `set_continuity_address` runs:

- Ledger: `set_protected_protocol_address`, `set_continuity_address`
- Protocol: `set_ledger_address`, `add_accepted_scope` (for every scope it should honor, **including the scope of `RATIFY_GUARDIAN_PAUSE` requests**, otherwise every ratification is a refusal), `add_severity_reporter`, `add_guardian`, `set_slash_recipient`

The contracts are not upgradeable and keep no migration path.

## Status

- **Experimental, not audited.** Do not hold real value in these contracts.
- A hostile review of the first versions found 3 critical and 9 major issues. The current versions fix or mitigate them. Findings, residual risks and evidence are in [SECURITY.md](SECURITY.md).
- Verified offline (unit tests and 142 scenario steps on a stand-in for GenVM), by direct tests in gltest (`tests/direct`, 136 tests) and on GenLayer Studio: 92 of 97 write steps of the scenarios ran with the expected outcome. 5 of the 17 reverts have a captured reason. See `tests/results/studio-run-2-hardened.json`. That Studio run used AuthorityLedger v0.5.0, ProtectedProtocol v0.4.0 and ContinuityCore v0.4.0. **The patch versions (Ledger v0.5.1, Protocol v0.4.1, ContinuityCore v0.4.1) have not been run on Studio yet.**
- Ratification is rechecked when it is resolved: the verdict must still be valid (at most one hour) and the Ledger must still authorize the request, otherwise the pause is refused and the signers are slashed. Call `resolve_ratification` right after the verdict.
- AI outcomes depend on the validator LLM set and are not bit for bit reproducible.
- Trust is still centralized: one owner key per contract. Use a multisig address as owner.

## License

MIT, see [LICENSE](LICENSE).
loading README.md…]()
