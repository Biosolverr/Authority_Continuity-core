# Deployment

The previous contract versions were tested on GenLayer Studio (`studionet`). **The versions described here (Ledger v0.5.0, Protocol v0.4.0, ContinuityCore v0.4.0) have been verified offline and in part on Studio** (see `tests/results/studio-run-2-hardened.json`). Public testnets are untested.

## Prerequisites

- Three accounts you control, called O (owner and deployer), A and B. To script anything you need their private keys. Studio did not show keys for its built in accounts in our setup, so create accounts you hold the keys for (for example with `genlayer account create` or any wallet) and import them.
- The three contract files. Each starts with a `# { "Depends": "py-genlayer:..." }` header that must stay on the second line.
- Node 18 or newer for the tests and the console.

## 1. Deploy, in this order

| Order | Contract | Constructor arguments |
|---|---|---|
| 1 | `ContinuityCore` | none |
| 2 | `AuthorityLedger` | none |
| 3 | `ProtectedProtocol` | `guardian_threshold` (integer, at least 1). The tested run used 2 |

Deploy all three with account O, because the deployer becomes the owner.

In Studio: open the contract file, pick the account, set the argument for `ProtectedProtocol`, deploy. With the CLI (flags change between versions, check `genlayer deploy --help`): select the network with `genlayer network`, then deploy each file.

Record the three addresses. Call them `LEDGER`, `PROTOCOL`, `CONTINUITY`.

## 2. Wire them (all signed by O)

| Step | Contract | Method | Argument |
|---|---|---|---|
| 1 | Ledger | `set_protected_protocol_address` | `PROTOCOL` |
| 2 | Protocol | `set_ledger_address` | `LEDGER` |
| 3 | Ledger | `set_continuity_address` | `CONTINUITY` (probed by a read, a wrong address reverts `NOT_A_CONTINUITY_CONTRACT`) |
| 4 | Protocol | `set_slash_recipient` | the address that should receive penalties (once. Later changes need `propose_slash_recipient` and a 24 hour wait) |
| 5 | Protocol | `add_severity_reporter` | the account that will publish severity |
| 6 | Protocol | `add_guardian` | each guardian address (at least as many as the threshold) |
| 7 | Protocol | `add_accepted_scope` | every scope the target will honor, for example `guardian-quorum`. **Without this no verdict is honored** (`SCOPE_NOT_ACCEPTED`) |

Steps 1 to 4 work once and revert with `ALREADY_SET` afterwards.

Authority model, decide before you grant anything:

- The owner can always create root delegations. To let someone else do it: Ledger `allow_root_grantor(capability, grantor)` **and** Protocol `add_trusted_grantor(grantor)`. Both are needed.
- Recommended: Ledger `set_min_severity` for `RATIFY_GUARDIAN_PAUSE` and `PAUSE_PROTOCOL`, so a deterministic floor backs the AI. Continuity `set_allowed_hosts` to name the evidence hosts you accept.
- Emergency controls you now have: Ledger `disable_capability`, `owner_revoke_delegation`, `void_verdict`, `disallow_root_grantor`; Protocol `unpause_by_owner`.
- Hand ownership to a multisig address with `transfer_ownership`, then `accept_ownership` from that address. Do this on all three contracts.
- Use one Ledger per protected protocol: the Ledger reads severity from a single Protocol.
- Optional hardening: Ledger `require_gate_for_capability` for `PAUSE_PROTOCOL`. Gate nodes must be authored by the delegation's root grantor or the owner and gate one request only.

## 3. Verify the wiring

- Protocol `get_guardians`: expected `active_count` and `threshold`.
- Protocol `get_slash_info`: `recipient` equals the address you set.
- Ledger `list_capabilities`: four built in capabilities, `CHANGE_GUARDIAN_THRESHOLD` with `assurance_level` 2, none disabled.
- Protocol `is_scope_accepted` for each scope you added: `true`.
- Ledger `get_stats`: all zeros on a fresh deployment.

## 4. Run the checks

```bash
cd tests
npm install
export CHAIN=studionet
export O_KEY=0x...  A_KEY=0x...  B_KEY=0x...
export LEDGER=0x...  PROTOCOL=0x...  CONTINUITY=0x...
(cd offline && python3 -m unittest && python3 run_scenarios.py)   # offline checks, no network
npm run plan        # prints the plan, sends nothing
npm run test:fast   # phases 0 and 1, no AI calls
npm test            # everything, including LLM steps (slow)
```

The scenarios assume a fresh deployment with threshold 2. Phase 0 does the wiring (guardians O, A, B, reporter O, recipient B, accepted scope `guardian-quorum`). Phase 6 also wants a fourth account in `X_KEY` that holds no role. Phase 0 of the scenarios repeats the wiring, so if you already wired by hand, skip it with `PHASES=1,2,3,4,5 npm test`, otherwise the one shot setters revert with `ALREADY_SET`.

## 5. The web console (optional)

`console/index.html` is a static page. Host it anywhere, for example on Vercel with the included `vercel.json` (`framework` null, no build). Enter the network, a private key and the three addresses in the bar at the top, then press Connect: it probes each contract with a read.

The key stays in the current tab (`sessionStorage`) and is gone when the tab closes, unless you tick "Remember keys on this device", which moves it to `localStorage`. Use throwaway keys on test networks only (SECURITY.md, C1).

## Common mistakes

| Symptom | Cause |
|---|---|
| `NOT_OWNER` on wiring | A call was signed by an account other than the deployer |
| `SEVERITY_SNAPSHOT_STALE` | More than 10 minutes between `report_severity` and the AI step |
| `REQUEST_EXPIRED` | Request ttl too short. Use 86400 or more |
| `*_HASH_MISMATCH` | A pasted text lost a character, or the hash was computed from different text |
| Studio account drained after a deposit | `Value` was entered in wei. Studio expects GEN |
| `SLASH_RECIPIENT_NOT_SET` on sweep | Wiring step 4 was skipped |
| `SCOPE_NOT_ACCEPTED` | Wiring step 7 was skipped for that scope |
| `GRANTOR_NOT_ALLOWED` | The signer is neither the owner nor an allowed grantor of that capability |
| `ROOT_GRANTOR_NOT_TRUSTED` | The Protocol does not trust that grantor (`add_trusted_grantor`) |
| `BAD_VALID_SECONDS` | A verdict lives at most 3600 seconds |
[DEPLOY.md](https://github.com/user-attachments/files/33808507/DEPLOY.md)
