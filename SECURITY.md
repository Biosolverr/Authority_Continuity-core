# Security

## Status

These contracts are **experimental and unaudited**. The previous versions were tested by hand on GenLayer Studio. The hardened versions were verified offline and in part on Studio. Do not use them to protect real funds. This document lists what we know is weak. Absence from the list does not mean absence of bugs.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use the repository's private vulnerability reporting (Security tab, Report a vulnerability; the maintainer must enable it) or contact the maintainer privately, and include the contract, the method, a transaction sequence that reproduces it and the network. Expect an acknowledgement, not a bounty.

## Trust model

| Actor | Can do | Cannot do |
|---|---|---|
| Owner (one key per contract) | Link contracts once, register capabilities, raise a capability's consequence class and severity floor, switch gates on, allow or disallow root grantors, disable or enable a capability, revoke any delegation, void any verdict, add or remove reporters and guardians (never below the quorum), name accepted scopes and trusted grantors on the target, unpause as a last resort, propose a new slash recipient (24 hour delay), transfer ownership in two steps, set the evidence host allow list | Lower a class or floor, switch a gate off, change the slash recipient instantly, change evidence or judges it does not own |
| Allowed root grantor | Create root delegations for the capabilities it was allowed for. The target still honors them only for its accepted scopes | Act on a capability it was not allowed for |
| Delegate | Request, redelegate with the identical intent, within depth, window and limits | Widen the intent, redelegate a limited delegation |
| Severity reporter | Publish a score, the median of fresh reports is what counts | Be added without the owner |
| Guardian | Pause with a bond, sign, approve critical actions | Withdraw a bond while a signed pause is unresolved, change the threshold alone |
| Anyone | Resolve a flagged conflict inside one root, expire requests, poll, refresh, sweep slashed funds, link a ratification request after one hour, resolve a timed out pause, cancel a stale proposal, apply a proposed recipient after the delay | Create root delegations, derive from other people's nodes, bypass a verdict on the target |
| Validators | Run the LLM, fetch evidence sources, reach consensus on a normalized decision | Be assumed honest or identical to each other |

## Status of the findings after the hardening release

Findings were made against AuthorityLedger v0.4.0, ProtectedProtocol v0.3.1 and ContinuityCore v0.3.0. The fixes ship as AuthorityLedger v0.5.1, ProtectedProtocol v0.4.1 and ContinuityCore v0.4.1. The later patch versions add F16 to F20, L2 and L3 below, after review remarks and our own pass over the code.

**Verification so far:** 27 unit tests and all 142 executable steps of the scenario file pass on an offline stand-in for GenVM (kept in the development repository, not in this submission). Removing a fix makes a test fail in 9 of 10 mutation checks (the tenth is a redundant check). **The hardened versions also ran on Studio** (2026-10-20): 92 of the 97 write steps of the scenarios have a matching transaction and every one ended as expected. Only 5 of the 17 reverts have a captured reason, so the negative checks for F1, F2 and F9 reverted but stay unconfirmed by reason, and the timeout, delay and cap paths were never run on chain (see `tests/results/studio-run-2-hardened.json`). Treat the offline result as the main evidence and the Studio run as a smoke test.

| ID | Severity | Status | What changed | What is left |
|---|---|---|---|---|
| F1 | CRITICAL | FIXED | Ledger: only the owner or an allowed grantor can create a root delegation (allow_root_grantor). check_authority returns scope and root_grantor, the Protocol requires an accepted scope and the owner or a trusted grantor as root. Owner kill switches: disable_capability, owner_revoke_delegation, void_verdict, disallow_root_grantor. | The owner key is now the root of trust. An allowed grantor can still write a permissive intent, so allow only people you would trust with that capability. |
| F2 | CRITICAL | FIXED | redelegate requires the child's intent hash to equal the parent's (CHILD_INTENT_MUST_MATCH_PARENT). | A child cannot narrow the intent either. That is deliberate. |
| F3 | CRITICAL | FIXED | propose_threshold_change, vote_threshold_change and get_threshold_proposal were removed. The threshold changes only through the critical path. | The critical path still relies on guardian approvals, and the owner chooses the guardians. |
| F4 | MAJOR | MITIGATED | Conflicts are only considered inside one root grantor, flags are capped at 16, the scan covers the newest 64 delegations of a scope, re-rolling INCONCLUSIVE needs a 300 second cooldown. | An allowed grantor can still block its own colleagues. A conflict remains an AI judgment. |
| F5 | MAJOR | MITIGATED | A ratification request must be created after the pause and can be linked once. The verdict must match the pause justification, must not be voided, and must be adjudicated after the pause, otherwise it counts as a refusal. Since v0.4.1 an IN_SCOPE verdict ratifies only if the Ledger still authorizes the linked request when resolve_ratification runs (see F16). | The AI still judges the stated story, not the facts. Set set_min_severity on RATIFY_GUARDIAN_PAUSE to add a deterministic floor. |
| F16 | MAJOR | FIXED (v0.4.1) | resolve_ratification rechecks the linked request against the Ledger's current authorization (check_authority: verdict valid and not voided, delegation chain, capability and gate live, root grantor allowed), then the Protocol's own accepted scope and trusted root grantor. Any failure, or an unreachable Ledger, settles the pause as a refusal. | A verdict lives at most one hour, so resolve_ratification must run inside that window or the pause is refused and the signers are slashed. The ratification scope must be added with add_accepted_scope, otherwise every ratification is a refusal. |
| F18 | MINOR | FIXED (v0.4.1) | link_ratification_request accepts only a request whose requester signed that pause, so an outsider holding a ratification delegation cannot link a request bound to fail and get the signers slashed. | A signer can still link a request that will fail, which only hurts the signers themselves. |
| F19 | MINOR | FIXED (v0.4.1) | A critical action's approval window is capped by the valid_until of the verdict behind it, instead of a fixed 24 hours that the Ledger recheck at the last approval made unreachable. | The guardians must approve inside the verdict window (at most one hour). |
| F20 | MINOR | FIXED (ContinuityCore v0.4.1) | verify_evidence is owner only, like revalidate, so a third party cannot choose when the source is read, start someone else's lease clock or trigger its retry cooldown. | None known. |
| L2 | MINOR | FIXED (AuthorityLedger v0.5.1) | is_delegation_valid applies the same live checks as check_authority for a disabled capability and a disallowed root grantor. | The view still ignores the verdict, the request limit and conflicts. It tells whether the delegation is usable, not whether an action is authorized. |
| L3 | MINOR | FIXED (AuthorityLedger v0.5.1) | A cancelled or expired gated request releases its gate node, which can then gate a new request. | A request that was adjudicated keeps its gate. |
| F17 | MINOR | FIXED (v0.4.1) | propose_pause reverts PROPOSAL_EXISTS for an id that already exists, so a repeated call with the same text, time and guardian cannot overwrite a proposal. | None known. |
| F6 | MAJOR | FIXED | resolve_ratification settles an unlinked or unadjudicated pause as a refusal after 7 days, anyone can link after 1 hour, cancel_stale_proposal frees unexecuted proposals after 24 hours, unpause_by_owner is the last resort. | A stuck pause can still last up to 7 days, and its bond stays locked for that time. |
| F7 | MAJOR | MITIGATED | A gate node must be authored by the delegation's root grantor or the owner and gates one request only. Only a node's owner (or an address it granted with grant_derive) can derive from it, and a node takes at most 64 dependents. | Whether a fact is relevant to an action is still judged only by the AI prompt. |
| F8 | MAJOR | MITIGATED | Stricter URL filter (port 443, alphabetic TLD, no internal or wildcard DNS names), optional host allow list (set_allowed_hosts), oversized pages fail closed, source text cannot close the prompt fence, stored reasons are sanitized. | The filter cannot see DNS resolution. Use the allow list, and rely on validator network isolation (not verified). |
| F9 | MAJOR | PARTLY FIXED | The target honors only scopes it names (add_accepted_scope), so a grant for one target is refused by another. | The Ledger still reads severity from one Protocol. Deploy one Ledger per protected protocol. |
| F10 | MAJOR | MITIGATED | Caps: 64 scanned, 16 flags, 512 delegations per scope and per delegate, 16 children per delegation, 64 dependents per node, 64 guardians, 16 reporters. | Indexes are still comma separated strings, so reading a large list stays linear. |
| F11 | MAJOR | PARTLY FIXED | Two step ownership transfer on all three contracts, delayed slash recipient change, guardians cannot be removed below the quorum. | Still one owner key unless the owner is a multisig address. Other owner actions have no timelock. |
| F12 | MINOR | MITIGATED | Verdicts live at most 3600 seconds (was 86400). | Severity is still not re-checked at execution, so an approval stays usable for up to an hour after the incident. |
| F13 | MINOR | MITIGATED | A four word overlap with any golden case is rejected, and the cases need at least two distinct labels. | The owner still picks the cases, and LLM results can flip. |
| F14 | MINOR | FIXED | Cancelled or expired requests refund the limit slot, set_min_severity exists, revalidation and recertification runs are owner only, signatures of removed guardians are not counted, pause proposals expire. | None known. |
| F15 | MINOR | MITIGATED | Every untrusted text is fenced and sanitized in prompts and limited to 1500 characters. | Inherent: prompt injection and disagreement between validator models cannot be excluded. |
| K1 | MINOR | FIXED | See F6. | See F6. |
| K2 | MINOR | FIXED | resolve_conflict copies the four fields into local strings before the non-deterministic block. | None known. |
| C1 | MAJOR | PARTLY FIXED | Keys live in the tab (sessionStorage) unless the person ticks remember, saved key lists follow the same rule, the SDK version is pinned to 1.1.8. | No integrity hash on CDN scripts. A remembered key is still exposed to XSS. |

## Findings in detail

Each entry describes the problem as it was found in the earlier versions.

### F1 (CRITICAL): The root grantor is not authenticated, and the owner has no kill switch

- **Consequence:** Anyone can self-grant a capability such as PAUSE_PROTOCOL with an intent they wrote themselves, obtain an IN_SCOPE verdict (it needs a fresh severity snapshot, which honest reporters supply), and call pause_via_verdict or unpause_via_verdict. A delegation can be created non-revocable, and the owner cannot revoke other people's delegations, disable a capability or void a verdict.
- **Root cause:** create_delegation is open to any address. check_authority returns no root grantor and ProtectedProtocol trusts authorized: true as is. The Ledger has no owner controlled allow list and no emergency controls.
- **Mitigation:** Keep an owner managed allow list of root grantors per capability and return root_grantor from check_authority so each target compares it with its own owner. Add an owner kill switch per capability.
- **Evidence:** code review

### F2 (CRITICAL): Redelegation lets the delegate replace the grantor's intent

- **Consequence:** A delegate holding a narrow intent can redelegate (max_depth 1 or more) with a much broader intent, and the AI then judges requests against the broader text. The constraint the grantor wrote is bypassed one hop down. Capability and scope are inherited, intent is not.
- **Root cause:** redelegate stores the intent_hash argument for the child. _create_request, _prepare_judgment and the prompt use only the child's intent. The parent's intent is never consulted again.
- **Mitigation:** Force child intent_hash to equal the parent's, or judge every ancestor intent and require IN_SCOPE for all of them.
- **Evidence:** code review

### F3 (CRITICAL): A plain guardian vote bypasses the critical threshold control

- **Consequence:** The v0.3 header says CHANGE_GUARDIAN_THRESHOLD needs two independent controls (verdict for the exact action plus guardian approvals). A second path, propose_threshold_change and vote_threshold_change, changes the same threshold with a strict majority of active guardians and no Ledger verdict. The owner controls the guardian set, so the owner can add sock puppets and move the threshold alone. Documentation contradicts implementation.
- **Root cause:** The old v0.2 threshold path was kept when the critical path was added.
- **Mitigation:** Remove the plain path or make it call the same Ledger check. Require a bond to count as a guardian vote.
- **Evidence:** code review

### F4 (MAJOR): The conflict check can be used to block anyone's new requests

- **Consequence:** Delegations in the same scope with a different capability or delegate are flagged as possible conflicts, and the flag is written into both sides. An attacker creates a non-revocable delegation in the victim's scope, writes an opposing intent, and calls resolve_conflict. If the LLM answers CONFLICT, every new request on the victim's delegation fails with BLOCKED_BY_UNRESOLVED_CONFLICT_WITH until the attacker revokes, which can be never. Existing verdicts keep working. Feasible once the victim's intent text has appeared in any transaction, because resolve_conflict needs it.
- **Root cause:** Anyone can create delegations in any scope, resolve_conflict is permissionless, and a CONFLICT with any active delegation blocks, whoever granted it.
- **Mitigation:** Only consider conflicts between delegations of the same root grantor, or let the victim's grantor dismiss a conflict. Cap flags per delegation.
- **Evidence:** code review, block observed on chain

### F5 (MAJOR): A ratification verdict is not bound to the pause, and it judges a story, not facts

- **Consequence:** link_ratification_request checks only the capability and that the request's justification_hash equals the sha256 of the pause text. resolve_ratification ignores valid_until and creation time. One IN_SCOPE verdict can therefore ratify any number of later pauses that reuse the same text, and a verdict adjudicated before the pause existed counts. After an INCONCLUSIVE verdict the appeal accepts a new justification, so the text that gets judged can differ from the text of the pause. More fundamentally the AI sees only the stated justification, and the only external fact is the score from owner appointed reporters. A false 'active exploitation in progress' passes if the intent matches and the score is not contradicting it.
- **Root cause:** The Protocol never ties the request to this pause by time, delegate or verdict hash, and the Ledger offers no fact check.
- **Mitigation:** Store the verdict hash and require adjudication after the pause. Reject a request already linked to another pause. Compare the appeal justification hash with the pause hash.
- **Evidence:** code review

### F16 (MAJOR): Ratification used a verdict that could have lapsed by resolution time

- **Consequence:** Up to v0.4.0, resolve_ratification read the verdict and compared its decision, voided flag, justification hash and time. It never asked the Ledger whether the request was still authorized at that moment. An IN_SCOPE verdict could ratify a pause after the verdict had expired, after the delegation or capability was revoked or disabled, after a gate closed or the root grantor was disallowed, and without the Protocol's own accepted scope and trusted root grantor checks that pause_via_verdict applies.
- **Root cause:** The ratification path used get_verdict and its own checks instead of the Ledger's check_authority, which every other path uses.
- **Fix:** resolve_ratification calls check_authority for the linked request (actor is the request's requester, capability RATIFY_GUARDIAN_PAUSE, the request's own action params hash) and then applies the same scope and root grantor rules as _verify_result. A denial, a missing scope or untrusted grantor, or an unreachable Ledger turns the decision into a refusal: signers are slashed and the pause is lifted, never left open.
- **Operational effect:** the verdict window (at most 3600 seconds) is now also the window to call resolve_ratification. A pause whose verdict lapses before resolution is refused.
- **Evidence:** offline tests test_f16_* (valid ratification, unaccepted or removed scope, expired verdict, revoked delegation, disabled capability, disallowed or untrusted root grantor, closed gate, voided verdict). Not yet run on Studio.

### F18 to F20, L2, L3 (MINOR): found in our own pass after the F16 review remark

- **F18:** after one hour anyone may link a ratification request. An outsider with a RATIFY_GUARDIAN_PAUSE delegation could link a request that is bound to be refused and make the signers lose their bond. Fix: the request's requester must be a signer of the pause (REQUESTER_NOT_A_SIGNER).
- **F19:** a critical action advertised a 24 hour approval window, but the Ledger recheck at the last approval fails once the verdict (at most one hour) has expired, so late approvals could never finish. Fix: the window ends at the verdict's valid_until.
- **F20:** verify_evidence had no owner check, unlike revalidate (F14). Fix: owner only.
- **L2:** is_delegation_valid ignored a disabled capability and a disallowed root grantor, so it could read true where check_authority denies. Fix: same checks.
- **L3:** a gated request that was cancelled or expired kept its gate node bound forever. Fix: the gate is released.
- **Evidence:** direct tests (test_is_delegation_valid, test_verify_evidence_is_owner_only) and offline tests test_f18_*, test_f19_*, test_f20_*, test_l2_*, test_l3_*. Not yet run on Studio.

### F17 (MINOR): A repeated pause proposal could overwrite an earlier one

- **Consequence:** The proposal id is a hash of the text, the transaction time and the guardian. The same guardian sending the same text in the same timestamp overwrote the stored proposal, resetting executed, resolved, link and signers while the protocol stayed paused.
- **Fix:** propose_pause reverts PROPOSAL_EXISTS.
- **Evidence:** direct test test_proposal_id_cannot_be_overwritten and offline test_f17_*.

### F6 (MAJOR): A pause can become unresolvable, and a bond can stay locked

- **Consequence:** Only a signer can call link_ratification_request, and resolve_ratification needs a linked request. A guardian who pauses and never links keeps the protocol paused and their bond locked, and nobody else can force resolution. The owner has no unpause method: the only exits are unpause_via_verdict (which depends on F1 being fixed the right way) and resolve_ratification. A pause that never reaches its threshold also keeps signers' bonds locked. On the tested network a leftover pause kept guardian A's bond locked after a later pause was resolved and slashed (K1).
- **Root cause:** No timeout, no third party linking, and active_signed_count is decreased only in resolve_ratification.
- **Mitigation:** After the grace period let anyone link or close the pause, with the same slashing result as a refusal. Add an owner or quorum unpause.
- **Evidence:** code review, K1 observed on chain

### F7 (MAJOR): Gates prove freshness, not relevance, and anyone can build on anyone's evidence

- **Consequence:** derive_assertion and derive_action accept any evidence as a parent and any text as the statement. Nothing checks that the text follows from the parents. create_request_gated accepts any ACTION node, and the Ledger only asks can_execute, so one open node can gate unrelated requests and is not consumed by them. Anyone can derive from your evidence, which adds children and blocks your reclaim forever.
- **Root cause:** Continuity checks liveness of parents, never meaning. Relevance is left to a soft instruction in the Ledger prompt.
- **Mitigation:** Bind a gate node to one request or capability and to an approved author. Limit who can attach children, or let the evidence owner detach strangers.
- **Evidence:** code review

### F8 (MAJOR): Evidence fetching: filter bypass, hidden text, delimiter breakout

- **Consequence:** _valid_url rejects localhost but accepts https://localhost./, https://foo.localhost/, https://0x7f.1/ and names that resolve to private or metadata addresses such as 169.254.169.254.nip.io, so validators may be pushed to fetch internal addresses (the response can leak through the leader's free text reason, 200 characters, which is stored). Source text is cut at 12000 characters, so a revocation placed after that point is invisible to revalidation. The source is wrapped in a fixed delimiter that the page can close, then add its own instructions.
- **Root cause:** String based host checks, no resolution check, no escaping, free text reason stored without validation.
- **Mitigation:** Allow list of source hosts, resolve and check addresses on the validator side, escape or randomize the delimiter, fail revalidation when the page exceeds the limit.
- **Evidence:** code review, URL filter reproduced offline

### F9 (MAJOR): Capability grants are global across targets

- **Consequence:** check_authority takes no scope and no target identity. A verdict for PAUSE_PROTOCOL in scope 'vault-a' is accepted by any ProtectedProtocol that trusts the same Ledger, and each target keeps its own replay map, so one request can be consumed once on every target. The Ledger also reads severity from one fixed Protocol, which then gates verdicts that other targets consume.
- **Root cause:** The adapter was designed for one target and generalized without a target binding.
- **Mitigation:** Pass scope or a target id into check_authority and compare it, and keep severity per target.
- **Evidence:** code review

### F10 (MAJOR): Unbounded growth and linear scans

- **Consequence:** scope_index, delegate_index and the conflict lists are comma separated strings. _scan_potential_conflicts walks every delegation of a scope, and every new delegation appends itself to each flagged peer, so create_request of the victim loops over a list the attacker keeps growing. Delegations are permissionless.
- **Root cause:** Storage as CSV strings and O(n) loops without a cap.
- **Mitigation:** Cap flags and index sizes, use real maps, require a deposit for creating delegations.
- **Evidence:** code review

### F11 (MAJOR): Single owner key and one way setters

- **Consequence:** One key sets reporters, guardians and wiring, and no ownership transfer exists. set_slash_recipient works once: a wrong address receives every penalty forever, and a lost owner key leaves slashed funds unsweepable if no recipient was set. remove_guardian can drop active guardians below the threshold and brick the fast pause path.
- **Root cause:** No transfer, no delay, no invariants on removal.
- **Mitigation:** Multisig owner with a delay, a recipient change with a delay, and an invariant active guardians >= threshold.
- **Evidence:** code review

### F12 (MINOR): The verdict outlives the incident

- **Consequence:** Severity is read at adjudication only. check_authority does not re-check it, and verdicts last up to 24 hours, so an approval given during an incident stays usable after it ended.
- **Root cause:** Severity is not part of the execution time check.
- **Mitigation:** Re-read severity in check_authority or shorten verdicts.
- **Evidence:** code review

### F13 (MINOR): The golden case gate is gameable

- **Consequence:** _overfit blocks only a golden input appearing whole inside the prompt. A prompt with keyword rules copied from the cases passes. The owner picks 3 to 8 cases, so the gate proves that the owner's own examples pass. LLM flakiness can flip PASS and FAIL.
- **Root cause:** Substring check, owner chosen cases, no diversity requirement.
- **Mitigation:** Fuzzy overlap check, held out cases, repeat runs.
- **Evidence:** code review

### F14 (MINOR): Smaller state and invariant gaps

- **Consequence:** A one shot delegation is burned by a request that expires or is cancelled. Votes and signatures of removed guardians stay counted for plain pauses and threshold votes, and threshold proposals never expire. Built in capabilities cannot receive a min_severity because there is no setter. A conflict result of INCONCLUSIVE can be re-rolled by anyone. Anyone can trigger revalidation of an expired lease at a moment when the source is down, which fails it closed for another cooldown.
- **Root cause:** Missing refunds, expiries and setters.
- **Mitigation:** Refund on expiry, expire proposals, add a min_severity setter, recount votes on use.
- **Evidence:** code review

### F15 (MINOR): AI decisions are not proofs

- **Consequence:** Prompt injection is mitigated by instruction text only. Validators run different models and can disagree. An LLM cannot be forced to answer INCONCLUSIVE, so the appeal path stays unexercised.
- **Root cause:** Inherent to the design.
- **Mitigation:** Keep irreversible actions behind deterministic controls, as the critical path does.
- **Evidence:** code review

### K1 (MINOR): Bond locked by an old unresolved pause

- **Consequence:** See F6. withdraw_bond kept reverting with BOND_LOCKED_BY_UNRESOLVED_PROPOSAL.
- **Root cause:** See F6.
- **Mitigation:** See F6.
- **Evidence:** observed on chain

### K2 (MINOR): Storage read inside a non-deterministic block

- **Consequence:** resolve_conflict logs 'Detected pickling storage class. Reading storage in nondet mode is not supported'. It succeeds and validators agree today.
- **Root cause:** get_decision captures stored structs a and b.
- **Mitigation:** Copy the four fields into local strings first.
- **Evidence:** observed on chain

### C1 (MAJOR): The web console keeps a private key in the browser

The console is not part of this submission. The finding is kept because it belongs to the full development repository.

- **Consequence:** The key lives in localStorage and the SDK is loaded from esm.sh without a pinned version or integrity hash. A compromised release or XSS can steal it. The console writes chain data with text nodes only (no innerHTML found), which limits XSS.
- **Root cause:** Convenience over isolation.
- **Mitigation:** Throwaway keys on test networks only, pin the SDK, never paste a key that holds value.
- **Evidence:** code review, no HTML sinks found

### Suggested fix order (done in this release, in this order)

1. F1 and F2. 2. F3. 3. F5 and F6. 4. F4, F8, F9, F7. 5. The rest.

## Properties we rely on, and how well they are backed

| Property | Backing |
|---|---|
| Only the owner or an allowed grantor creates root delegations, and targets verify scope and root grantor | Offline tests. On chain: step 6.1 (stranger X) was not run, two reverted create_delegation calls by A fit but their reasons were not captured, the reverted pause in step 6.7 is unconfirmed by reason |
| A child delegation carries the parent's intent | Offline tests. On chain step 6.3 reverted, reason not captured |
| The threshold changes only through the critical path | Offline tests (the plain vote methods no longer exist) |
| A parent revoked or expired invalidates the whole chain, request limits, committee approvals, class only increases | Tested live on Studio on the old and the hardened versions, offline tests |
| Routine class makes no AI call | Tested live, offline test |
| Swapped action parameters are rejected | Offline tests. Step 2.7 was not run on chain |
| A ratification verdict belongs to one pause and matches its justification | Offline tests. The normal path (link, adjudicate, resolve, slash) ran on chain |
| A pause cannot stay stuck | Offline tests. On chain only the normal path ran (bond withdrawn after resolve). The 7 day timeout path did not |
| Slashed funds reach the recipient only | Tested live on both versions (Protocol balance 0.80 GEN: 1.0 deposited, 0.1 swept to B, 0.1 withdrawn by A), offline test |
| Replay protection | On the target, tested live on ProtectedProtocol |
| An expired fact closes a gate without AI | Tested earlier on Studio, fields not recorded |
| Appeal after INCONCLUSIVE | Offline tests with a scripted LLM. An LLM cannot be forced to answer INCONCLUSIVE on chain |

## Operational notes

- Severity snapshots are valid for 10 minutes. A late step fails with `SEVERITY_SNAPSHOT_STALE`, which is safe but easy to misread as a bug.
- Studio takes `Value` in GEN. Pasting a wei amount there can drain the account.
- A request that expires before its verdict fails with `REQUEST_EXPIRED`. Use long request ttls.

## Not verified

Public testnet behavior, any load or gas limit, the appeal flow, the parameter swap rejection (step 2.7), the reason strings of most reverts, concurrent use by several operators, and the automated runner. See `tests/results/studio-run-2-hardened.json`.
