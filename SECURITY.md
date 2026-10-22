# Security

## Status

These contracts are **experimental and unaudited**. They were checked with unit tests (`tests/direct`) and a hand run on GenLayer Studio. Do not use them to protect real funds. This document lists what we know is weak. Absence from the list does not mean absence of bugs.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use the repository's private vulnerability reporting (Security tab, Report a vulnerability) or contact the maintainer privately, and include the contract, the method, a transaction sequence that reproduces it and the network. Expect an acknowledgement, not a bounty.

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

## Verification so far

- Unit tests in `tests/direct` (gltest direct mode) cover the contract logic.
- A hand run on Studio on 2026-10-20 (`studio-run-hardened.json`): 92 of 97 planned write steps were executed and all 92 ended as expected. Only 5 of the 17 reverts have a captured reason, so the negative checks for F1, F2 and F9 reverted but stay unconfirmed by reason. The timeout, delay and cap paths were not run on chain.
- Nothing ran on a public testnet.

## Findings

The findings were made against earlier versions (AuthorityLedger v0.4.0, ProtectedProtocol v0.3.1, ContinuityCore v0.3.0), which are not part of this repository. The fixes ship as AuthorityLedger v0.5.0, ProtectedProtocol v0.4.0 and ContinuityCore v0.4.0.

CRITICAL means a design level hole that lets an unauthorized party take a privileged action or defeats a control the documentation promises. MAJOR means a bypass, a lasting block or an integrity loss that needs more conditions. MINOR means a bounded weakness or an invariant gap. There are no FATAL findings. Evidence is "code review" (read from the source), "observed on chain", or "reproduced offline".

| ID | Severity | Problem in the earlier versions | Fix | What is left | Evidence |
|---|---|---|---|---|---|
| F1 | CRITICAL | Anyone could self-grant a capability such as PAUSE_PROTOCOL with an intent they wrote, obtain an IN_SCOPE verdict and pause the protocol. The target trusted `authorized: true` as is, and the owner could not revoke other people's delegations, disable a capability or void a verdict. | Only the owner or an allowed grantor creates root delegations (`allow_root_grantor`). `check_authority` returns `scope` and `root_grantor`, and the Protocol requires an accepted scope and the owner or a trusted grantor as root. Kill switches: `disable_capability`, `owner_revoke_delegation`, `void_verdict`, `disallow_root_grantor`. | The owner key is the root of trust. An allowed grantor can still write a permissive intent, so allow only people you would trust with that capability. | code review |
| F2 | CRITICAL | A delegate holding a narrow intent could redelegate with a much broader one, and the AI judged requests against the broader text. | The child's intent hash must equal the parent's (`CHILD_INTENT_MUST_MATCH_PARENT`). | A child cannot narrow the intent either. That is deliberate. | code review |
| F3 | CRITICAL | A plain majority vote of guardians changed the threshold with no Ledger verdict, although the documentation promised two independent controls. The owner chooses the guardians, so the owner could move the threshold alone. | `propose_threshold_change`, `vote_threshold_change` and `get_threshold_proposal` were removed. The threshold changes only through the critical path. | The critical path still relies on guardian approvals, and the owner chooses the guardians. | code review |
| F4 | MAJOR | A non-revocable delegation in a victim's scope plus `resolve_conflict` could block every new request of the victim for as long as the attacker liked. | Conflicts are considered only inside one root grantor, flags are capped at 16, the scan covers the newest 64 delegations of a scope, and re-rolling an INCONCLUSIVE result needs a 300 second cooldown. | An allowed grantor can still block its own colleagues. A conflict remains an AI judgment. | code review, block observed on chain |
| F5 | MAJOR | A ratification verdict was not bound to the pause: one IN_SCOPE verdict could ratify any number of later pauses with the same text, an appeal could rewrite the judged justification, and the AI judged a story, not facts. | The request must be created after the pause and can be linked once. The verdict must match the pause justification, must not be voided and must be adjudicated after the pause, otherwise it counts as a refusal. | The AI still judges the stated story. Set `set_min_severity` on `RATIFY_GUARDIAN_PAUSE` to add a deterministic floor. | code review |
| F6 | MAJOR | Only a signer could link a ratification request, and there was no timeout, so a pause could stay unresolved forever with its signers' bonds locked. The owner had no unpause method. | After 7 days an unlinked or unadjudicated pause settles as a refusal, anyone can link after 1 hour, `cancel_stale_proposal` frees unexecuted proposals after 24 hours, `unpause_by_owner` is the last resort. | A stuck pause can still last up to 7 days, and its bond stays locked for that time. | code review, K1 observed on chain |
| F7 | MAJOR | Any evidence could be a parent of any statement, any open action node could gate unrelated requests, and anyone could attach children to your evidence and block its `reclaim` forever. | A gate node must be authored by the delegation's root grantor or the owner and gates one request only. Only a node's owner (or an address it granted with `grant_derive`) can derive from it, and a node takes at most 64 dependents. | Whether a fact is relevant to an action is still judged only by the AI prompt. | code review |
| F8 | MAJOR | The URL filter accepted `localhost.`, `foo.localhost`, `0x7f.1` and wildcard DNS names, source text was cut at 12000 characters so a later revocation was invisible, the page could close the prompt delimiter, and the leader's free text reason was stored as is. | Stricter filter (port 443, alphabetic TLD, no internal or wildcard DNS names), optional host allow list (`set_allowed_hosts`), oversized pages fail closed, the prompt fence cannot be closed by the page, stored reasons are sanitized. | The filter cannot see DNS resolution. Use the allow list and rely on validator network isolation (not verified). | code review, filter reproduced offline |
| F9 | MAJOR | `check_authority` carried no scope or target, so a grant for one target was accepted by any target trusting the same Ledger. | The target honors only scopes it names (`add_accepted_scope`). | The Ledger still reads severity from one Protocol. Deploy one Ledger per protected protocol. | code review |
| F10 | MAJOR | Comma separated indexes and linear scans grew without a cap, and delegations are permissionless. | Caps: 64 scanned, 16 flags, 512 delegations per scope and per delegate, 16 children per delegation, 64 dependents per node, 64 guardians, 16 reporters. | Indexes are still comma separated strings, so reading a large list stays linear. | code review |
| F11 | MAJOR | One owner key, no ownership transfer, a slash recipient that could be set once, and guardians that could be removed below the quorum. | Two step ownership transfer on all three contracts, delayed slash recipient change, guardians cannot be removed below the quorum. | Still one owner key unless the owner is a multisig address. Other owner actions have no timelock. | code review |
| F12 | MINOR | Verdicts lasted up to 24 hours and severity was not re-checked at execution, so an approval outlived the incident. | Verdicts live at most 3600 seconds. | Severity is still not re-checked at execution, so an approval stays usable for up to an hour after the incident. | code review |
| F13 | MINOR | The golden case gate only blocked a golden input appearing whole in the prompt, and the owner picks the cases. | A four word overlap with any golden case is rejected, and the cases need at least two distinct labels. | The owner still picks the cases, and LLM results can flip. | code review |
| F14 | MINOR | A one shot delegation was burned by an expired or cancelled request, built in capabilities had no severity floor setter, signatures of removed guardians stayed counted, and anyone could trigger revalidation while the source was down. | Cancelled or expired requests refund the slot, `set_min_severity` exists, revalidation and recertification are owner only, removed guardians' signatures are not counted, pause proposals expire. | None known. | code review |
| F15 | MINOR | Prompt injection was mitigated by instruction text only. | Every untrusted text is fenced, sanitized and limited to 1500 characters. | Inherent: prompt injection and disagreement between validator models cannot be excluded. | code review |
| K1 | MINOR | `withdraw_bond` kept reverting because of an old unresolved pause. | See F6. | See F6. | observed on chain |
| K2 | MINOR | `resolve_conflict` read storage inside the non-deterministic block (validators log a warning). | The four fields are copied into local strings first. | None known. | observed on chain |

## What was seen on Studio

| Property | Seen on Studio |
|---|---|
| Revoking a parent delegation invalidates its children, request limits, committee approvals, consequence class only increases | Yes |
| Routine class makes no AI call | Yes (first run) |
| Critical threshold change with verdict and guardian approvals, and an out of scope refusal | Yes. The refusal reason was not captured in the second run |
| Slashing, sweep to the recipient, bond withdrawal after the pause is resolved | Yes. Protocol balance 0.80 GEN equals 1.0 deposited, 0.1 swept to the recipient, 0.1 withdrawn |
| Conflict detection and the block it causes | Yes. The reason was captured in the first run only |
| Evidence lease cycle (verify, expire, revalidate, revoke, reclaim, execute) and judge activation with golden cases | Yes |
| Root grantor check, child intent check, scope check (F1, F2, F9) | The calls reverted as expected, the reason strings were not captured |
| Swapped action parameters rejected, appeal after INCONCLUSIVE, timeout paths, a stranger account creating a root delegation | Not seen on chain |

## Operational notes

- Severity snapshots are valid for 10 minutes. A late step fails with `SEVERITY_SNAPSHOT_STALE`, which is safe but easy to misread as a bug.
- Studio takes `Value` in GEN. Pasting a wei amount there can drain the account.
- A request that expires before its verdict fails with `REQUEST_EXPIRED`. Use long request ttls.

## Not verified

Public testnet behavior, any load or gas limit, the appeal flow, the swapped parameter rejection, the reason strings of most reverts, a stranger account attacking a deployment, and concurrent use by several operators.
