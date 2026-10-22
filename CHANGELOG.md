# Changelog

## Hardening release: AuthorityLedger v0.5.0, ProtectedProtocol v0.4.0, ContinuityCore v0.4.0

Fixes the findings F1 to F15, K1, K2 and C1 of [SECURITY.md](SECURITY.md). The contracts are **not upgradeable and state is not migrated**: deploy new instances and wire them again (see [DEPLOY.md](DEPLOY.md)). Verified offline, and in part on Studio (2026-10-20, see `tests/results/studio-run-2-hardened.json`).

### Breaking changes you will notice

AuthorityLedger
- `create_delegation` reverts `GRANTOR_NOT_ALLOWED` unless the signer is the owner or was allowed with `allow_root_grantor(capability, grantor)`.
- `redelegate` requires the child `intent_hash` to equal the parent's (`CHILD_INTENT_MUST_MATCH_PARENT`).
- A verdict lives at most **3600 seconds** (`valid_seconds`), it was 86400.
- Texts passed to `adjudicate`, `adjudicate_action`, `appeal_*` and `resolve_conflict` are limited to 1500 characters (`TEXT_TOO_LONG`).
- `check_authority` returns two more fields: `scope` and `root_grantor`. It denies with `VERDICT_VOIDED`, `CAPABILITY_DISABLED` and `ROOT_GRANTOR_NOT_ALLOWED` as well.
- `get_verdict` returns `adjudicated_at` and `voided`. `get_capability` and `list_capabilities` return `disabled`. `get_delegation` returns `root_grantor` and `children_count`.
- `create_request_gated` requires the gate node to be authored by the delegation's root grantor or the owner (`GATE_AUTHOR_NOT_TRUSTED`) and binds it to one request (`GATE_ALREADY_BOUND`).
- Cancelling or expiring a pending request gives its limit slot back.
- `resolve_conflict` on an INCONCLUSIVE pair needs a 300 second cooldown between attempts (`COOLDOWN`). Conflicts are only considered between delegations of the same root grantor.
- Caps: 16 conflict flags, 512 delegations per scope and per delegate, 16 children per delegation (`SCOPE_FULL`, `TOO_MANY_DELEGATIONS`, `TOO_MANY_CHILDREN`).
- Side effect to know: a delegation's root grantor is compared with the current owner and the allow list at check time. After an ownership transfer the previous owner's delegations stop working unless that address is allowed explicitly.

ProtectedProtocol
- Removed: `propose_threshold_change`, `vote_threshold_change`, `get_threshold_proposal`. The threshold changes only through `propose_critical_threshold_change` and `approve_critical_action`.
- A verdict is honored only for scopes named with `add_accepted_scope`, and only when the root grantor is the owner or was added with `add_trusted_grantor` (`SCOPE_NOT_ACCEPTED`, `ROOT_GRANTOR_NOT_TRUSTED`).
- `link_ratification_request`: the request must be created after the pause (`REQUEST_PREDATES_PAUSE`) and can be linked once (`REQUEST_ALREADY_LINKED`). Non signers may link after one hour.
- `resolve_ratification`: a verdict that is voided, adjudicated before the pause, or judged on a different justification (for example after an appeal that rewrote it) counts as a refusal. After 7 days an unlinked or unadjudicated pause is settled as a refusal.
- `remove_guardian` reverts `WOULD_BREAK_QUORUM` below the threshold. `report_severity` accepts scores up to 1,000,000. Texts of pauses are limited to 2000 characters.
- `sign_pause` and `propose_pause` count signatures of active guardians only, and a proposal older than 24 hours cannot be signed (`PROPOSAL_EXPIRED`).
- `get_proposal` returns `created_at`. `get_slash_info` returns `pending_recipient` and `pending_recipient_at`.

ContinuityCore
- The contract has an owner now (the deployer). It only controls `set_allowed_hosts`.
- `derive_assertion` and `derive_action` need ownership of every parent or a grant from the parent's owner (`grant_derive`), `NOT_ALLOWED_TO_DERIVE`. A node accepts at most 64 dependents.
- `request_revalidation`, `revalidate` and the recertification runs of `run_case` are owner only.
- Source URLs: port 443 only, plain DNS names with an alphabetic top level domain, no internal or wildcard DNS names. Pages above 12000 characters fail closed as `SOURCE_UNAVAILABLE`.
- Judges need at least two distinct expected labels (`NEED_TWO_LABELS`). A four word overlap between a golden input and the prompt counts as overfitting.
- `get_log` and `get_children` return an empty list for negative offsets.

### New methods

AuthorityLedger: `transfer_ownership`, `accept_ownership`, `allow_root_grantor`, `disallow_root_grantor`, `is_root_grantor_allowed`, `disable_capability`, `enable_capability`, `owner_revoke_delegation`, `void_verdict`, `set_min_severity`.
ProtectedProtocol: `transfer_ownership`, `accept_ownership`, `add_accepted_scope`, `remove_accepted_scope`, `add_trusted_grantor`, `remove_trusted_grantor`, `is_scope_accepted`, `unpause_by_owner`, `cancel_stale_proposal`, `propose_slash_recipient`, `apply_slash_recipient`.
ContinuityCore: `transfer_ownership`, `accept_ownership`, `set_allowed_hosts`, `grant_derive`.

### Other changes

- `resolve_conflict` no longer touches storage inside the non-deterministic block (K2).
- Prompts fence every untrusted text with markers the text cannot close, and sanitize it.
- Stored reasons of evidence checks are reduced to a short plain subset.
- Console: 118 methods (all public methods of the three contracts), SDK pinned to genlayer-js 1.1.8, keys stay in the browser tab unless "Remember keys on this device" is ticked.
- Tests: 144 scenario steps in 7 phases, an offline unit suite and an offline scenario runner.

### Not changed on purpose

Behavior of the guardian fast path, bonds, slashing amounts (0.1 GEN), the critical path design, severity snapshots (10 minutes), the AI decision format, and the capability names.
