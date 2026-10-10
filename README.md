# Continuity Core

Trust in on-chain state expires. Continuity Core makes that explicit for two things that most
systems trust forever: **facts** ("the supplier is licensed") and **LLM judges** ("the AI checker
approves this payment"). Both are put on a lease. When a lease lapses, everything built on it is
blocked until the basis is re-checked by GenLayer validators.

One Intelligent Contract, one shared lease state machine, one dependency graph.

```
EVIDENCE lease  ----\
                     >---  ASSERTION  ---  ACTION   (executes only if every ancestor lease is live)
JUDGE lease     ----/
```

## The problem

* A fact verified once is treated as true forever. Licenses are revoked, pages change, sources
  disappear.
* An LLM judge is treated as a constant. In practice its behavior is defined by a prompt that can be
  swapped, and by models that drift.
* Deterministic code can check `block.timestamp > expires_at`. It cannot decide that "the new version
  of the document still supports the old claim", or that "this new prompt still behaves like the old
  one". Those are semantic questions.

## How it works

### Two branches, one lifecycle

| | EVIDENCE branch | JUDGE branch |
|---|---|---|
| What is leased | A claim about a web source | The active prompt version of an LLM adjudicator |
| Entering the lease | `verify_evidence`: validators compare claim to source | `activate_version`: every golden case passed, results fresh |
| Renewing | `revalidate`: `SAME` / `CHANGED` / `CONTRADICTED` | `run_case` for every golden once per cycle, then `finalize_recert` |
| Failure | `CHANGED` or no decision: `EXPIRED`; `CONTRADICTED`: `INVALIDATED` | Any golden fails: `EXPIRED` with verdict `DRIFTED` |
| Consensus compares | Verdict bucket | Label from a closed enum |

Lease states: `UNVERIFIED`, `VERIFIED`, `ACTIVE`, `EXPIRING`, `EXPIRED`, `REVALIDATION_PENDING`,
`REVALIDATED`, `INVALIDATED`. Time moves a lease to `EXPIRING` and `EXPIRED`; revalidation is
fail-closed (`REVALIDATION_PENDING` is not a live state).

### Dependency graph

`derive_assertion` and `derive_action` create nodes over one or more leases. A derived node is
trusted only if all ancestors are live. The graph is a DAG by construction (parents must already
exist and cannot be edited), with at most 8 parents per node and depth 16.

**Enforcement is pull-based.** `execute_action` recomputes trust from the leases and the current
time. The stored state of derived nodes is only a cache that anyone can refresh with
`refresh_node`. No write path iterates over dependents, so dependents can never block the lease they
depend on.

### The regression gate (judge branch)

An owner registers a judge slot with a closed label enum and appends **golden cases** (input and
expected label). Goldens are append-only: they can be added, never edited or removed. A new prompt
version can only become active if validators executed it on every golden and every result is `PASS`
and recent. The gate can only block. It never grants authority the owner did not already have.

Anti-gaming rules: at least 3 goldens, a golden input may not appear verbatim in a prompt, one run
per case per recertification cycle, 300 second cooldown between attempts.

### Why GenLayer

The probes are semantic and need independent execution: comparing a claim with a changing page, and
running a prompt on a case. A hash diff can only say "changed", and a single trusted oracle puts all
trust in its operator. Validators with different models re-execute each probe and only a majority
verdict is accepted. Everything else (state machine, graph, gate, freshness) is deterministic code.

## Verified behavior

* 47 direct-mode tests (mocked web and LLM): `tests/direct/test_continuity_core.py`.
* A mutation check broke twelve protections one at a time (enforcement off, activation ignoring
  failed or stale cases, repeated runs in a cycle, `reclaim` with dependents, both validators
  accepting everything, `max_age`, drift undetected, vacuous suites, overfit check, and others).
  The suite caught all twelve.
* Live GenLayer Studio run with a heterogeneous validator set: see `proof.json` for 60 transaction
  hashes and the observations from read calls. Covered live: lease expiry and revalidation (`SAME`),
  source change to `CONTRADICTED`, judge activation and recertification, stale-result guard,
  regressed prompt blocked (`CASE_FAILED`), judge drift (`DRIFTED`), replacement by a good version
  (`SUPERSEDED`), action blocked by either lapsed lease and unblocked after revalidation, `reclaim`
  refused with dependents.
* Stability sample on a second judge (JD-6): four clear-cut cases, one of them a prompt-injection
  input. All four were accepted in the first consensus round with 12 visible `Agree` votes and no
  visible `Disagree`. Studio lists only validators that finished before quorum, so these are lower
  bounds on participation. A paraphrased evidence claim, by contrast, needed up to three rounds.

## Known limitations

Read these before relying on the contract. More detail in `SECURITY.md`.

1. The source is the trust root. The contract establishes "source S says C at time T", not that C is
   true.
2. Edges of the graph are declared by the node owner. The contract does not verify that an assertion
   really follows from its parents.
3. Goldens are owner-authored. A prompt can pass every golden and still misbehave elsewhere. A larger
   suite lowers the risk, it does not remove it.
4. The gate is only as strong as the validator majority. In the live run a deliberately harmful
   prompt was followed by three of four responding validators; one disagreed.
5. LLM variance costs liveness. A paraphrased claim needed three consensus rounds once and one round
   another time; clear cases were accepted in the first round.
6. `EXECUTED` is irreversible. There is no dispute or hold window.
7. Prompt injection from source text is mitigated by prompt instructions only.
8. The live sample is small (two judges with up to four goldens each, a few dozen consensus runs). The `CHANGED`
   verdict, dishonest leaders and dishonest validators are covered by mocks only.
9. The gate observes behavior on goldens, not the intent of a prompt. A prompt that tells the model to
   follow any instructions in the request still passed the prompt-injection golden, because the
   validating models resisted the injection on their own. Only what goldens exercise is guarded.

## Quick start

### Deploy

The first two lines of the contract are the runner header and must stay exactly as they are:

```
# v0.3.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
```

The contract failed to load in Studio ("invalid_contract") until the header matched this form. The
exact trigger was not isolated. Paste `contracts/continuity_core.py` into GenLayer Studio and deploy
with no constructor arguments.

### Walkthrough

```
register_evidence(claim, source_url, ttl_seconds)      -> EV-n
verify_evidence(EV-n)                                  -> ACTIVE

register_judge(description, ["ALLOW","DENY"], ttl)     -> JD-n
add_golden(JD-n, input_text, expected_label)           (at least 3)
propose_version(JD-n, "... {input}")                   -> version number
run_case(JD-n, version, case_idx)                      (every case, then within one hour:)
activate_version(JD-n, version)

derive_action(description, [EV-n, JD-n], max_age_s)    -> AC-n
execute_action(AC-n)                                   reverts with ACTION_BLOCKED_BY:<lease> if any
                                                       ancestor lease has lapsed
```

After a lease expires: `request_revalidation`, then `revalidate` (evidence) or `run_case` for each
golden followed by `finalize_recert` (judge). Consumers that read a prompt must use
`get_active_prompt` and check `live`.

### Tests

```
pip install genlayer-test pytest
pytest tests/direct/test_continuity_core.py -q
```

Notes:

* Direct mode freezes `gl.message_raw["datetime"]` when the contract class is loaded, so the test
  helper `warp()` updates it as well. On a real network that field is the transaction time.
* Windows: `gltest` calls `os.unlink` on a temp file that is still open. Run
  `python scripts/patch_gltest_windows.py` once.
* If the SDK download returns 404, place `genvm-universal-v0.2.12.tar.xz` from the `genlayerlabs/genvm`
  releases into `~/.cache/gltest-direct/`.
* Direct mode does not build the contract schema. Redeploy in Studio after changing the contract.

## Repository layout

```
contracts/continuity_core.py        the Intelligent Contract
tests/direct/test_continuity_core.py direct-mode suite (47 cases)
scripts/patch_gltest_windows.py     Windows fix for gltest direct mode
proof.json                          live Studio transactions and observations
SECURITY.md                         trust assumptions and threat model
```
g README.md…]()
# Continuity-core
