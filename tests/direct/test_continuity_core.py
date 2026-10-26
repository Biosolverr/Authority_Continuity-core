"""Direct-mode proof suite for contracts/continuity_core.py (v0.4.1)

Claims covered (proof plan):
  P1 expiry blocks dependents WITHOUT poll (enforcement is live, cache is not authority)
  P2 dependents can never block transitions of the evidence they depend on
  P3 reclaim cannot rewrite a claim under existing dependents
  P4 all verdicts map to the expected lease states, fail-closed
  P5 judge versions activate only with a full, fresh PASS suite; gate only blocks
  P6 re-certification: one run per case per cycle, drift => EXPIRED
  P7 validator rejects a lying leader (evidence and judge probes)
  P8 platform: a node depending on evidence AND judge is blocked if EITHER lapses
v0.4 hardening:
  P9  F7  only the node owner (or a granted address) derives from a node, a node takes at most
          MAX_CHILDREN dependents
  P10 F8  URL filter, optional host allow list, oversized pages fail closed, stored reasons sanitized
  P11 F13 golden gate: four word overlap rejected, two distinct labels required
  P12 F14 request_revalidation, revalidate and run_case on an active version are owner only
  P13 F11 two step ownership transfer
  P14 F20 verify_evidence is owner only
"""
import calendar
import json
import sys
from datetime import datetime, timezone

import pytest

CONTRACT = "contracts/continuity_core.py"
T0 = calendar.timegm((2026, 10, 6, 10, 0, 0))

URL = "https://example.com/registry/123"
CLAIM = "Supplier A is certified for chemical transport."

VERIFY_PAT = r"(?s).*Decide whether the SOURCE TEXT supports.*"
REVAL_PAT = r"(?s).*re-checked against the CURRENT SOURCE TEXT.*"
WEB_PAT = r"example\.com"

GOLDENS = [
    ("GOLDEN_A pay 50 USD to known vendor", "ALLOW"),
    ("GOLDEN_B wire 90000 USD to unknown offshore account", "DENY"),
    ("GOLDEN_C refund 20 USD to original card", "ALLOW"),
]
PROMPT_V1 = "POLICYV1 You decide whether a payment request is within policy. Request: {input}"
PROMPT_V2 = "POLICYV2 Judge whether this payment request is within policy. Request: {input}"
OK_ANSWERS = {"GOLDEN_A": "ALLOW", "GOLDEN_B": "DENY", "GOLDEN_C": "ALLOW"}

MAX_CHILDREN = 64  # keep in sync with MAX_CHILDREN in continuity_core.py


# ------------------------------------------------------------------ helpers
def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def warp(vm, ts: int):
    """Move the simulated tx time.

    gltest's vm.warp() updates vm._datetime and patches datetime.now(), but the contract reads
    gl.message_raw["datetime"], which gltest freezes when the contract class is loaded (only
    sender/origin are refreshed). So we also update that cached field. On a real network this
    field IS the transaction time, so the contract code needs no change.
    """
    vm.warp(iso(ts))
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = iso(ts)


def mocks(vm, body="Supplier A holds a valid chemical transport certification.",
          status=200, verify="SUPPORTED", reval="SAME"):
    vm.clear_mocks()
    vm.mock_web(WEB_PAT, {"status": status, "body": body})
    vm.mock_llm(VERIFY_PAT, json.dumps({"verdict": verify, "reason": "t"}))
    vm.mock_llm(REVAL_PAT, json.dumps({"verdict": reval, "reason": "t"}))


def judge_mocks(vm, marker, answers):
    vm.clear_mocks()
    for key, label in answers.items():
        vm.mock_llm(rf"(?s).*{marker}.*{key}.*", json.dumps({"label": label}))


def make_evidence(core, vm, ttl=1000):
    mocks(vm)
    eid = core.register_evidence(CLAIM, URL, ttl)
    core.verify_evidence(eid)
    return eid


def make_judge(core, ttl=1000, goldens=GOLDENS):
    jid = core.register_judge("Payment policy adjudicator", ["ALLOW", "DENY"], ttl)
    for text, label in goldens:
        core.add_golden(jid, text, label)
    return jid


def activate_v1(core, vm, jid):
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    v = core.propose_version(jid, PROMPT_V1)
    for i in range(len(GOLDENS)):
        assert core.run_case(jid, v, i) == "PASS"
    core.activate_version(jid, v)
    return v


@pytest.fixture
def vm(direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    warp(direct_vm, T0)
    return direct_vm


@pytest.fixture
def core(vm, direct_deploy):
    return direct_deploy(CONTRACT)


# ================================================================== EVIDENCE branch
def test_verify_supported_becomes_active(core, vm):
    eid = make_evidence(core, vm)
    n = core.get_node(eid)
    assert n["stored_state"] == "ACTIVE" and n["expires_at"] == T0 + 1000
    assert n["last_verdict"] == "SUPPORTED"


def test_verify_evidence_is_owner_only(core, vm, direct_bob):  # F20
    mocks(vm)
    eid = core.register_evidence(CLAIM, URL, 1000)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.verify_evidence(eid)
    assert core.get_node(eid)["stored_state"] == "UNVERIFIED"  # the stranger changed nothing
    assert core.verify_evidence(eid) == "ACTIVE"


def test_verify_not_supported_stays_unverified(core, vm):
    mocks(vm, verify="NOT_SUPPORTED")
    eid = core.register_evidence(CLAIM, URL, 1000)
    assert core.verify_evidence(eid) == "UNVERIFIED"
    assert core.get_node(eid)["last_verdict"] == "NOT_SUPPORTED"


def test_time_transitions_and_poll(core, vm):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 900)
    assert core.get_state(eid) == "EXPIRING"
    assert core.get_node(eid)["stored_state"] == "ACTIVE"  # cache lags until poll
    assert core.poll(eid) == "EXPIRING"
    warp(vm, T0 + 1000)
    assert core.get_state(eid) == "EXPIRED"
    assert core.poll(eid) == "EXPIRED"


def test_bad_urls_and_ttl_rejected(core, vm):
    for bad in ["http://example.com/x", "https://localhost/x", "https://10.0.0.1/x",
                "https://user@example.com/x", "https://intranet.local/x", "https://nodots/x"]:
        with vm.expect_revert("BAD_SOURCE_URL"):
            core.register_evidence(CLAIM, bad, 1000)
    with vm.expect_revert("BAD_TTL"):
        core.register_evidence(CLAIM, URL, 10)


def test_url_filter_v04_extras(core, vm):  # P10 / F8
    for bad in ["https://example.com:8443/x",       # only port 443
                "https://169.254.169.254/x",        # numeric TLD
                "https://foo.nip.io/x",             # wildcard DNS
                "https://example.com./x",           # trailing dot
                "https://[::1]/x"]:                 # IPv6 literal
        with vm.expect_revert("BAD_SOURCE_URL"):
            core.register_evidence(CLAIM, bad, 1000)
    core.register_evidence(CLAIM, "https://example.com:443/x", 1000)  # explicit 443 is fine


def test_request_revalidation_is_owner_only(core, vm, direct_bob):  # P12 / F14
    eid = make_evidence(core, vm)
    warp(vm, T0 + 900)  # EXPIRING
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.request_revalidation(eid)
    assert core.request_revalidation(eid) == "REVALIDATION_PENDING"
    assert core.get_state(eid) == "REVALIDATION_PENDING"  # fail-closed: not live


def test_request_revalidation_rejected_while_active(core, vm):
    eid = make_evidence(core, vm)
    with vm.expect_revert("NOT_EXPIRING_OR_EXPIRED"):
        core.request_revalidation(eid)


def test_revalidate_same_renews(core, vm):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)  # owner only since v0.4
    mocks(vm, reval="SAME")
    assert core.revalidate(eid) == "REVALIDATED"
    n = core.get_node(eid)
    assert n["revalidation_count"] == 1 and n["expires_at"] == T0 + 2000
    assert n["effective_state"] == "REVALIDATED"


def test_revalidate_is_owner_only(core, vm, direct_bob):  # P12 / F14
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)
    mocks(vm, reval="SAME")
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.revalidate(eid)
    assert core.get_state(eid) == "REVALIDATION_PENDING"


@pytest.mark.parametrize("verdict,expected", [
    ("CHANGED", "EXPIRED"),
    ("INCONCLUSIVE", "EXPIRED"),
    ("CONTRADICTED", "INVALIDATED"),
])
def test_revalidate_non_same_is_fail_closed(core, vm, verdict, expected):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)
    mocks(vm, reval=verdict)
    assert core.revalidate(eid) == expected
    assert core.get_node(eid)["last_verdict"] == verdict


def test_revalidate_source_unavailable_is_fail_closed(core, vm):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)
    mocks(vm, status=404)
    assert core.revalidate(eid) == "EXPIRED"
    assert core.get_node(eid)["last_verdict"] == "SOURCE_UNAVAILABLE"


def test_revalidate_requires_pending(core, vm):
    eid = make_evidence(core, vm)
    with vm.expect_revert("NOT_REVALIDATION_PENDING"):
        core.revalidate(eid)


def test_cooldown_between_attempts(core, vm):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)
    mocks(vm, reval="INCONCLUSIVE")
    core.revalidate(eid)  # -> EXPIRED, last_attempt = now
    with vm.expect_revert("COOLDOWN"):
        core.request_revalidation(eid)
    warp(vm, T0 + 1301)
    assert core.request_revalidation(eid) == "REVALIDATION_PENDING"


def test_verify_retry_cooldown(core, vm):
    mocks(vm, verify="INCONCLUSIVE")
    eid = core.register_evidence(CLAIM, URL, 1000)
    core.verify_evidence(eid)
    with vm.expect_revert("COOLDOWN"):
        core.verify_evidence(eid)


def test_reclaim_forbidden_with_dependents_allowed_without(core, vm):
    e1 = make_evidence(core, vm)
    e2 = core.register_evidence(CLAIM, URL, 1000)
    core.derive_assertion("Supplier A may carry chemicals", [e1])
    core.revoke(e1)
    core.revoke(e2)
    with vm.expect_revert("HAS_DEPENDENTS_REGISTER_NEW_EVIDENCE"):
        core.reclaim(e1, "Supplier A is certified for all hazmat classes")
    core.reclaim(e2, "Supplier A is certified for class 3 liquids")
    assert core.get_node(e2)["stored_state"] == "UNVERIFIED"


def test_revoke_owner_only(core, vm, direct_bob):
    eid = make_evidence(core, vm)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.revoke(eid)
    core.revoke(eid)
    assert core.get_state(eid) == "INVALIDATED"
    with vm.expect_revert("ALREADY_INVALIDATED"):
        core.revoke(eid)


# ================================================================== F8: source handling
def test_host_allow_list(core, vm, direct_bob):  # P10 / F8
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.set_allowed_hosts("registry.example.org")
    with vm.expect_revert("BAD_HOST"):
        core.set_allowed_hosts("bad host!")
    core.set_allowed_hosts("registry.example.org")
    with vm.expect_revert("SOURCE_HOST_NOT_ALLOWED"):
        core.register_evidence(CLAIM, URL, 1000)
    core.register_evidence(CLAIM, "https://registry.example.org/x", 1000)
    core.register_evidence(CLAIM, "https://api.registry.example.org/x", 1000)  # subdomain
    with vm.expect_revert("SOURCE_HOST_NOT_ALLOWED"):
        core.register_evidence(CLAIM, "https://evilregistry.example.org/x", 1000)
    core.set_allowed_hosts("")  # empty means open again
    core.register_evidence(CLAIM, URL, 1000)


def test_oversized_page_fails_closed(core, vm):  # P10 / F8
    mocks(vm, body="x" * 13000)  # above MAX_SOURCE_CHARS, must not be cut and judged
    eid = core.register_evidence(CLAIM, URL, 1000)
    assert core.verify_evidence(eid) == "UNVERIFIED"
    assert core.get_node(eid)["last_verdict"] == "SOURCE_UNAVAILABLE"


def test_stored_reason_is_sanitized(core, vm):  # P10 / F8
    vm.clear_mocks()
    vm.mock_web(WEB_PAT, {"status": 200, "body": "Supplier A holds a valid chemical transport certification."})
    vm.mock_llm(VERIFY_PAT, json.dumps({"verdict": "SUPPORTED", "reason": "see https://evil.com/x now <b>ok</b>"}))
    eid = core.register_evidence(CLAIM, URL, 1000)
    core.verify_evidence(eid)
    reason = core.get_node(eid)["last_reason"]
    assert "http" not in reason.lower()
    assert "/" not in reason and "<" not in reason and ">" not in reason
    assert len(reason) <= 120


# ================================================================== GRAPH / enforcement
def test_action_executes_when_evidence_live(core, vm):
    eid = make_evidence(core, vm)
    aid = core.derive_action("Release funds", [eid], 0)
    assert core.can_execute(aid) is True
    assert core.execute_action(aid) == "EXECUTED"
    with vm.expect_revert("ALREADY_EXECUTED"):
        core.execute_action(aid)


def test_expiry_blocks_action_without_poll(core, vm):  # P1
    eid = make_evidence(core, vm)
    asid = core.derive_assertion("Entity may operate", [eid])
    aid = core.derive_action("Release funds", [asid], 0)
    warp(vm, T0 + 1000)  # nobody polled
    assert core.get_node(eid)["stored_state"] == "ACTIVE"
    assert core.can_execute(aid) is False
    assert core.get_blocker(aid) == eid
    with vm.expect_revert(f"ACTION_BLOCKED_BY:{eid}"):
        core.execute_action(aid)


def test_refresh_node_persists_cache(core, vm):
    eid = make_evidence(core, vm)
    asid = core.derive_assertion("Entity may operate", [eid])
    warp(vm, T0 + 1000)
    assert core.get_state(asid) == "SUSPENDED"
    assert core.get_node(asid)["stored_state"] == "VALID"  # stale cache, never authority
    assert core.refresh_node(asid) == "SUSPENDED"
    assert core.get_node(asid)["blocker"] == eid


def test_two_parents_either_lapse_suspends(core, vm):
    e1 = make_evidence(core, vm, ttl=1000)
    mocks(vm)
    e2 = core.register_evidence(CLAIM, URL, 5000)
    core.verify_evidence(e2)
    asid = core.derive_assertion("Both hold", [e1, e2])
    assert core.get_state(asid) == "VALID"
    warp(vm, T0 + 1000)
    assert core.get_state(asid) == "SUSPENDED" and core.get_blocker(asid) == e1


def test_dependents_cannot_block_transitions(core, vm):  # P2
    eid = make_evidence(core, vm)
    for i in range(MAX_CHILDREN):  # v0.4: a node takes at most MAX_CHILDREN dependents
        core.derive_assertion(f"dependent {i}", [eid])
    warp(vm, T0 + 1000)
    assert core.poll(eid) == "EXPIRED"
    core.request_revalidation(eid)
    mocks(vm, reval="SAME")
    assert core.revalidate(eid) == "REVALIDATED"


def test_dependents_are_capped(core, vm):  # P9 / F7
    eid = make_evidence(core, vm)
    for i in range(MAX_CHILDREN):
        core.derive_assertion(f"dependent {i}", [eid])
    with vm.expect_revert("TOO_MANY_DEPENDENTS"):
        core.derive_assertion("one too many", [eid])


def test_derive_requires_owner_or_grant(core, vm, direct_bob):  # P9 / F7
    eid = make_evidence(core, vm)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_ALLOWED_TO_DERIVE"):
            core.derive_assertion("stranger builds on my evidence", [eid])
        with vm.expect_revert("NOT_OWNER"):
            core.grant_derive(eid, direct_bob)  # only the node owner can grant
    core.grant_derive(eid, direct_bob)
    with vm.prank(direct_bob):
        asid = core.derive_assertion("granted builder", [eid])
    assert core.get_node(asid)["owner"] != core.get_node(eid)["owner"]


def test_max_age_requires_fresh_evidence(core, vm):
    eid = make_evidence(core, vm, ttl=1000)
    aid = core.derive_action("Irreversible release", [eid], 100)
    assert core.can_execute(aid) is True
    warp(vm, T0 + 200)  # evidence still live, but older than max_age
    assert core.get_state(eid) in ("ACTIVE", "EXPIRING")
    assert core.can_execute(aid) is False
    with vm.expect_revert("ACTION_BLOCKED_BY"):
        core.execute_action(aid)


def test_only_owner_executes(core, vm, direct_bob):
    eid = make_evidence(core, vm)
    aid = core.derive_action("Release funds", [eid], 0)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.execute_action(aid)


def test_graph_limits(core, vm):
    eid = make_evidence(core, vm)
    aid = core.derive_action("leaf", [eid], 0)
    with vm.expect_revert("PARENT_CANNOT_BE_ACTION"):
        core.derive_assertion("child of action", [aid])
    with vm.expect_revert("DUPLICATE_PARENT"):
        core.derive_assertion("dup", [eid, eid])
    nine = [core.register_evidence(CLAIM, URL, 1000) for _ in range(9)]
    with vm.expect_revert("BAD_PARENT_COUNT"):
        core.derive_assertion("too many parents", nine)
    cur = eid
    for _ in range(16):
        cur = core.derive_assertion("chain", [cur])
    with vm.expect_revert("GRAPH_TOO_DEEP"):
        core.derive_assertion("chain", [cur])


# ================================================================== JUDGE branch
def test_register_judge_validation(core, vm):
    with vm.expect_revert("BAD_LABELS"):
        core.register_judge("d", ["ONLY_ONE"], 1000)
    with vm.expect_revert("BAD_LABEL_FORMAT"):
        core.register_judge("d", ["allow", "DENY"], 1000)
    with vm.expect_revert("BAD_TTL"):
        core.register_judge("d", ["ALLOW", "DENY"], 5)


def test_golden_rules(core, vm, direct_bob):
    jid = core.register_judge("d", ["ALLOW", "DENY"], 1000)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.add_golden(jid, "GOLDEN_X some input text", "ALLOW")
    with vm.expect_revert("LABEL_NOT_IN_ENUM"):
        core.add_golden(jid, "GOLDEN_X some input text", "MAYBE")
    with vm.expect_revert("BAD_GOLDEN_INPUT_LENGTH"):
        core.add_golden(jid, "short", "ALLOW")
    for i in range(8):
        core.add_golden(jid, f"GOLDEN_{i} sample input text", "ALLOW")
    with vm.expect_revert("TOO_MANY_GOLDENS"):
        core.add_golden(jid, "GOLDEN_9 sample input text", "ALLOW")


def test_propose_preconditions(core, vm):
    jid = core.register_judge("d", ["ALLOW", "DENY"], 1000)
    core.add_golden(jid, *GOLDENS[0])
    core.add_golden(jid, *GOLDENS[1])
    with vm.expect_revert("NOT_ENOUGH_GOLDENS"):  # no vacuous suites
        core.propose_version(jid, PROMPT_V1)
    core.add_golden(jid, *GOLDENS[2])
    with vm.expect_revert("PROMPT_MISSING_INPUT_PLACEHOLDER"):
        core.propose_version(jid, "POLICYV1 judge this request without a placeholder")
    with vm.expect_revert("OVERFIT_GOLDEN_IN_PROMPT"):
        core.propose_version(jid, PROMPT_V2 + " Example: " + GOLDENS[0][0])


def test_golden_four_word_overlap_rejected(core, vm):  # P11 / F13
    jid = make_judge(core)
    # not the whole golden input, only a run of four words from GOLDEN_A
    with vm.expect_revert("OVERFIT_GOLDEN_IN_PROMPT"):
        core.propose_version(jid, "POLICYV3 Judge requests like pay 50 USD to anyone. Request: {input}")


def test_judge_needs_two_distinct_labels(core, vm):  # P11 / F13
    one_label = [
        ("GOLDEN_A pay 50 USD to known vendor", "ALLOW"),
        ("GOLDEN_C refund 20 USD to original card", "ALLOW"),
        ("GOLDEN_D pay 10 USD for office supplies", "ALLOW"),
    ]
    jid = make_judge(core, goldens=one_label)
    with vm.expect_revert("NEED_TWO_LABELS"):
        core.propose_version(jid, PROMPT_V1)


def test_activate_requires_all_cases_run(core, vm):  # P5
    jid = make_judge(core)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    v = core.propose_version(jid, PROMPT_V1)
    with vm.expect_revert("CASE_NOT_RUN:0"):
        core.activate_version(jid, v)
    core.run_case(jid, v, 0)
    core.run_case(jid, v, 1)
    with vm.expect_revert("CASE_NOT_RUN:2"):
        core.activate_version(jid, v)


def test_activate_happy_path(core, vm):
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    n = core.get_node(jid)
    assert n["stored_state"] == "ACTIVE" and n["active_version"] == v
    ap = core.get_active_prompt(jid)
    assert ap["live"] is True and ap["prompt"] == PROMPT_V1


def test_failing_version_cannot_activate_and_changes_nothing(core, vm):  # P5 gate only blocks
    jid = make_judge(core)
    activate_v1(core, vm, jid)
    before = core.get_node(jid)
    bad = dict(OK_ANSWERS, GOLDEN_B="ALLOW")  # semantic regression on the risky case
    judge_mocks(vm, "POLICYV2", bad)
    v2 = core.propose_version(jid, PROMPT_V2)
    assert core.run_case(jid, v2, 0) == "PASS"
    assert core.run_case(jid, v2, 1) == "FAIL"
    assert core.run_case(jid, v2, 2) == "PASS"
    with vm.expect_revert("CASE_FAILED:1"):
        core.activate_version(jid, v2)
    after = core.get_node(jid)
    assert after["active_version"] == before["active_version"] == 1
    assert after["stored_state"] == before["stored_state"]
    assert core.get_active_prompt(jid)["prompt"] == PROMPT_V1


def test_good_version_supersedes(core, vm):
    jid = make_judge(core)
    activate_v1(core, vm, jid)
    judge_mocks(vm, "POLICYV2", OK_ANSWERS)
    v2 = core.propose_version(jid, PROMPT_V2)
    for i in range(3):
        core.run_case(jid, v2, i)
    core.activate_version(jid, v2)
    assert core.get_version(jid, 1)["state"] == "SUPERSEDED"
    assert core.get_version(jid, 2)["state"] == "ACTIVE"
    assert core.get_node(jid)["active_version"] == 2


def test_activation_requires_fresh_results(core, vm):
    jid = make_judge(core)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    v = core.propose_version(jid, PROMPT_V1)
    for i in range(3):
        core.run_case(jid, v, i)
    warp(vm, T0 + 3601)
    with vm.expect_revert("CASE_RESULT_STALE"):
        core.activate_version(jid, v)


def test_run_case_rules_for_proposed(core, vm, direct_bob):
    jid = make_judge(core)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    v = core.propose_version(jid, PROMPT_V1)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.run_case(jid, v, 0)
    core.run_case(jid, v, 0)
    with vm.expect_revert("COOLDOWN"):
        core.run_case(jid, v, 0)
    with vm.expect_revert("CASE_NOT_FOUND"):
        core.run_case(jid, v, 3)


def test_run_case_on_active_requires_recertification(core, vm):
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    with vm.expect_revert("NOT_IN_RECERTIFICATION"):
        core.run_case(jid, v, 0)


def test_recert_all_pass_renews(core, vm, direct_bob):  # P6 / P12
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    warp(vm, T0 + 1000)
    assert core.get_state(jid) == "EXPIRED"
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    with vm.prank(direct_bob):  # v0.4: running cases of the active version is owner only
        with vm.expect_revert("NOT_OWNER"):
            core.run_case(jid, v, 0)
    for i in range(3):
        assert core.run_case(jid, v, i) == "PASS"
    with vm.prank(direct_bob):  # finalizing stays permissionless
        assert core.finalize_recert(jid) == "REVALIDATED"
    n = core.get_node(jid)
    assert n["last_verdict"] == "SAME" and n["expires_at"] == T0 + 2000


def test_recert_drift_expires(core, vm):  # P6
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    warp(vm, T0 + 1000)
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", dict(OK_ANSWERS, GOLDEN_B="ALLOW"))  # model drifted
    for i in range(3):
        core.run_case(jid, v, i)
    assert core.finalize_recert(jid) == "EXPIRED"
    assert core.get_node(jid)["last_verdict"] == "DRIFTED"
    assert core.get_active_prompt(jid)["live"] is False


def test_recert_one_run_per_case_per_cycle(core, vm):  # no re-rolling the dice
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    warp(vm, T0 + 1000)
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    core.run_case(jid, v, 0)
    with vm.expect_revert("ALREADY_RUN_THIS_CYCLE"):
        core.run_case(jid, v, 0)


def test_recert_incomplete_cannot_finalize(core, vm):
    jid = make_judge(core)
    v = activate_v1(core, vm, jid)
    warp(vm, T0 + 1000)
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    core.run_case(jid, v, 0)
    with vm.expect_revert("RECERT_INCOMPLETE:1"):
        core.finalize_recert(jid)


def test_unactivated_judge_cannot_request_revalidation(core, vm):
    jid = make_judge(core)
    warp(vm, T0 + 2000)  # never activated -> stays UNVERIFIED, not EXPIRED
    with vm.expect_revert("NOT_EXPIRING_OR_EXPIRED"):
        core.request_revalidation(jid)


# ================================================================== PLATFORM (both branches)
def test_action_blocked_when_judge_lapses_even_if_evidence_live(core, vm):  # P8
    mocks(vm)
    eid = core.register_evidence(CLAIM, URL, 5000)
    core.verify_evidence(eid)
    jid = make_judge(core, ttl=1000)
    v = activate_v1(core, vm, jid)
    aid = core.derive_action("Execute payment", [eid, jid], 0)
    assert core.can_execute(aid) is True
    warp(vm, T0 + 1000)
    assert core.get_state(eid) in ("ACTIVE", "EXPIRING")
    assert core.can_execute(aid) is False and core.get_blocker(aid) == jid
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    for i in range(3):
        core.run_case(jid, v, i)
    core.finalize_recert(jid)
    assert core.can_execute(aid) is True
    assert core.execute_action(aid) == "EXECUTED"


def test_action_blocked_when_judge_drifts(core, vm):  # P8
    mocks(vm)
    eid = core.register_evidence(CLAIM, URL, 5000)
    core.verify_evidence(eid)
    jid = make_judge(core, ttl=1000)
    v = activate_v1(core, vm, jid)
    aid = core.derive_action("Execute payment", [eid, jid], 0)
    warp(vm, T0 + 1000)
    core.request_revalidation(jid)
    judge_mocks(vm, "POLICYV1", dict(OK_ANSWERS, GOLDEN_A="DENY"))
    for i in range(3):
        core.run_case(jid, v, i)
    core.finalize_recert(jid)
    with vm.expect_revert(f"ACTION_BLOCKED_BY:{jid}"):
        core.execute_action(aid)


def test_action_blocked_when_evidence_lapses_even_if_judge_live(core, vm):  # P8
    mocks(vm)
    eid = core.register_evidence(CLAIM, URL, 500)
    core.verify_evidence(eid)
    jid = make_judge(core, ttl=5000)
    activate_v1(core, vm, jid)
    aid = core.derive_action("Execute payment", [eid, jid], 0)
    warp(vm, T0 + 500)
    assert core.get_blocker(aid) == eid


# ================================================================== OWNERSHIP (P13 / F11)
def test_two_step_ownership_transfer(core, vm, direct_alice, direct_bob):
    core.transfer_ownership(direct_bob)
    with vm.expect_revert("NOT_PENDING_OWNER"):  # alice is not the pending owner
        core.accept_ownership()
    core.set_allowed_hosts("example.com")  # until accepted, alice is still the owner
    with vm.prank(direct_bob):
        core.accept_ownership()
        core.set_allowed_hosts("example.org")
    with vm.expect_revert("NOT_OWNER"):
        core.set_allowed_hosts("example.com")


# ================================================================== CONSENSUS (P7)
def test_validator_rejects_lying_leader_on_verify(core, vm):
    mocks(vm, verify="SUPPORTED")
    eid = core.register_evidence(CLAIM, URL, 1000)
    core.verify_evidence(eid)  # leader ran with SUPPORTED
    mocks(vm, verify="NOT_SUPPORTED")  # honest validator sees something else
    assert vm.run_validator() is False


def test_validator_accepts_honest_leader_on_verify(core, vm):
    mocks(vm, verify="SUPPORTED")
    eid = core.register_evidence(CLAIM, URL, 1000)
    core.verify_evidence(eid)
    mocks(vm, verify="SUPPORTED")
    assert vm.run_validator() is True


def test_validator_treats_no_decision_outcomes_as_equal(core, vm):
    mocks(vm, verify="INCONCLUSIVE")
    eid = core.register_evidence(CLAIM, URL, 1000)
    core.verify_evidence(eid)  # leader: INCONCLUSIVE
    mocks(vm, status=404)  # validator: SOURCE_UNAVAILABLE -> same bucket
    assert vm.run_validator() is True


def test_validator_rejects_lying_leader_on_revalidate(core, vm):
    eid = make_evidence(core, vm)
    warp(vm, T0 + 1000)
    core.request_revalidation(eid)
    mocks(vm, reval="SAME")
    core.revalidate(eid)  # leader says SAME
    mocks(vm, reval="CONTRADICTED")
    assert vm.run_validator() is False


def test_validator_rejects_wrong_label_on_judge_case(core, vm):
    jid = make_judge(core)
    judge_mocks(vm, "POLICYV1", OK_ANSWERS)
    v = core.propose_version(jid, PROMPT_V1)
    core.run_case(jid, v, 1)  # leader: DENY (correct)
    judge_mocks(vm, "POLICYV1", dict(OK_ANSWERS, GOLDEN_B="ALLOW"))
    assert vm.run_validator() is False
