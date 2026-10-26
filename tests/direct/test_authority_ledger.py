"""Direct-mode suite for contracts/authority_ledger.py (v0.5.1)

Scope: everything the Ledger does on its own. Calls to the other two contracts are NOT routed in
gltest direct mode, so these paths are covered elsewhere (offline stand-in and the Studio scenarios):
  adjudicate / adjudicate_action / appeal_* up to the verdict (the severity read needs the Protocol),
  check_authority on an IN_SCOPE verdict, gates (need ContinuityCore).
What is checked here that way: the guards that run BEFORE such a call. A call to a contract that
is not there does not fail like on a real network in direct mode (it returns nothing), so the
"clean error on a failing severity read" and "continuity address is probed" paths are left to Studio.

Claims covered:
  L1  capability registry: validation, only raise assurance and min severity, kill switch
  L2  root grantors: only the owner or an allowed grantor creates root delegations (F1)
  L3  redelegation: same intent, depth, window, limits, revocation (F2, F10)
  L4  limits and approvals gate requests; cancel and expire refund a slot (F14)
  L5  request guards, hash binding, TTL
  L6  adjudication guards that run before the severity read, hash binding, text limits (F15)
  L7  conflicts: same root only, flags both ways, LLM judgment, cooldown (F4, K2)
  L8  check_authority fails closed
  L9  two step ownership (F11)
"""
import calendar
import hashlib
import json
import sys
from datetime import datetime, timezone

import pytest

CONTRACT = "contracts/authority_ledger.py"
T0 = calendar.timegm((2026, 10, 6, 10, 0, 0))

CAP = "PAUSE_PROTOCOL"
SCOPE = "protocol:main"
INTENT = "Pause the protocol only during a confirmed exploit"
JUST = "Exploit confirmed on block 123"
CONFLICT_PAT = r"(?s).*Два делегирования.*"


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hexof(addr) -> str:
    """Hex form the contract stores for an address (the fixtures are raw bytes in direct mode)."""
    from genlayer.py.types import Address
    return Address(bytes(addr)).as_hex if isinstance(addr, (bytes, bytearray)) else addr.as_hex


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def warp(vm, ts: int):
    """Move the simulated tx time (see the note in test_continuity_core.py)."""
    vm.warp(iso(ts))
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = iso(ts)


@pytest.fixture
def vm(direct_vm, direct_alice):
    direct_vm.sender = direct_alice  # alice is the owner
    warp(direct_vm, T0)
    return direct_vm


@pytest.fixture
def core(vm, direct_deploy):
    return direct_deploy(CONTRACT)


def deleg(core, delegate, cap=CAP, scope=SCOPE, frm=T0 - 100, until=T0 + 10000, depth=2,
          intent=INTENT, revocable=True):
    return core.create_delegation(delegate, cap, scope, frm, until, depth, sha(intent), revocable)


def request(core, vm, who, did, ttl=600, cap=CAP, scope=SCOPE, intent=INTENT, just=JUST):
    with vm.prank(who):
        return core.create_request(did, cap, scope, sha(intent), sha(just), ttl)


# ================================================================== L1 capability registry
def test_builtin_capabilities(core):
    caps = core.list_capabilities()
    assert set(caps) == {"PAUSE_PROTOCOL", "UNPAUSE_PROTOCOL", "RATIFY_GUARDIAN_PAUSE", "CHANGE_GUARDIAN_THRESHOLD"}
    c = core.get_capability("CHANGE_GUARDIAN_THRESHOLD")
    assert c["assurance_level"] == 2 and c["builtin"] is True and c["disabled"] is False
    assert core.get_capability(CAP)["assurance_level"] == 1


def test_get_unknown_capability(core, vm):
    with vm.expect_revert("NOT_FOUND"):
        core.get_capability("NOPE")


def test_register_capability(core, vm, direct_bob):
    core.register_capability("MY_CAP", "my capability", 5)
    c = core.get_capability("MY_CAP")
    assert c["min_severity"] == 5 and c["assurance_level"] == 1 and c["builtin"] is False
    core.register_capability_with_assurance("MY_CAP_2", "routine", 0, 0)
    assert core.get_capability("MY_CAP_2")["assurance_level"] == 0
    with vm.expect_revert("ALREADY_REGISTERED"):
        core.register_capability("MY_CAP", "again", 0)
    for bad in ["", "lower_case", "HAS SPACE", "X" * 65]:
        with vm.expect_revert("BAD_CAPABILITY_NAME"):
            core.register_capability(bad, "d", 0)
    with vm.expect_revert("DESCRIPTION_TOO_LONG"):
        core.register_capability("LONG_DESC", "x" * 281, 0)
    with vm.expect_revert("BAD_MIN_SEVERITY"):
        core.register_capability("NEG_SEV", "d", -1)
    with vm.expect_revert("BAD_ASSURANCE_LEVEL"):
        core.register_capability_with_assurance("BAD_LVL", "d", 0, 3)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.register_capability("BOB_CAP", "d", 0)


def test_assurance_and_min_severity_only_increase(core, vm):  # L1 / F14
    with vm.expect_revert("ASSURANCE_CAN_ONLY_INCREASE"):
        core.set_capability_assurance(CAP, 0)
    with vm.expect_revert("BAD_ASSURANCE_LEVEL"):
        core.set_capability_assurance(CAP, 3)
    with vm.expect_revert("NOT_FOUND"):
        core.set_capability_assurance("NOPE", 2)
    core.set_capability_assurance(CAP, 2)
    assert core.get_capability(CAP)["assurance_level"] == 2
    core.set_min_severity(CAP, 10)
    with vm.expect_revert("MIN_SEVERITY_CAN_ONLY_INCREASE"):
        core.set_min_severity(CAP, 5)
    with vm.expect_revert("BAD_MIN_SEVERITY"):
        core.set_min_severity(CAP, -1)
    assert core.get_capability(CAP)["min_severity"] == 10


def test_kill_switch_capability(core, vm, direct_bob):  # L1 / F1
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.disable_capability(CAP)
    core.disable_capability(CAP)
    with vm.expect_revert("CAPABILITY_DISABLED"):
        deleg(core, direct_bob)
    core.enable_capability(CAP)
    assert deleg(core, direct_bob)
    with vm.expect_revert("NOT_FOUND"):
        core.disable_capability("NOPE")


def test_disabled_capability_blocks_requests(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    core.disable_capability(CAP)
    with vm.prank(direct_bob):
        with vm.expect_revert("CAPABILITY_DISABLED"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)


# ================================================================== L2 root grantors
def test_only_allowed_root_grantors_delegate(core, vm, direct_alice, direct_bob, direct_charlie):
    with vm.prank(direct_bob):
        with vm.expect_revert("GRANTOR_NOT_ALLOWED"):
            deleg(core, direct_charlie)
    assert core.is_root_grantor_allowed(CAP, direct_bob) is False
    assert core.is_root_grantor_allowed(CAP, direct_alice) is True  # the owner is always allowed
    core.allow_root_grantor(CAP, direct_bob)
    core.allow_root_grantor(CAP, direct_bob)  # idempotent
    assert core.is_root_grantor_allowed(CAP, direct_bob) is True
    with vm.prank(direct_bob):
        did = deleg(core, direct_charlie)
        with vm.expect_revert("GRANTOR_NOT_ALLOWED"):  # allowed per capability only
            deleg(core, direct_charlie, cap="UNPAUSE_PROTOCOL")
    assert core.get_delegation(did)["root_grantor"] == hexof(direct_bob)
    core.disallow_root_grantor(CAP, direct_bob)
    assert core.is_root_grantor_allowed(CAP, direct_bob) is False


def test_root_grantor_admin_is_owner_only(core, vm, direct_bob):
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.allow_root_grantor(CAP, direct_bob)
        with vm.expect_revert("NOT_OWNER"):
            core.disallow_root_grantor(CAP, direct_bob)
    with vm.expect_revert("NOT_FOUND"):
        core.allow_root_grantor("NOPE", direct_bob)


def test_disallowed_grantor_delegations_stop_working(core, vm, direct_bob, direct_charlie):  # F1
    core.allow_root_grantor(CAP, direct_bob)
    with vm.prank(direct_bob):
        did = deleg(core, direct_charlie)
    request(core, vm, direct_charlie, did)  # works while allowed
    core.disallow_root_grantor(CAP, direct_bob)
    with vm.prank(direct_charlie):
        with vm.expect_revert("ROOT_GRANTOR_NOT_ALLOWED"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)


# ================================================================== delegations
def test_create_delegation_validation(core, vm, direct_bob):
    with vm.expect_revert("UNKNOWN_CAPABILITY"):
        core.create_delegation(direct_bob, "NOPE", SCOPE, T0, T0 + 100, 1, sha(INTENT), True)
    with vm.expect_revert("BAD_WINDOW"):
        core.create_delegation(direct_bob, CAP, SCOPE, T0 + 100, T0 + 100, 1, sha(INTENT), True)
    with vm.expect_revert("BAD_MAX_DEPTH"):
        deleg(core, direct_bob, depth=9)
    with vm.expect_revert("ALREADY_EXPIRED"):
        core.create_delegation(direct_bob, CAP, SCOPE, T0 - 200, T0 - 100, 1, sha(INTENT), True)


def test_delegation_record_and_indexes(core, direct_alice, direct_bob):
    did = deleg(core, direct_bob)
    d = core.get_delegation(did)
    assert d["capability"] == CAP and d["scope"] == SCOPE and d["depth"] == 0
    assert d["revoked"] is False and d["root_grantor"] == hexof(direct_alice)
    assert core.list_delegations_of_scope(SCOPE, 0, 10) == [did]
    assert core.list_delegations_of_delegate(direct_bob, 0, 10) == [did]
    assert core.get_stats()["delegations"] == 1


def test_pagination_rules(core, vm, direct_bob):
    for _ in range(3):
        deleg(core, direct_bob)
    assert len(core.list_delegations_of_scope(SCOPE, 0, 2)) == 2
    assert len(core.list_delegations_of_scope(SCOPE, 2, 50)) == 1
    with vm.expect_revert("BAD_PAGE"):
        core.list_delegations_of_scope(SCOPE, -1, 5)
    with vm.expect_revert("BAD_PAGE"):
        core.list_delegations_of_scope(SCOPE, 0, 0)


def test_is_delegation_valid(core, vm, direct_bob, direct_charlie):
    did = deleg(core, direct_bob)
    assert core.is_delegation_valid(did, direct_bob, CAP, SCOPE) is True
    assert core.is_delegation_valid(did, direct_charlie, CAP, SCOPE) is False
    assert core.is_delegation_valid(did, direct_bob, CAP, "other") is False
    assert core.is_delegation_valid("nope", direct_bob, CAP, SCOPE) is False
    core.disable_capability(CAP)  # L2: the view applies the same live checks as check_authority
    assert core.is_delegation_valid(did, direct_bob, CAP, SCOPE) is False
    core.enable_capability(CAP)
    assert core.is_delegation_valid(did, direct_bob, CAP, SCOPE) is True
    core.allow_root_grantor(CAP, direct_charlie)
    with vm.prank(direct_charlie):
        foreign = deleg(core, direct_bob)
    assert core.is_delegation_valid(foreign, direct_bob, CAP, SCOPE) is True
    core.disallow_root_grantor(CAP, direct_charlie)
    assert core.is_delegation_valid(foreign, direct_bob, CAP, SCOPE) is False
    warp(vm, T0 + 10001)
    assert core.is_delegation_valid(did, direct_bob, CAP, SCOPE) is False


def test_delegation_not_yet_active(core, vm, direct_bob):
    did = deleg(core, direct_bob, frm=T0 + 500)
    with vm.prank(direct_bob):
        with vm.expect_revert("DELEGATION_NOT_ACTIVE"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)


# ================================================================== L3 redelegation
def test_redelegate_keeps_intent_and_chain(core, vm, direct_bob, direct_charlie, direct_alice):  # F2
    did = deleg(core, direct_bob, depth=1)
    with vm.prank(direct_alice):
        with vm.expect_revert("NOT_DELEGATE"):
            core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)
    with vm.prank(direct_bob):
        with vm.expect_revert("CHILD_INTENT_MUST_MATCH_PARENT"):
            core.redelegate(did, direct_charlie, T0, T0 + 500, sha("a different intent"), True)
        child = core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)
    c = core.get_delegation(child)
    assert c["depth"] == 1 and c["parent_id"] == did and c["root_grantor"] == hexof(direct_alice)
    assert core.get_delegation(did)["children_count"] == 1
    with vm.prank(direct_charlie):  # depth 1 of max 1: no further redelegation
        with vm.expect_revert("MAX_DEPTH_EXCEEDED"):
            core.redelegate(child, direct_bob, T0, T0 + 100, sha(INTENT), True)


def test_redelegate_window_and_errors(core, vm, direct_bob, direct_charlie):
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("PARENT_NOT_FOUND"):
            core.redelegate("nope", direct_charlie, T0, T0 + 100, sha(INTENT), True)
        with vm.expect_revert("BAD_WINDOW"):
            core.redelegate(did, direct_charlie, T0 + 100, T0 + 100, sha(INTENT), True)
        with vm.expect_revert("EXCEEDS_PARENT_WINDOW"):
            core.redelegate(did, direct_charlie, T0, T0 + 20000, sha(INTENT), True)
        with vm.expect_revert("EXCEEDS_PARENT_WINDOW"):
            core.redelegate(did, direct_charlie, T0 - 500, T0 + 100, sha(INTENT), True)


def test_revoked_parent_cannot_redelegate_and_kills_children(core, vm, direct_bob, direct_charlie):
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        child = core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)
    core.revoke_delegation(did)
    with vm.prank(direct_bob):
        with vm.expect_revert("PARENT_REVOKED"):
            core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)
    with vm.prank(direct_charlie):  # the child dies with its parent
        with vm.expect_revert("DELEGATION_REVOKED"):
            core.create_request(child, CAP, SCOPE, sha(INTENT), sha(JUST), 600)


def test_children_cap(core, vm, direct_bob, direct_charlie):  # F10
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        for _ in range(16):
            core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)
        with vm.expect_revert("TOO_MANY_CHILDREN"):
            core.redelegate(did, direct_charlie, T0, T0 + 500, sha(INTENT), True)


def test_revoke_rules(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    fixed = deleg(core, direct_bob, revocable=False)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_GRANTOR"):
            core.revoke_delegation(did)
    with vm.expect_revert("NOT_REVOCABLE"):
        core.revoke_delegation(fixed)
    core.revoke_delegation(did)
    with vm.expect_revert("ALREADY_REVOKED"):
        core.revoke_delegation(did)
    with vm.expect_revert("NOT_FOUND"):
        core.revoke_delegation("nope")


def test_owner_can_revoke_anything(core, vm, direct_bob, direct_charlie):  # F1
    core.allow_root_grantor(CAP, direct_bob)
    with vm.prank(direct_bob):
        did = deleg(core, direct_charlie, revocable=False)
    core.owner_revoke_delegation(did)  # alice is the owner, not the grantor
    assert core.get_delegation(did)["revoked"] is True
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.owner_revoke_delegation(did)
    with vm.expect_revert("NOT_FOUND"):
        core.owner_revoke_delegation("nope")


# ================================================================== L4 limits and approvals
def test_request_limit_and_refund(core, vm, direct_bob, direct_charlie):  # F14
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_GRANTOR"):
            core.set_delegation_limit(did, 1)
    with vm.expect_revert("BAD_LIMIT"):
        core.set_delegation_limit(did, 0)
    core.set_delegation_limit(did, 1)
    with vm.expect_revert("LIMIT_ALREADY_SET"):
        core.set_delegation_limit(did, 2)
    r1 = request(core, vm, direct_bob, did)
    with vm.prank(direct_bob):
        with vm.expect_revert("REQUEST_LIMIT_REACHED"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)
        core.cancel_request(r1)  # a cancelled request gives its slot back
    request(core, vm, direct_bob, did)
    assert core.get_delegation(did)["requests_used"] == 1


def test_expired_request_refunds_slot(core, vm, direct_bob):  # F14
    did = deleg(core, direct_bob)
    core.set_delegation_limit(did, 1)
    r1 = request(core, vm, direct_bob, did, ttl=100)
    with vm.expect_revert("NOT_YET_EXPIRED"):
        core.expire_request(r1)
    warp(vm, T0 + 101)
    core.expire_request(r1)  # anyone may call
    assert core.get_request(r1)["status"] == "EXPIRED"
    with vm.expect_revert("TERMINAL_ALREADY"):
        core.expire_request(r1)
    assert core.get_delegation(did)["requests_used"] == 0


def test_limited_delegation_cannot_redelegate_and_vice_versa(core, vm, direct_bob, direct_charlie):
    lim = deleg(core, direct_bob)
    core.set_delegation_limit(lim, 3)
    with vm.prank(direct_bob):
        with vm.expect_revert("LIMITED_NOT_REDELEGABLE"):
            core.redelegate(lim, direct_charlie, T0, T0 + 100, sha(INTENT), True)
    used = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        core.redelegate(used, direct_charlie, T0, T0 + 100, sha(INTENT), True)
    with vm.expect_revert("DELEGATION_ALREADY_IN_USE"):
        core.set_delegation_limit(used, 1)


def test_approvals_gate_requests(core, vm, direct_alice, direct_bob, direct_charlie):
    did = deleg(core, direct_bob)
    pair = f"{hexof(direct_charlie)},{hexof(direct_alice)}"
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_GRANTOR"):
            core.require_approvals(did, pair, 2)
    with vm.expect_revert("BAD_APPROVERS"):
        core.require_approvals(did, "", 1)
    with vm.expect_revert("BAD_REQUIRED"):
        core.require_approvals(did, pair, 3)
    core.require_approvals(did, pair, 2)
    with vm.expect_revert("APPROVALS_ALREADY_SET"):
        core.require_approvals(did, pair, 1)
    with vm.prank(direct_bob):
        with vm.expect_revert("APPROVALS_PENDING"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)
        with vm.expect_revert("NOT_AN_APPROVER"):
            core.approve_delegation(did)
    core.approve_delegation(did)  # alice
    with vm.expect_revert("ALREADY_APPROVED"):
        core.approve_delegation(did)
    with vm.prank(direct_bob):
        with vm.expect_revert("APPROVALS_PENDING"):  # 1 of 2
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)
    with vm.prank(direct_charlie):
        core.approve_delegation(did)
    request(core, vm, direct_bob, did)  # 2 of 2


def test_approvals_cannot_change_after_use(core, vm, direct_bob, direct_alice):
    did = deleg(core, direct_bob)
    request(core, vm, direct_bob, did)
    with vm.expect_revert("DELEGATION_ALREADY_IN_USE"):
        core.require_approvals(did, hexof(direct_alice), 1)


# ================================================================== L5 requests
def test_create_request_record(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did, ttl=600)
    r = core.get_request(rid)
    assert r["status"] == "PENDING" and r["delegation_id"] == did and r["capability"] == CAP
    assert r["created_at"] == T0 and r["expires_at"] == T0 + 600 and r["gate_action_id"] == ""
    assert core.list_requests_of_delegation(did, 0, 10) == [rid]
    assert core.get_stats()["requests"] == 1
    with vm.prank(direct_bob):
        rid2 = core.create_request_with_params(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600, sha("exact action"))
    assert core.get_request(rid2)["action_params_hash"] == sha("exact action")


def test_create_request_guards(core, vm, direct_alice, direct_bob):
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("DELEGATION_NOT_FOUND"):
            core.create_request("nope", CAP, SCOPE, sha(INTENT), sha(JUST), 600)
        with vm.expect_revert("CAPABILITY_OR_SCOPE_MISMATCH"):
            core.create_request(did, CAP, "other:scope", sha(INTENT), sha(JUST), 600)
        with vm.expect_revert("CAPABILITY_OR_SCOPE_MISMATCH"):
            core.create_request(did, "UNPAUSE_PROTOCOL", SCOPE, sha(INTENT), sha(JUST), 600)
        with vm.expect_revert("INTENT_HASH_MISMATCH"):
            core.create_request(did, CAP, SCOPE, sha("not the intent"), sha(JUST), 600)
        with vm.expect_revert("BAD_TTL"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 0)
        with vm.expect_revert("BAD_TTL"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 7 * 86400 + 1)
    with vm.prank(direct_alice):  # not the delegate, even as the owner
        with vm.expect_revert("NOT_DELEGATE"):
            core.create_request(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600)


def test_cancel_rules(core, vm, direct_alice, direct_bob):
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did)
    with vm.expect_revert("NOT_REQUESTER"):  # alice
        core.cancel_request(rid)
    with vm.prank(direct_bob):
        core.cancel_request(rid)
        with vm.expect_revert("TERMINAL_ALREADY"):
            core.cancel_request(rid)
        with vm.expect_revert("NOT_FOUND"):
            core.cancel_request("nope")
    assert core.get_request(rid)["status"] == "CANCELLED"


# ================================================================== L6 adjudication guards
def test_adjudicate_guards_before_severity(core, vm, direct_alice, direct_bob, direct_charlie):  # F15
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did)
    with vm.prank(direct_charlie):
        with vm.expect_revert("NOT_REQUESTER_OR_OWNER"):
            core.adjudicate(rid, INTENT, JUST, 600)
    with vm.prank(direct_bob):
        with vm.expect_revert("REQUEST_NOT_FOUND"):
            core.adjudicate("nope", INTENT, JUST, 600)
        with vm.expect_revert("BAD_VALID_SECONDS"):
            core.adjudicate(rid, INTENT, JUST, 0)
        with vm.expect_revert("BAD_VALID_SECONDS"):
            core.adjudicate(rid, INTENT, JUST, 3601)
        with vm.expect_revert("INTENT_HASH_MISMATCH"):
            core.adjudicate(rid, "another intent text", JUST, 600)
        with vm.expect_revert("TEXT_TOO_LONG"):
            core.adjudicate(rid, INTENT, "x" * 1501, 600)
        with vm.expect_revert("JUSTIFICATION_HASH_MISMATCH"):
            core.adjudicate(rid, INTENT, "another justification", 600)
        with vm.expect_revert("NO_ACTION_BOUND"):
            core.adjudicate_action(rid, INTENT, "some action", JUST, 600)
    # the owner may adjudicate too, and then the severity read is what stops it (no Protocol set)
    with vm.expect_revert("PROTECTED_PROTOCOL_NOT_CONFIGURED"):
        core.adjudicate(rid, INTENT, JUST, 600)


def test_adjudicate_action_guards(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        rid = core.create_request_with_params(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600, sha("exact action"))
        with vm.expect_revert("ACTION_TEXT_REQUIRED"):
            core.adjudicate(rid, INTENT, JUST, 600)
        with vm.expect_revert("ACTION_HASH_MISMATCH"):
            core.adjudicate_action(rid, INTENT, "a different action", JUST, 600)
        with vm.expect_revert("TEXT_TOO_LONG"):
            core.adjudicate_action(rid, INTENT, "x" * 1501, JUST, 600)


def test_adjudicate_rejects_expired_request(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did, ttl=100)
    warp(vm, T0 + 101)
    with vm.prank(direct_bob):
        with vm.expect_revert("REQUEST_EXPIRED"):
            core.adjudicate(rid, INTENT, JUST, 600)


def test_adjudicate_rejects_revoked_chain(core, vm, direct_bob):
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did)
    core.revoke_delegation(did)
    with vm.prank(direct_bob):
        with vm.expect_revert("DELEGATION_REVOKED_SINCE_REQUEST"):
            core.adjudicate(rid, INTENT, JUST, 600)




def test_no_verdict_yet(core, vm):
    with vm.expect_revert("NOT_ADJUDICATED"):
        core.get_verdict("nope")
    with vm.expect_revert("NOT_ADJUDICATED"):
        core.void_verdict("nope")
    with vm.expect_revert("NOT_ADJUDICATED"):
        core.appeal_verdict("nope", INTENT, "new justification", 600)


# ================================================================== L8 check_authority
def test_check_authority_fails_closed(core, vm, direct_bob):
    res = core.check_authority("nope", direct_bob, CAP, "")
    assert res["authorized"] is False and res["reason"] == "REQUEST_NOT_FOUND" and res["scope"] == ""
    did = deleg(core, direct_bob)
    rid = request(core, vm, direct_bob, did)
    assert core.check_authority(rid, direct_bob, "UNPAUSE_PROTOCOL", "")["reason"] == "CAPABILITY_MISMATCH"
    assert core.check_authority(rid, direct_bob, CAP, sha("x"))["reason"] == "ACTION_PARAMS_MISMATCH"
    res = core.check_authority(rid, direct_bob, CAP, "")
    assert res["authorized"] is False and res["reason"] == "NOT_ADJUDICATED"
    assert res["assurance_level"] == -1


# ================================================================== L7 conflicts
INTENT_B = "Never pause the protocol while a migration is running"


def two_conflicting(core, direct_bob, direct_charlie):
    a = deleg(core, direct_bob)
    b = deleg(core, direct_charlie, intent=INTENT_B)
    return a, b


def test_conflicts_flagged_both_ways(core, direct_bob, direct_charlie):  # F4
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    assert core.get_potential_conflicts(b) == [a]
    assert core.get_potential_conflicts(a) == [b]


def test_conflict_scan_limits(core, vm, direct_bob, direct_charlie):  # F4
    a = deleg(core, direct_bob)
    other_scope = deleg(core, direct_charlie, scope="other:scope")
    same_delegate = deleg(core, direct_bob)  # same delegate and capability: not a conflict
    assert core.get_potential_conflicts(other_scope) == []
    assert core.get_potential_conflicts(same_delegate) == []
    late = deleg(core, direct_charlie, frm=T0 + 20000, until=T0 + 30000)  # windows do not overlap
    assert core.get_potential_conflicts(late) == []
    core.allow_root_grantor(CAP, direct_bob)
    with vm.prank(direct_bob):  # another root grantor: not compared with the owner's delegations
        foreign = deleg(core, direct_charlie)
    assert core.get_potential_conflicts(foreign) == []
    assert a not in core.get_potential_conflicts(foreign)


def test_resolve_conflict_guards(core, vm, direct_bob, direct_charlie):
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    lone = deleg(core, direct_bob, scope="lonely:scope")
    with vm.expect_revert("DELEGATION_NOT_FOUND"):
        core.resolve_conflict(a, "nope", INTENT, INTENT_B)
    with vm.expect_revert("NOT_A_FLAGGED_PAIR"):
        core.resolve_conflict(a, lone, INTENT, INTENT)
    with vm.expect_revert("INTENT_HASH_MISMATCH_A"):
        core.resolve_conflict(a, b, "wrong text", INTENT_B)
    with vm.expect_revert("INTENT_HASH_MISMATCH_B"):
        core.resolve_conflict(a, b, INTENT, "wrong text")
    with vm.expect_revert("TEXT_TOO_LONG"):
        core.resolve_conflict(a, b, "x" * 1501, INTENT_B)


def test_resolve_conflict_blocks_requests(core, vm, direct_bob, direct_charlie):  # K2
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    vm.mock_llm(CONFLICT_PAT, json.dumps({"decision": "CONFLICT"}))
    assert core.resolve_conflict(a, b, INTENT, INTENT_B) == "CONFLICT"
    assert core.get_conflict(b, a)["decision"] == "CONFLICT"  # order of the pair does not matter
    vm.clear_mocks()
    assert core.resolve_conflict(b, a, INTENT_B, INTENT) == "CONFLICT"  # final, no new LLM call
    with vm.prank(direct_bob):
        with vm.expect_revert(f"BLOCKED_BY_UNRESOLVED_CONFLICT_WITH:{b}"):
            core.create_request(a, CAP, SCOPE, sha(INTENT), sha(JUST), 600)
    core.revoke_delegation(b)  # a revoked counterpart no longer blocks
    request(core, vm, direct_bob, a)


def test_no_conflict_does_not_block(core, vm, direct_bob, direct_charlie):
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    vm.mock_llm(CONFLICT_PAT, json.dumps({"decision": "NO_CONFLICT"}))
    assert core.resolve_conflict(a, b, INTENT, INTENT_B) == "NO_CONFLICT"
    request(core, vm, direct_bob, a)


def test_inconclusive_conflict_can_be_rerolled_after_cooldown(core, vm, direct_bob, direct_charlie):
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    vm.mock_llm(CONFLICT_PAT, "this is not json")
    assert core.resolve_conflict(a, b, INTENT, INTENT_B) == "INCONCLUSIVE"
    with vm.expect_revert("COOLDOWN"):
        core.resolve_conflict(a, b, INTENT, INTENT_B)
    warp(vm, T0 + 301)
    vm.clear_mocks()
    vm.mock_llm(CONFLICT_PAT, json.dumps({"decision": "NO_CONFLICT"}))
    assert core.resolve_conflict(a, b, INTENT, INTENT_B) == "NO_CONFLICT"


def test_unknown_conflict_decision_is_inconclusive(core, vm, direct_bob, direct_charlie):
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    vm.mock_llm(CONFLICT_PAT, json.dumps({"decision": "MAYBE"}))
    assert core.resolve_conflict(a, b, INTENT, INTENT_B) == "INCONCLUSIVE"


def test_get_conflict_not_resolved(core, vm, direct_bob, direct_charlie):
    a, b = two_conflicting(core, direct_bob, direct_charlie)
    with vm.expect_revert("NOT_RESOLVED"):
        core.get_conflict(a, b)


# ================================================================== wiring and gates (no peer contract)
def test_wiring_is_set_once_and_owner_only(core, vm, direct_bob, direct_charlie):
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.set_protected_protocol_address(direct_charlie)
    core.set_protected_protocol_address(direct_charlie)
    with vm.expect_revert("ALREADY_SET"):
        core.set_protected_protocol_address(direct_bob)
    assert core.get_stats()["protected_protocol_configured"] is True




def test_gates_need_continuity(core, vm, direct_bob):
    with vm.expect_revert("CONTINUITY_NOT_CONFIGURED"):
        core.require_gate_for_capability(CAP)
    did = deleg(core, direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("CONTINUITY_NOT_CONFIGURED"):
            core.create_request_gated(did, CAP, SCOPE, sha(INTENT), sha(JUST), 600, "", "ACTION-1")
    rid = request(core, vm, direct_bob, did)
    status = core.get_gate_status(rid)
    assert status["open"] is True and status["reason"] == "NO_GATE"
    with vm.expect_revert("NOT_FOUND"):
        core.get_gate_status("nope")


# ================================================================== L9 ownership
def test_two_step_ownership(core, vm, direct_alice, direct_bob):  # F11
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_OWNER"):
            core.transfer_ownership(direct_bob)
    core.transfer_ownership(direct_bob)
    with vm.expect_revert("NOT_PENDING_OWNER"):  # alice is not the pending owner
        core.accept_ownership()
    core.disable_capability(CAP)  # until accepted, alice is still the owner
    core.enable_capability(CAP)
    with vm.prank(direct_bob):
        core.accept_ownership()
        core.disable_capability(CAP)
    with vm.expect_revert("NOT_OWNER"):
        core.enable_capability(CAP)
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_PENDING_OWNER"):  # the pending slot is cleared
            core.accept_ownership()
