"""Direct-mode suite for contracts/protected_protocol.py (v0.4.1)

Scope: everything the Protocol does on its own. Calls into the Ledger are NOT routed in gltest
direct mode, so these paths are covered elsewhere (offline stand-in and the Studio scenarios):
  pause_via_verdict / unpause_via_verdict / the critical path with a real verdict,
  link_ratification_request and resolve_ratification with a real Ledger verdict, including the
  F16 recheck of the linked request at resolution (covered by the offline suite, test_f16_*).
Also not covered here: withdraw_bond and sweep_slashed paying out (native transfers are not
simulated), they are covered by the Studio run.
What is checked here for those paths: the guards that run before any Ledger call, and the
fail-closed branches that need no Ledger (timeout refusal, slashing).

Claims covered:
  P1 ownership is two step and admin methods are owner only (F11)
  P2 accepted scopes and trusted grantors are owner managed (F1/F9)
  P3 risk snapshot: median of fresh reports, stale and removed reporters ignored
  P4 guardian fast path: bond, threshold, TTL, cancel of stale proposals (F6)
  P5 an unlinked pause cannot stay stuck: timeout refusal slashes and unpauses (F6)
  P6 owner last resort: unpause_by_owner (F6)
  P7 slash recipient change is delayed (F11)
  P8 guardian removal cannot break the quorum (F11)
  P9 critical path guards before the Ledger is consulted
"""
import calendar
import hashlib
import sys
from datetime import datetime, timezone

import pytest

CONTRACT = "contracts/protected_protocol.py"
T0 = calendar.timegm((2026, 10, 6, 10, 0, 0))
BOND = 10**17
JUST = "Suspicious drain on the main pool"


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def warp(vm, ts: int):
    """Move the simulated tx time (see the note in test_continuity_core.py)."""
    vm.warp(iso(ts))
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = iso(ts)


def hexof(addr) -> str:
    from genlayer.py.types import Address
    return Address(bytes(addr)).as_hex if isinstance(addr, (bytes, bytearray)) else addr.as_hex


@pytest.fixture
def vm(direct_vm, direct_alice):
    direct_vm.sender = direct_alice  # alice is the owner
    warp(direct_vm, T0)
    return direct_vm


@pytest.fixture
def deploy(vm, direct_deploy):
    def _deploy(threshold=1):
        return direct_deploy(CONTRACT, threshold)
    return _deploy


@pytest.fixture
def core(deploy):
    return deploy(1)


def add_guardian_with_bond(core, vm, guardian, bond=BOND):
    core.add_guardian(guardian)
    with vm.prank(guardian):
        vm.value = bond
        core.deposit_bond()
        vm.value = 0


# ================================================================== P1 ownership and admin
def test_constructor_rejects_zero_threshold(vm, direct_deploy):
    with vm.expect_revert("BAD_THRESHOLD"):
        direct_deploy(CONTRACT, 0)


def test_constructor_sets_threshold(vm, direct_deploy):
    c = direct_deploy(CONTRACT, 3)  # one deployment per test in direct mode
    assert c.get_guardians()["threshold"] == 3
    assert c.get_status()["paused"] is False


def test_admin_methods_are_owner_only(core, vm, direct_bob):
    with vm.prank(direct_bob):
        for call in (
            lambda: core.set_ledger_address(direct_bob),
            lambda: core.transfer_ownership(direct_bob),
            lambda: core.add_accepted_scope("s"),
            lambda: core.remove_accepted_scope("s"),
            lambda: core.add_trusted_grantor(direct_bob),
            lambda: core.remove_trusted_grantor(direct_bob),
            lambda: core.add_severity_reporter(direct_bob),
            lambda: core.remove_severity_reporter(direct_bob),
            lambda: core.add_guardian(direct_bob),
            lambda: core.remove_guardian(direct_bob),
            lambda: core.set_slash_recipient(direct_bob),
            lambda: core.propose_slash_recipient(direct_bob),
            lambda: core.unpause_by_owner(),
        ):
            with vm.expect_revert("NOT_OWNER"):
                call()


def test_two_step_ownership(core, vm, direct_bob):  # F11
    core.transfer_ownership(direct_bob)
    with vm.expect_revert("NOT_PENDING_OWNER"):  # alice is not the pending owner
        core.accept_ownership()
    core.add_accepted_scope("still-owner")  # until accepted, alice is still the owner
    with vm.prank(direct_bob):
        core.accept_ownership()
        core.add_accepted_scope("new-owner")
    with vm.expect_revert("NOT_OWNER"):
        core.add_accepted_scope("old-owner")


def test_ledger_address_set_once(core, vm, direct_bob, direct_charlie):
    core.set_ledger_address(direct_bob)
    with vm.expect_revert("ALREADY_SET"):
        core.set_ledger_address(direct_charlie)


# ================================================================== P2 scopes and grantors
def test_accepted_scopes(core, vm):
    assert core.is_scope_accepted("protocol:main") is False
    core.add_accepted_scope("protocol:main")
    assert core.is_scope_accepted("protocol:main") is True
    core.remove_accepted_scope("protocol:main")
    assert core.is_scope_accepted("protocol:main") is False
    core.remove_accepted_scope("never-added")  # no error
    with vm.expect_revert("BAD_SCOPE"):
        core.add_accepted_scope("")
    with vm.expect_revert("BAD_SCOPE"):
        core.add_accepted_scope("x" * 101)


def test_trusted_grantors_toggle(core, direct_bob):
    key = hexof(direct_bob).lower()
    core.add_trusted_grantor(direct_bob)
    assert core.trusted_grantors[key] is True
    core.remove_trusted_grantor(direct_bob)
    assert core.trusted_grantors[key] is False


# ================================================================== P3 risk snapshot
def test_snapshot_is_the_median_of_fresh_reports(core, vm, direct_alice, direct_bob, direct_charlie):
    assert core.get_risk_snapshot() == {"severity_score": 0, "reported_at": 0}
    for who in (direct_alice, direct_bob, direct_charlie):
        core.add_severity_reporter(who)
    with vm.expect_revert("NOT_A_SEVERITY_REPORTER"):
        with vm.prank(create_stranger()):
            core.report_severity(10)
    core.report_severity(50)
    assert core.get_risk_snapshot() == {"severity_score": 50, "reported_at": T0}
    with vm.prank(direct_bob):
        core.report_severity(100)
    assert core.get_risk_snapshot()["severity_score"] == 75  # even count: mean of the middle two
    with vm.prank(direct_charlie):
        core.report_severity(10)
    assert core.get_risk_snapshot()["severity_score"] == 50  # odd count: the middle one


def create_stranger():
    from gltest.direct import create_address
    return create_address("stranger")


def test_report_bounds(core, vm, direct_alice):
    core.add_severity_reporter(direct_alice)
    with vm.expect_revert("BAD_SCORE"):
        core.report_severity(-1)
    with vm.expect_revert("BAD_SCORE"):
        core.report_severity(10**6 + 1)
    core.report_severity(10**6)
    rep = core.get_severity_report(direct_alice)
    assert rep["score"] == 10**6 and rep["is_active_reporter"] is True


def test_stale_and_removed_reports_are_ignored(core, vm, direct_alice, direct_bob):
    core.add_severity_reporter(direct_alice)
    core.add_severity_reporter(direct_bob)
    core.report_severity(40)
    with vm.prank(direct_bob):
        core.report_severity(80)
    core.remove_severity_reporter(direct_bob)
    assert core.get_risk_snapshot()["severity_score"] == 40  # bob no longer counts
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_A_SEVERITY_REPORTER"):
            core.report_severity(90)
    warp(vm, T0 + 601)  # older than MAX_REPORT_AGE_SECONDS
    assert core.get_risk_snapshot() == {"severity_score": 0, "reported_at": 0}


def test_reporter_cap(core, vm):
    from gltest.direct import create_address
    for i in range(16):
        core.add_severity_reporter(create_address(f"reporter{i}"))
    with vm.expect_revert("TOO_MANY_REPORTERS"):
        core.add_severity_reporter(create_address("reporter-extra"))


# ================================================================== P8 guardians and bonds
def test_guardian_cap(core, vm):
    from gltest.direct import create_address
    for i in range(64):
        core.add_guardian(create_address(f"g{i}"))
    with vm.expect_revert("TOO_MANY_GUARDIANS"):
        core.add_guardian(create_address("g-extra"))


def test_guardians_and_quorum(deploy, vm, direct_bob, direct_charlie):  # F11
    core = deploy(1)
    core.add_guardian(direct_bob)
    g = core.get_guardians()
    assert g["active_count"] == 1 and g["threshold"] == 1
    with vm.expect_revert("WOULD_BREAK_QUORUM"):
        core.remove_guardian(direct_bob)
    core.add_guardian(direct_charlie)
    core.remove_guardian(direct_bob)
    assert core.get_guardians()["active_count"] == 1
    core.remove_guardian(direct_bob)  # already removed: no error, no effect


def test_deposit_bond_rules(core, vm, direct_bob, direct_charlie):
    core.add_guardian(direct_bob)
    with vm.prank(direct_charlie):
        vm.value = BOND
        with vm.expect_revert("NOT_GUARDIAN"):
            core.deposit_bond()
        vm.value = 0
    with vm.prank(direct_bob):
        vm.value = 0
        with vm.expect_revert("ZERO_VALUE"):
            core.deposit_bond()
        vm.value = BOND
        core.deposit_bond()
        core.deposit_bond()
        vm.value = 0
    assert core.get_bond(direct_bob) == 2 * BOND


# ================================================================== P4 guardian pause
def test_pause_needs_guardian_and_bond(core, vm, direct_bob, direct_charlie):
    core.add_guardian(direct_bob)
    with vm.prank(direct_charlie):
        with vm.expect_revert("NOT_GUARDIAN"):
            core.propose_pause(JUST)
    with vm.prank(direct_bob):
        with vm.expect_revert("INSUFFICIENT_BOND"):
            core.propose_pause(JUST)
        with vm.expect_revert("INSUFFICIENT_BOND"):
            core.sign_pause("nope")
    add_guardian_with_bond(core, vm, direct_charlie)
    with vm.prank(direct_charlie):
        with vm.expect_revert("TEXT_TOO_LONG"):
            core.propose_pause("x" * 2001)
        with vm.expect_revert("NO_PROPOSAL"):
            core.sign_pause("nope")


def test_threshold_one_pauses_at_once(core, vm, direct_bob):
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    st = core.get_status()
    assert st["paused"] is True and st["paused_at"] == T0
    p = core.get_proposal(pid)
    assert p["executed"] is True and p["paused_at_snapshot"] == T0 and p["signature_count"] == 1
    assert core.get_active_signed_count(direct_bob) == 1


def test_threshold_two_needs_two_signers(deploy, vm, direct_bob, direct_charlie):
    core = deploy(2)
    add_guardian_with_bond(core, vm, direct_bob)
    add_guardian_with_bond(core, vm, direct_charlie)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
        with vm.expect_revert("ALREADY_SIGNED"):
            core.sign_pause(pid)
    assert core.get_status()["paused"] is False
    with vm.prank(direct_charlie):
        core.sign_pause(pid)
    assert core.get_status()["paused"] is True
    p = core.get_proposal(pid)
    assert p["executed"] is True and p["signature_count"] == 2
    with vm.prank(direct_charlie):
        with vm.expect_revert("ALREADY_EXECUTED"):
            core.sign_pause(pid)


def test_removed_guardian_signature_does_not_count(deploy, vm, direct_alice, direct_bob, direct_charlie):  # F14
    from gltest.direct import create_address
    core = deploy(2)
    third = create_address("third")
    for g in (direct_bob, direct_charlie, third):
        add_guardian_with_bond(core, vm, g)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    core.remove_guardian(direct_bob)  # 3 active, threshold 2: allowed
    with vm.prank(direct_charlie):
        core.sign_pause(pid)  # bob's signature no longer counts, so this is 1 live signature
    assert core.get_status()["paused"] is False
    with vm.prank(third):
        core.sign_pause(pid)
    assert core.get_status()["paused"] is True


def test_proposal_expires_and_stale_cancel_releases_signers(deploy, vm, direct_bob, direct_charlie):  # F6
    core = deploy(2)
    add_guardian_with_bond(core, vm, direct_bob)
    add_guardian_with_bond(core, vm, direct_charlie)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
        with vm.expect_revert("BOND_LOCKED_BY_UNRESOLVED_PROPOSAL"):
            core.withdraw_bond(1)
    with vm.expect_revert("NOT_STALE_YET"):
        core.cancel_stale_proposal(pid)
    warp(vm, T0 + 86401)
    with vm.prank(direct_charlie):
        with vm.expect_revert("PROPOSAL_EXPIRED"):
            core.sign_pause(pid)
    core.cancel_stale_proposal(pid)  # anyone may release the signers
    assert core.get_proposal(pid)["resolved"] is True
    assert core.get_active_signed_count(direct_bob) == 0
    with vm.expect_revert("ALREADY_RESOLVED"):
        core.cancel_stale_proposal(pid)
    with vm.prank(direct_charlie):
        with vm.expect_revert("ALREADY_RESOLVED"):
            core.sign_pause(pid)
    with vm.expect_revert("NO_PROPOSAL"):
        core.cancel_stale_proposal("nope")


def test_executed_proposal_cannot_be_cancelled(core, vm, direct_bob):
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    warp(vm, T0 + 86401)
    with vm.expect_revert("ALREADY_EXECUTED"):
        core.cancel_stale_proposal(pid)


def test_proposal_id_cannot_be_overwritten(deploy, vm, direct_bob):  # F17
    core = deploy(2)
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        core.propose_pause(JUST)
        with vm.expect_revert("PROPOSAL_EXISTS"):  # same text, same time, same guardian
            core.propose_pause(JUST)


# ================================================================== P6 owner last resort
def test_unpause_by_owner(core, vm, direct_bob):  # F6
    with vm.expect_revert("NOT_PAUSED"):
        core.unpause_by_owner()
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        core.propose_pause(JUST)
    assert core.get_status()["paused"] is True
    core.unpause_by_owner()
    assert core.get_status()["paused"] is False


# ================================================================== ratification guards and P5 timeout
def test_link_guards(core, vm, direct_bob, direct_charlie):  # F5 / F6
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.expect_revert("NO_PROPOSAL"):
        core.link_ratification_request("nope", "req")
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    with vm.prank(direct_charlie):  # a stranger within the first hour
        with vm.expect_revert("NOT_A_SIGNER_OF_THIS_PAUSE"):
            core.link_ratification_request(pid, "req")
        warp(vm, T0 + 3600)  # after the delay anyone may link; the next guard is the Ledger itself
        with vm.expect_revert("LEDGER_NOT_CONFIGURED"):
            core.link_ratification_request(pid, "req")
    with vm.prank(direct_bob):  # a signer always reaches the Ledger step
        with vm.expect_revert("LEDGER_NOT_CONFIGURED"):
            core.link_ratification_request(pid, "req")


def test_link_requires_executed_pause(deploy, vm, direct_bob):
    core = deploy(2)
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
        with vm.expect_revert("NOT_EXECUTED"):
            core.link_ratification_request(pid, "req")
    with vm.expect_revert("NOT_EXECUTED"):
        core.resolve_ratification(pid)


def test_unlinked_pause_resolves_as_refusal_after_timeout(core, vm, direct_bob):  # F6 / K1
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    with vm.expect_revert("NOT_LINKED"):
        core.resolve_ratification(pid)
    warp(vm, T0 + 7 * 86400)  # RATIFICATION_TIMEOUT
    core.resolve_ratification(pid)  # anyone can settle it
    assert core.get_proposal(pid)["resolved"] is True
    assert core.get_status()["paused"] is False  # the unratified pause is lifted
    assert core.get_bond(direct_bob) == 0  # and the signer is slashed
    assert core.get_slash_info()["pending"] == BOND
    assert core.get_active_signed_count(direct_bob) == 0
    with vm.expect_revert("ALREADY_RESOLVED"):
        core.resolve_ratification(pid)


def test_timeout_does_not_unpause_a_newer_pause(core, vm, direct_bob):
    add_guardian_with_bond(core, vm, direct_bob, bond=2 * BOND)
    with vm.prank(direct_bob):
        first = core.propose_pause(JUST)
    core.unpause_by_owner()
    warp(vm, T0 + 100)
    with vm.prank(direct_bob):
        core.propose_pause("A second, different pause")  # paused_at moves on
    warp(vm, T0 + 7 * 86400)
    core.resolve_ratification(first)
    assert core.get_status()["paused"] is True  # only the pause it ratified would be lifted


def test_slash_never_exceeds_the_bond(core, vm, direct_bob):
    add_guardian_with_bond(core, vm, direct_bob, bond=BOND)
    with vm.prank(direct_bob):
        pid = core.propose_pause(JUST)
    warp(vm, T0 + 7 * 86400)
    core.resolve_ratification(pid)
    assert core.get_slash_info()["pending"] == BOND
    assert core.get_bond(direct_bob) == 0


# ================================================================== P7 slash recipient
def test_slash_recipient_set_once_then_delayed(core, vm, direct_bob, direct_charlie):  # F11
    with vm.expect_revert("SLASH_RECIPIENT_NOT_SET"):
        core.sweep_slashed()
    assert core.get_slash_info()["recipient"] == ""
    core.set_slash_recipient(direct_bob)
    with vm.expect_revert("SLASH_RECIPIENT_ALREADY_SET"):
        core.set_slash_recipient(direct_charlie)
    with vm.expect_revert("NOTHING_TO_SWEEP"):
        core.sweep_slashed()
    with vm.expect_revert("NOTHING_PENDING"):
        core.apply_slash_recipient()
    core.propose_slash_recipient(direct_charlie)
    info = core.get_slash_info()
    assert info["recipient"] == hexof(direct_bob) and info["pending_recipient"] == hexof(direct_charlie)
    assert info["pending_recipient_at"] == T0 + 86400
    with vm.expect_revert("TOO_EARLY"):
        core.apply_slash_recipient()
    warp(vm, T0 + 86400)
    core.apply_slash_recipient()  # anyone may apply once the delay is over
    info = core.get_slash_info()
    assert info["recipient"] == hexof(direct_charlie) and info["pending_recipient"] == ""
    with vm.expect_revert("NOTHING_PENDING"):
        core.apply_slash_recipient()


def test_withdraw_bond_guards(core, vm, direct_bob):
    add_guardian_with_bond(core, vm, direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("BAD_AMOUNT"):
            core.withdraw_bond(0)
        with vm.expect_revert("INSUFFICIENT_BOND"):
            core.withdraw_bond(BOND + 1)


# ================================================================== P9 critical path guards and Ledger-dependent entry points
def test_threshold_payload_is_canonical(core):
    assert core.canonical_threshold_payload(2) == "CHANGE_GUARDIAN_THRESHOLD:from=1,to=2"


def test_critical_proposal_guards(core, vm, direct_bob, direct_charlie):
    core.add_guardian(direct_bob)
    core.add_guardian(direct_charlie)
    with vm.expect_revert("BAD_THRESHOLD"):
        core.propose_critical_threshold_change("req", 0)
    with vm.expect_revert("BAD_THRESHOLD"):
        core.propose_critical_threshold_change("req", 3)  # more than the active guardians
    with vm.expect_revert("NO_CHANGE"):
        core.propose_critical_threshold_change("req", 1)
    with vm.expect_revert("LEDGER_NOT_CONFIGURED"):  # a valid proposal needs a Ledger verdict
        core.propose_critical_threshold_change("req", 2)


def test_critical_approval_guards(core, vm, direct_bob):
    with vm.expect_revert("NO_PROPOSAL"):
        core.get_critical_action("nope")
    with vm.prank(direct_bob):
        with vm.expect_revert("NOT_GUARDIAN"):
            core.approve_critical_action("nope")
    core.add_guardian(direct_bob)
    with vm.prank(direct_bob):
        with vm.expect_revert("NO_PROPOSAL"):
            core.approve_critical_action("nope")


def test_verdict_entry_points_need_a_ledger(core, vm):
    with vm.expect_revert("LEDGER_NOT_CONFIGURED"):
        core.pause_via_verdict("req")
    with vm.expect_revert("LEDGER_NOT_CONFIGURED"):
        core.unpause_via_verdict("req")
    assert core.get_execution_status("req") is False
    assert core.get_status()["paused"] is False
