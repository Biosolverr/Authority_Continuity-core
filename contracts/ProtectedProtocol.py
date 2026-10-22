# v0.4.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
ProtectedProtocol v0.4.0: demo target for AuthorityLedger.

v0.4 hardening (see SECURITY.md, findings F1 to F15):
  F1/F9  Every verdict is checked against owner managed lists: the scope must be accepted
         (add_accepted_scope) and the root grantor must be the owner or a trusted grantor.
  F3     The plain guardian vote on the threshold is removed. The threshold changes only through the
         critical path (verdict for the exact action plus guardian approvals).
  F5     A ratification request must be created after the pause and can be linked to one pause only.
         The verdict must match the pause justification (an appeal that rewrites it counts as a refusal)
         and must not be voided.
  F6/K1  Pauses can no longer get stuck: anyone can link after a short delay, resolve_ratification settles
         an unlinked or unadjudicated pause as a refusal after a timeout, stale unexecuted proposals can be
         cancelled, and the owner has unpause_by_owner as a last resort.
  F11    Two step ownership transfer, delayed slash recipient change, remove_guardian cannot break the quorum.
  F14    Signatures of removed guardians are not counted, list sizes are capped.
Behavior unchanged: pause and unpause by verdict, guardian fast path with bonds, slashing and sweep.
"""
from genlayer import *
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


def _coerce_address(val) -> Address:
    if hasattr(val, "as_bytes"):
        return val
    if isinstance(val, bool):
        raise gl.vm.UserError(f"invalid address value: {val!r}")
    if isinstance(val, int):
        try:
            return Address(val.to_bytes(Address.SIZE, "big"))
        except (OverflowError, ValueError):
            raise gl.vm.UserError(f"invalid address value: {val!r}")
    if isinstance(val, (bytes, bytearray, memoryview)):
        return Address(bytes(val))
    if isinstance(val, str):
        return Address(val)
    raise gl.vm.UserError(f"unsupported address value type: {type(val)}")


def _key(addr) -> str:
    return _coerce_address(addr).as_hex


def _now() -> int:
    raw = gl.message_raw["datetime"]
    return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())


@gl.evm.contract_interface
class _Recipient:
    """Declared EVM recipient: the only correct way to send native GEN to an EOA."""
    class View:
        pass

    class Write:
        pass


CAP_PAUSE = "PAUSE_PROTOCOL"
CAP_UNPAUSE = "UNPAUSE_PROTOCOL"
CAP_RATIFY_GUARDIAN_PAUSE = "RATIFY_GUARDIAN_PAUSE"
CAP_CHANGE_THRESHOLD = "CHANGE_GUARDIAN_THRESHOLD"
CRITICAL_APPROVAL_WINDOW = 86400

MAX_REPORT_AGE_SECONDS = 600  # keep in sync with MAX_SEVERITY_AGE_SECONDS in the Ledger
MIN_BOND = 10**17
SLASH_AMOUNT = 10**17
RATIFICATION_GRACE_SECONDS = 86400
RATIFICATION_TIMEOUT = 7 * 86400
LINK_OPEN_AFTER_SECONDS = 3600
PROPOSAL_TTL = 86400
SLASH_RECIPIENT_DELAY = 86400
MAX_GUARDIAN_KEYS = 64
MAX_REPORTER_KEYS = 16
MAX_SCORE = 10**6
MAX_TEXT = 2000


@allow_storage
@dataclass
class PauseProposal:
    justification_text: str
    signature_count: u256
    executed: bool
    resolved: bool
    request_id: str
    paused_at_snapshot: u64
    created_at: u64


@allow_storage
@dataclass
class CriticalAction:
    new_threshold: u256
    proposer: Address
    payload_hash: str
    approvals_csv: str
    expires_at: u64
    executed: bool


class ProtectedProtocol(gl.Contract):
    owner: Address
    pending_owner: Address
    pending_owner_set: bool
    ledger_address: Address
    ledger_configured: bool

    accepted_scopes: TreeMap[str, bool]
    trusted_grantors: TreeMap[str, bool]

    paused: bool
    paused_at: u64
    executed_requests: TreeMap[str, bool]
    linked_requests: TreeMap[str, bool]

    severity_reporters: TreeMap[str, bool]
    reporter_keys_csv: str
    severity_reports: TreeMap[str, u256]
    severity_report_times: TreeMap[str, u256]

    guardians: TreeMap[str, bool]
    guardian_keys_csv: str
    bonds: TreeMap[str, u256]
    proposals: TreeMap[str, PauseProposal]
    signers_of: TreeMap[str, str]
    active_signed_count: TreeMap[str, u256]
    threshold: u256

    critical_actions: TreeMap[str, CriticalAction]

    slash_recipient: Address
    slash_recipient_set: bool
    pending_slash_recipient: Address
    pending_slash_set: bool
    pending_slash_at: u64
    slashed_pending: u256

    def __init__(self, guardian_threshold: int):
        self.owner = gl.message.sender_address
        self.pending_owner_set = False
        self.ledger_configured = False
        self.paused = False
        self.paused_at = u64(0)
        self.reporter_keys_csv = ""
        self.guardian_keys_csv = ""
        self.slash_recipient_set = False
        self.pending_slash_set = False
        self.pending_slash_at = u64(0)
        self.slashed_pending = u256(0)
        if guardian_threshold < 1:
            raise gl.vm.UserError("BAD_THRESHOLD")
        self.threshold = u256(guardian_threshold)

    def _only_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")

    @gl.public.write
    def set_ledger_address(self, ledger_address: Address) -> None:
        self._only_owner()
        if self.ledger_configured:
            raise gl.vm.UserError("ALREADY_SET")
        self.ledger_address = _coerce_address(ledger_address)
        self.ledger_configured = True

    @gl.public.write
    def transfer_ownership(self, new_owner: Address) -> None:
        self._only_owner()
        self.pending_owner = _coerce_address(new_owner)
        self.pending_owner_set = True

    @gl.public.write
    def accept_ownership(self) -> None:
        if not self.pending_owner_set or gl.message.sender_address != self.pending_owner:
            raise gl.vm.UserError("NOT_PENDING_OWNER")
        self.owner = self.pending_owner
        self.pending_owner_set = False

    # ---- F1/F9: what this target accepts from the Ledger ----
    @gl.public.write
    def add_accepted_scope(self, scope: str) -> None:
        self._only_owner()
        if len(scope) < 1 or len(scope) > 100:
            raise gl.vm.UserError("BAD_SCOPE")
        self.accepted_scopes[scope] = True

    @gl.public.write
    def remove_accepted_scope(self, scope: str) -> None:
        self._only_owner()
        if scope in self.accepted_scopes:
            self.accepted_scopes[scope] = False

    @gl.public.write
    def add_trusted_grantor(self, grantor: Address) -> None:
        self._only_owner()
        self.trusted_grantors[_key(grantor).lower()] = True

    @gl.public.write
    def remove_trusted_grantor(self, grantor: Address) -> None:
        self._only_owner()
        k = _key(grantor).lower()
        if k in self.trusted_grantors:
            self.trusted_grantors[k] = False

    @gl.public.view
    def is_scope_accepted(self, scope: str) -> bool:
        return bool(self.accepted_scopes[scope]) if scope in self.accepted_scopes else False

    # ------------------------------------------------------------------ #
    # Risk snapshot, the only input the Ledger reads
    # ------------------------------------------------------------------ #

    @gl.public.write
    def add_severity_reporter(self, reporter: Address) -> None:
        self._only_owner()
        key = _key(reporter)
        if key not in self.severity_reporters:
            if len([k for k in self.reporter_keys_csv.split(",") if k]) >= MAX_REPORTER_KEYS:
                raise gl.vm.UserError("TOO_MANY_REPORTERS")
            self.reporter_keys_csv = (self.reporter_keys_csv + "," + key) if self.reporter_keys_csv else key
        self.severity_reporters[key] = True

    @gl.public.write
    def remove_severity_reporter(self, reporter: Address) -> None:
        self._only_owner()
        key = _key(reporter)
        if key in self.severity_reporters:
            self.severity_reporters[key] = False

    @gl.public.write
    def report_severity(self, score: int) -> None:
        key = _key(gl.message.sender_address)
        if key not in self.severity_reporters or not self.severity_reporters[key]:
            raise gl.vm.UserError("NOT_A_SEVERITY_REPORTER")
        if score < 0 or score > MAX_SCORE:
            raise gl.vm.UserError("BAD_SCORE")
        self.severity_reports[key] = u256(score)
        self.severity_report_times[key] = u256(_now())

    @gl.public.view
    def get_risk_snapshot(self) -> dict:
        now = _now()
        fresh_scores = []
        fresh_times = []
        for key in [k for k in self.reporter_keys_csv.split(",") if k]:
            if key not in self.severity_reporters or not self.severity_reporters[key]:
                continue
            if key not in self.severity_report_times:
                continue
            ts = int(self.severity_report_times[key])
            if now - ts > MAX_REPORT_AGE_SECONDS:
                continue
            fresh_scores.append(int(self.severity_reports[key]))
            fresh_times.append(ts)
        if not fresh_scores:
            return {"severity_score": 0, "reported_at": 0}
        fresh_scores.sort()
        n = len(fresh_scores)
        median = fresh_scores[n // 2] if n % 2 == 1 else (fresh_scores[n // 2 - 1] + fresh_scores[n // 2]) // 2
        return {"severity_score": median, "reported_at": max(fresh_times)}

    @gl.public.view
    def get_severity_report(self, reporter: Address) -> dict:
        key = _key(reporter)
        return {
            "score": int(self.severity_reports[key]) if key in self.severity_reports else 0,
            "reported_at": int(self.severity_report_times[key]) if key in self.severity_report_times else 0,
            "is_active_reporter": bool(self.severity_reporters[key]) if key in self.severity_reporters else False,
        }

    # ------------------------------------------------------------------ #
    # Verdict path
    # ------------------------------------------------------------------ #

    def _require_ledger_configured(self) -> None:
        if not self.ledger_configured:
            raise gl.vm.UserError("LEDGER_NOT_CONFIGURED")

    def _read_request(self, request_id: str) -> dict:
        self._require_ledger_configured()
        return gl.get_contract_at(self.ledger_address).view().get_request(request_id)

    def _read_verdict(self, request_id: str) -> dict:
        self._require_ledger_configured()
        return gl.get_contract_at(self.ledger_address).view().get_verdict(request_id)

    def _verify_result(self, res) -> None:
        """F1/F9: authorized, an accepted scope, and a trusted root grantor."""
        if not res["authorized"]:
            raise gl.vm.UserError(str(res["reason"]))
        scope = str(res["scope"])
        if scope not in self.accepted_scopes or not self.accepted_scopes[scope]:
            raise gl.vm.UserError("SCOPE_NOT_ACCEPTED")
        rg = str(res["root_grantor"]).lower()
        if rg != _key(self.owner).lower() and not (rg in self.trusted_grantors and self.trusted_grantors[rg]):
            raise gl.vm.UserError("ROOT_GRANTOR_NOT_TRUSTED")

    def _authorize_and_consume(self, request_id: str, expected_capability: str) -> None:
        if request_id in self.executed_requests:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        self._require_ledger_configured()
        ledger = gl.get_contract_at(self.ledger_address)
        res = ledger.view().check_authority(request_id, gl.message.sender_address, expected_capability, "")
        self._verify_result(res)
        self.executed_requests[request_id] = True

    # ------------------------------------------------------------------ #
    # Critical path: semantic authority (Ledger) plus collective (guardians)
    # ------------------------------------------------------------------ #

    def _threshold_payload(self, new_threshold: int) -> str:
        return f"{CAP_CHANGE_THRESHOLD}:from={int(self.threshold)},to={int(new_threshold)}"

    @gl.public.view
    def canonical_threshold_payload(self, new_threshold: int) -> str:
        return self._threshold_payload(new_threshold)

    def _check_critical_authority(self, request_id: str, actor, payload_hash: str) -> None:
        self._require_ledger_configured()
        res = gl.get_contract_at(self.ledger_address).view().check_authority(request_id, actor, CAP_CHANGE_THRESHOLD, payload_hash)
        self._verify_result(res)

    @gl.public.write
    def propose_critical_threshold_change(self, request_id: str, new_threshold: int) -> None:
        if request_id in self.executed_requests:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        if new_threshold < 1 or new_threshold > self._active_guardian_count():
            raise gl.vm.UserError("BAD_THRESHOLD")
        if new_threshold == int(self.threshold):
            raise gl.vm.UserError("NO_CHANGE")
        payload_hash = hashlib.sha256(self._threshold_payload(new_threshold).encode()).hexdigest()
        self._check_critical_authority(request_id, gl.message.sender_address, payload_hash)
        self.executed_requests[request_id] = True
        self.critical_actions[request_id] = CriticalAction(
            new_threshold=u256(new_threshold), proposer=gl.message.sender_address, payload_hash=payload_hash,
            approvals_csv="", expires_at=u64(_now() + CRITICAL_APPROVAL_WINDOW), executed=False,
        )

    @gl.public.write
    def approve_critical_action(self, request_id: str) -> None:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        if request_id not in self.critical_actions:
            raise gl.vm.UserError("NO_PROPOSAL")
        a = self.critical_actions[request_id]
        if a.executed:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        if _now() > a.expires_at:
            raise gl.vm.UserError("EXPIRED")
        done = [k for k in a.approvals_csv.split(",") if k]
        if key in done:
            raise gl.vm.UserError("ALREADY_APPROVED")
        done.append(key)
        a.approvals_csv = ",".join(done)
        live = sum(1 for k in done if self._is_active_guardian(k))
        if live >= int(self.threshold):
            self._finalize_critical(request_id)

    def _finalize_critical(self, request_id: str) -> None:
        a = self.critical_actions[request_id]
        current = hashlib.sha256(self._threshold_payload(int(a.new_threshold)).encode()).hexdigest()
        if current != a.payload_hash:
            raise gl.vm.UserError("STALE_ACTION")
        if int(a.new_threshold) > self._active_guardian_count():
            raise gl.vm.UserError("BAD_THRESHOLD")
        self._check_critical_authority(request_id, a.proposer, a.payload_hash)
        self.threshold = a.new_threshold
        a.executed = True

    @gl.public.view
    def get_critical_action(self, request_id: str) -> dict:
        if request_id not in self.critical_actions:
            raise gl.vm.UserError("NO_PROPOSAL")
        a = self.critical_actions[request_id]
        done = [k for k in a.approvals_csv.split(",") if k]
        return {"new_threshold": int(a.new_threshold), "proposer": a.proposer, "approvals": done,
                "approvals_count": len(done), "required": int(self.threshold),
                "expires_at": a.expires_at, "executed": a.executed}

    @gl.public.write
    def pause_via_verdict(self, request_id: str) -> None:
        self._authorize_and_consume(request_id, CAP_PAUSE)
        self.paused = True
        self.paused_at = u64(_now())

    @gl.public.write
    def unpause_via_verdict(self, request_id: str) -> None:
        self._authorize_and_consume(request_id, CAP_UNPAUSE)
        self.paused = False
        self.paused_at = u64(_now())

    @gl.public.write
    def unpause_by_owner(self) -> None:
        """F6: last resort so a stuck pause can never freeze the protocol."""
        self._only_owner()
        if not self.paused:
            raise gl.vm.UserError("NOT_PAUSED")
        self.paused = False
        self.paused_at = u64(_now())

    # ------------------------------------------------------------------ #
    # Guardian fast path
    # ------------------------------------------------------------------ #

    def _is_active_guardian(self, key: str) -> bool:
        return key in self.guardians and bool(self.guardians[key])

    @gl.public.write
    def add_guardian(self, guardian: Address) -> None:
        self._only_owner()
        key = _key(guardian)
        if key not in self.guardians:
            if len([k for k in self.guardian_keys_csv.split(",") if k]) >= MAX_GUARDIAN_KEYS:
                raise gl.vm.UserError("TOO_MANY_GUARDIANS")
            self.guardian_keys_csv = (self.guardian_keys_csv + "," + key) if self.guardian_keys_csv else key
        self.guardians[key] = True

    def _active_guardian_count(self) -> int:
        return sum(1 for k in self.guardian_keys_csv.split(",") if k and self._is_active_guardian(k))

    @gl.public.write
    def remove_guardian(self, guardian: Address) -> None:
        self._only_owner()
        key = _key(guardian)
        if key in self.guardians and self.guardians[key]:
            if self._active_guardian_count() - 1 < int(self.threshold):
                raise gl.vm.UserError("WOULD_BREAK_QUORUM")
            self.guardians[key] = False

    @gl.public.view
    def get_guardians(self) -> dict:
        active = [k for k in self.guardian_keys_csv.split(",") if k and self._is_active_guardian(k)]
        return {"guardians": active, "active_count": len(active), "threshold": int(self.threshold)}

    @gl.public.write.payable
    def deposit_bond(self) -> None:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        if int(gl.message.value) <= 0:
            raise gl.vm.UserError("ZERO_VALUE")
        current = self.bonds[key] if key in self.bonds else u256(0)
        self.bonds[key] = current + u256(gl.message.value)

    def _bump_active_signed(self, key: str, delta: int) -> None:
        current = int(self.active_signed_count[key]) if key in self.active_signed_count else 0
        self.active_signed_count[key] = u256(max(0, current + delta))

    def _live_signatures(self, pause_id: str) -> int:
        return sum(1 for s in self.signers_of[pause_id].split(",") if s and self._is_active_guardian(s))

    @gl.public.write
    def propose_pause(self, justification_text: str) -> str:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        if len(justification_text) > MAX_TEXT:
            raise gl.vm.UserError("TEXT_TOO_LONG")
        bond = int(self.bonds[key]) if key in self.bonds else 0
        if bond < MIN_BOND:
            raise gl.vm.UserError("INSUFFICIENT_BOND")
        pause_id = hashlib.sha256(f"pause:{justification_text}:{gl.message_raw['datetime']}:{key}".encode()).hexdigest()
        self.proposals[pause_id] = PauseProposal(
            justification_text=justification_text, signature_count=u256(1), executed=False, resolved=False,
            request_id="", paused_at_snapshot=u64(0), created_at=u64(_now()),
        )
        self.signers_of[pause_id] = key
        self._bump_active_signed(key, +1)
        if self._live_signatures(pause_id) >= int(self.threshold):
            self._execute_pause(pause_id)
        return pause_id

    @gl.public.write
    def sign_pause(self, pause_id: str) -> None:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        bond = int(self.bonds[key]) if key in self.bonds else 0
        if bond < MIN_BOND:
            raise gl.vm.UserError("INSUFFICIENT_BOND")
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        if p.executed:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        if p.resolved:
            raise gl.vm.UserError("ALREADY_RESOLVED")
        if _now() > int(p.created_at) + PROPOSAL_TTL:
            raise gl.vm.UserError("PROPOSAL_EXPIRED")
        signers_csv = self.signers_of[pause_id]
        if f",{key}," in f",{signers_csv},":
            raise gl.vm.UserError("ALREADY_SIGNED")
        self.signers_of[pause_id] = signers_csv + "," + key
        p.signature_count += u256(1)
        self._bump_active_signed(key, +1)
        if self._live_signatures(pause_id) >= int(self.threshold):
            self._execute_pause(pause_id)

    def _execute_pause(self, pause_id: str) -> None:
        p = self.proposals[pause_id]
        p.executed = True
        self.paused = True
        self.paused_at = u64(_now())
        p.paused_at_snapshot = self.paused_at

    @gl.public.write
    def cancel_stale_proposal(self, pause_id: str) -> None:
        """F6: a proposal that never reached its threshold releases its signers after PROPOSAL_TTL."""
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        if p.executed:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        if p.resolved:
            raise gl.vm.UserError("ALREADY_RESOLVED")
        if _now() <= int(p.created_at) + PROPOSAL_TTL:
            raise gl.vm.UserError("NOT_STALE_YET")
        p.resolved = True
        for key in [s for s in self.signers_of[pause_id].split(",") if s]:
            self._bump_active_signed(key, -1)

    @gl.public.write
    def link_ratification_request(self, pause_id: str, request_id: str) -> None:
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        if not p.executed:
            raise gl.vm.UserError("NOT_EXECUTED")
        if p.request_id != "":
            raise gl.vm.UserError("ALREADY_LINKED")
        key = _key(gl.message.sender_address)
        signers_csv = self.signers_of[pause_id]
        if f",{key}," not in f",{signers_csv},":
            # F6: after a short delay anyone may link, so unwilling signers cannot block resolution
            if _now() < int(p.paused_at_snapshot) + LINK_OPEN_AFTER_SECONDS:
                raise gl.vm.UserError("NOT_A_SIGNER_OF_THIS_PAUSE")
        if request_id in self.linked_requests:
            raise gl.vm.UserError("REQUEST_ALREADY_LINKED")
        req = self._read_request(request_id)
        if req["capability"] != CAP_RATIFY_GUARDIAN_PAUSE:
            raise gl.vm.UserError("WRONG_CAPABILITY")
        if req["justification_hash"] != hashlib.sha256(p.justification_text.encode()).hexdigest():
            raise gl.vm.UserError("JUSTIFICATION_MISMATCH")
        if int(req["created_at"]) < int(p.paused_at_snapshot):
            raise gl.vm.UserError("REQUEST_PREDATES_PAUSE")
        p.request_id = request_id
        self.linked_requests[request_id] = True

    @gl.public.write
    def resolve_ratification(self, pause_id: str) -> None:
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        if not p.executed:
            raise gl.vm.UserError("NOT_EXECUTED")
        if p.resolved:
            raise gl.vm.UserError("ALREADY_RESOLVED")
        now = _now()
        timed_out = now >= int(p.paused_at_snapshot) + RATIFICATION_TIMEOUT

        verdict = None
        if p.request_id == "":
            if not timed_out:
                raise gl.vm.UserError("NOT_LINKED")
        else:
            try:
                verdict = self._read_verdict(p.request_id)
            except Exception:
                verdict = None
            if verdict is None and not timed_out:
                raise gl.vm.UserError("NOT_ADJUDICATED")

        decision = "OUT_OF_SCOPE"
        if verdict is not None:
            decision = str(verdict["decision"])
            if decision == "INCONCLUSIVE" and not bool(verdict["appealed"]):
                if now < int(p.paused_at_snapshot) + RATIFICATION_GRACE_SECONDS:
                    raise gl.vm.UserError("AWAITING_APPEAL")
            expected = hashlib.sha256(p.justification_text.encode()).hexdigest()
            if (decision != "IN_SCOPE" or bool(verdict["voided"])
                    or str(verdict["justification_hash"]) != expected
                    or int(verdict["adjudicated_at"]) < int(p.paused_at_snapshot)):
                decision = "OUT_OF_SCOPE"

        p.resolved = True
        signer_keys = [s for s in self.signers_of[pause_id].split(",") if s]
        for key in signer_keys:
            self._bump_active_signed(key, -1)
        if decision == "IN_SCOPE":
            return

        for key in signer_keys:
            bond = int(self.bonds[key]) if key in self.bonds else 0
            slashed = min(bond, SLASH_AMOUNT)
            self.bonds[key] = u256(bond - slashed)
            self.slashed_pending = u256(int(self.slashed_pending) + slashed)
        if self.paused_at == p.paused_at_snapshot:
            self.paused = False
            self.paused_at = u64(now)

    @gl.public.write
    def withdraw_bond(self, amount: int) -> None:
        key = _key(gl.message.sender_address)
        if amount <= 0:
            raise gl.vm.UserError("BAD_AMOUNT")
        active = int(self.active_signed_count[key]) if key in self.active_signed_count else 0
        if active > 0:
            raise gl.vm.UserError("BOND_LOCKED_BY_UNRESOLVED_PROPOSAL")
        bond = int(self.bonds[key]) if key in self.bonds else 0
        if amount > bond:
            raise gl.vm.UserError("INSUFFICIENT_BOND")
        self.bonds[key] = u256(bond - amount)
        _Recipient(gl.message.sender_address).emit_transfer(value=u256(amount))

    @gl.public.write
    def set_slash_recipient(self, recipient: Address) -> None:
        """Owner, once: the first recipient. Later changes go through propose_slash_recipient."""
        self._only_owner()
        if self.slash_recipient_set:
            raise gl.vm.UserError("SLASH_RECIPIENT_ALREADY_SET")
        addr = _coerce_address(recipient)
        if bytes(addr.as_bytes) == bytes(Address.SIZE):
            raise gl.vm.UserError("BAD_RECIPIENT")
        self.slash_recipient = addr
        self.slash_recipient_set = True

    @gl.public.write
    def propose_slash_recipient(self, recipient: Address) -> None:
        """F11: change the recipient with a delay."""
        self._only_owner()
        addr = _coerce_address(recipient)
        if bytes(addr.as_bytes) == bytes(Address.SIZE):
            raise gl.vm.UserError("BAD_RECIPIENT")
        self.pending_slash_recipient = addr
        self.pending_slash_set = True
        self.pending_slash_at = u64(_now() + SLASH_RECIPIENT_DELAY)

    @gl.public.write
    def apply_slash_recipient(self) -> None:
        if not self.pending_slash_set:
            raise gl.vm.UserError("NOTHING_PENDING")
        if _now() < int(self.pending_slash_at):
            raise gl.vm.UserError("TOO_EARLY")
        self.slash_recipient = self.pending_slash_recipient
        self.slash_recipient_set = True
        self.pending_slash_set = False

    @gl.public.write
    def sweep_slashed(self) -> None:
        if not self.slash_recipient_set:
            raise gl.vm.UserError("SLASH_RECIPIENT_NOT_SET")
        amount = int(self.slashed_pending)
        if amount <= 0:
            raise gl.vm.UserError("NOTHING_TO_SWEEP")
        self.slashed_pending = u256(0)
        _Recipient(self.slash_recipient).emit_transfer(value=u256(amount))

    @gl.public.view
    def get_slash_info(self) -> dict:
        return {
            "recipient": self.slash_recipient.as_hex if self.slash_recipient_set else "",
            "pending": int(self.slashed_pending),
            "pending_recipient": self.pending_slash_recipient.as_hex if self.pending_slash_set else "",
            "pending_recipient_at": int(self.pending_slash_at) if self.pending_slash_set else 0,
        }

    @gl.public.view
    def get_status(self) -> dict:
        return {"paused": self.paused, "paused_at": self.paused_at}

    # ------------------------------------------------------------------ #
    # Getters
    # ------------------------------------------------------------------ #

    @gl.public.view
    def get_execution_status(self, request_id: str) -> bool:
        return bool(self.executed_requests[request_id]) if request_id in self.executed_requests else False

    @gl.public.view
    def get_proposal(self, pause_id: str) -> dict:
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        return {
            "justification_text": p.justification_text, "signature_count": int(p.signature_count),
            "threshold": int(self.threshold), "executed": p.executed, "resolved": p.resolved,
            "request_id": p.request_id, "paused_at_snapshot": p.paused_at_snapshot, "created_at": p.created_at,
        }

    @gl.public.view
    def get_bond(self, guardian: Address) -> int:
        key = _key(guardian)
        return int(self.bonds[key]) if key in self.bonds else 0

    @gl.public.view
    def get_active_signed_count(self, guardian: Address) -> int:
        key = _key(guardian)
        return int(self.active_signed_count[key]) if key in self.active_signed_count else 0

