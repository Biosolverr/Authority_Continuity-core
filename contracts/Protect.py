# v0.3.1
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
ProtectedProtocol v0.3.1 — demo target for AuthorityLedger.

The target checks authority itself (read-only Ledger.check_authority) and writes
only to its own state; it never receives external writes from the Ledger.

Execution paths, chosen by the consequences of the action:
  * Verdict path: pause/unpause via an IN_SCOPE verdict. Replay protection
    (executed_requests) lives here, in the target.
  * Critical path: CHANGE_GUARDIAN_THRESHOLD needs two independent controls:
      1. semantic authority: an IN_SCOPE verdict for the EXACT action. The target
         builds the canonical text from real parameters and passes its sha256 to
         the Ledger (mismatch = ACTION_PARAMS_MISMATCH / STALE_ACTION);
      2. collective authority: approve_critical_action() by as many guardians as
         the current threshold. Authority is re-checked at application time
         (revoked delegation or expired verdict = AUTHORITY_LOST).
    Neither control replaces the other.
  * Guardian fast path: bonded guardians pause by N-of-M signatures; the pause is
    ratified afterwards by a Ledger verdict. An INCONCLUSIVE ratification waits
    for an appeal until RATIFICATION_GRACE_SECONDS, then counts as a refusal.
    Rejected pauses slash the signers' bonds.
  * Slashing: resolve_ratification only accounts the amount in slashed_pending
    (no transfer, so it cannot fail on payout). The owner sets the recipient once
    (set_slash_recipient); anyone can call sweep_slashed(), which pays the
    recipient. State is zeroed BEFORE the transfer.
"""
from genlayer import *
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


def _coerce_address(val) -> Address:
    """See authority_ledger.py: the Studio UI may send an address as an int."""
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
    """Stable readable address key (checksum hex). str(Address) in the SDK gives
    Address("0x..."), which is awkward in responses and logs."""
    return _coerce_address(addr).as_hex


def _now() -> int:
    """Unix seconds from the ISO string gl.message_raw['datetime'] ('Z' -> '+00:00')."""
    raw = gl.message_raw["datetime"]
    return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())


@gl.evm.contract_interface
class _Recipient:
    """Declared EVM recipient: the ONLY correct way to send native GEN to an EOA
    (gl.get_contract_at(eoa).emit_transfer silently moves nothing)."""
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


@allow_storage
@dataclass
class ThresholdChangeProposal:
    new_threshold: u256
    votes: u256
    executed: bool


@allow_storage
@dataclass
class PauseProposal:
    justification_text: str
    signature_count: u256
    executed: bool
    resolved: bool
    request_id: str
    paused_at_snapshot: u64


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
    ledger_address: Address
    ledger_configured: bool

    paused: bool
    paused_at: u64
    executed_requests: TreeMap[str, bool]

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

    threshold_proposals: TreeMap[str, ThresholdChangeProposal]
    threshold_voters_of: TreeMap[str, str]

    critical_actions: TreeMap[str, CriticalAction]

    slash_recipient: Address
    slash_recipient_set: bool
    slashed_pending: u256

    def __init__(self, guardian_threshold: int):
        # No ledger_address here: circular dependency, resolved via a setter.
        self.owner = gl.message.sender_address
        self.ledger_configured = False
        self.paused = False
        self.paused_at = u64(0)
        self.reporter_keys_csv = ""
        self.guardian_keys_csv = ""
        self.slash_recipient_set = False
        self.slashed_pending = u256(0)
        if guardian_threshold < 1:
            raise gl.vm.UserError("BAD_THRESHOLD")
        self.threshold = u256(guardian_threshold)

    @gl.public.write
    def set_ledger_address(self, ledger_address: Address) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        if self.ledger_configured:
            raise gl.vm.UserError("ALREADY_SET")
        self.ledger_address = _coerce_address(ledger_address)
        self.ledger_configured = True

    # ------------------------------------------------------------------ #
    # Risk snapshot — the only input the Ledger reads
    # ------------------------------------------------------------------ #

    @gl.public.write
    def add_severity_reporter(self, reporter: Address) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        key = _key(reporter)
        if key not in self.severity_reporters:
            self.reporter_keys_csv = (self.reporter_keys_csv + "," + key) if self.reporter_keys_csv else key
        self.severity_reporters[key] = True

    @gl.public.write
    def remove_severity_reporter(self, reporter: Address) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        key = _key(reporter)
        if key in self.severity_reporters:
            self.severity_reporters[key] = False

    @gl.public.write
    def report_severity(self, score: int) -> None:
        # An external signal is not trusted automatically: only owner-approved
        # reporters, aggregated as the median of fresh reports.
        key = _key(gl.message.sender_address)
        if key not in self.severity_reporters or not self.severity_reporters[key]:
            raise gl.vm.UserError("NOT_A_SEVERITY_REPORTER")
        if score < 0:
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
    # Verdict path: the delegate calls pause; the target verifies authority
    # with one read-only Ledger.check_authority call.
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

    def _authorize_and_consume(self, request_id: str, expected_capability: str) -> None:
        if request_id in self.executed_requests:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        self._require_ledger_configured()
        ledger = gl.get_contract_at(self.ledger_address)
        # "" — these requests were created without action parameters.
        res = ledger.view().check_authority(
            request_id, gl.message.sender_address, expected_capability, ""
        )
        if not res["authorized"]:
            raise gl.vm.UserError(str(res["reason"]))
        self.executed_requests[request_id] = True  # writes ONLY to own state

    # ------------------------------------------------------------------ #
    # Critical path: semantic authority (Ledger) + collective (guardians)
    # ------------------------------------------------------------------ #

    def _threshold_payload(self, new_threshold: int) -> str:
        return f"{CAP_CHANGE_THRESHOLD}:from={int(self.threshold)},to={int(new_threshold)}"

    @gl.public.view
    def canonical_threshold_payload(self, new_threshold: int) -> str:
        """Exact text to hash (sha256) into the request's action_params_hash and
        to show the AI in adjudicate_action. Depends on the CURRENT threshold."""
        return self._threshold_payload(new_threshold)

    def _check_critical_authority(self, request_id: str, actor, payload_hash: str) -> None:
        self._require_ledger_configured()
        res = gl.get_contract_at(self.ledger_address).view().check_authority(
            request_id, actor, CAP_CHANGE_THRESHOLD, payload_hash
        )
        if not res["authorized"]:
            raise gl.vm.UserError(str(res["reason"]))

    @gl.public.write
    def propose_critical_threshold_change(self, request_id: str, new_threshold: int) -> None:
        if request_id in self.executed_requests:
            raise gl.vm.UserError("ALREADY_EXECUTED")
        if new_threshold < 1 or new_threshold > self._active_guardian_count():
            raise gl.vm.UserError("BAD_THRESHOLD")
        if new_threshold == int(self.threshold):
            raise gl.vm.UserError("NO_CHANGE")
        # The TARGET computes the hash from real parameters, not from the proposer's word.
        payload_hash = hashlib.sha256(self._threshold_payload(new_threshold).encode()).hexdigest()
        self._check_critical_authority(request_id, gl.message.sender_address, payload_hash)
        self.executed_requests[request_id] = True  # one request = one proposal
        self.critical_actions[request_id] = CriticalAction(
            new_threshold=u256(new_threshold),
            proposer=gl.message.sender_address,
            payload_hash=payload_hash,
            approvals_csv="",
            expires_at=u64(_now() + CRITICAL_APPROVAL_WINDOW),
            executed=False,
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

        # Count only ACTIVE guardians (votes of removed ones don't count).
        live = sum(1 for k in done if self._is_active_guardian(k))
        if live >= int(self.threshold):
            self._finalize_critical(request_id)

    def _finalize_critical(self, request_id: str) -> None:
        a = self.critical_actions[request_id]
        # Target state must not have changed since the verdict was issued.
        current = hashlib.sha256(self._threshold_payload(int(a.new_threshold)).encode()).hexdigest()
        if current != a.payload_hash:
            raise gl.vm.UserError("STALE_ACTION")
        # Authority is re-checked AT application time: revocation / expired verdict.
        self._check_critical_authority(request_id, a.proposer, a.payload_hash)
        self.threshold = a.new_threshold
        a.executed = True

    @gl.public.view
    def get_critical_action(self, request_id: str) -> dict:
        if request_id not in self.critical_actions:
            raise gl.vm.UserError("NO_PROPOSAL")
        a = self.critical_actions[request_id]
        done = [k for k in a.approvals_csv.split(",") if k]
        return {
            "new_threshold": int(a.new_threshold),
            "proposer": a.proposer,
            "approvals": done,
            "approvals_count": len(done),
            "required": int(self.threshold),
            "expires_at": a.expires_at,
            "executed": a.executed,
        }

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

    # ------------------------------------------------------------------ #
    # Guardian fast path
    # ------------------------------------------------------------------ #

    def _is_active_guardian(self, key: str) -> bool:
        return key in self.guardians and bool(self.guardians[key])

    @gl.public.write
    def add_guardian(self, guardian: Address) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        key = _key(guardian)
        if key not in self.guardians:
            self.guardian_keys_csv = (self.guardian_keys_csv + "," + key) if self.guardian_keys_csv else key
        self.guardians[key] = True

    def _active_guardian_count(self) -> int:
        return sum(1 for k in self.guardian_keys_csv.split(",") if k and self._is_active_guardian(k))

    @gl.public.view
    def get_guardians(self) -> dict:
        active = [k for k in self.guardian_keys_csv.split(",") if k and self._is_active_guardian(k)]
        return {"guardians": active, "active_count": len(active), "threshold": int(self.threshold)}

    @gl.public.write
    def propose_threshold_change(self, new_threshold: int) -> str:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        # A threshold above the active guardian count would block the fast path forever.
        if new_threshold < 1 or new_threshold > self._active_guardian_count():
            raise gl.vm.UserError("BAD_THRESHOLD")

        proposal_id = hashlib.sha256(
            f"threshold:{new_threshold}:{gl.message_raw['datetime']}:{key}".encode()
        ).hexdigest()
        self.threshold_proposals[proposal_id] = ThresholdChangeProposal(
            new_threshold=u256(new_threshold),
            votes=u256(1),
            executed=False,
        )
        self.threshold_voters_of[proposal_id] = key
        self._maybe_execute_threshold_change(proposal_id)
        return proposal_id

    @gl.public.write
    def vote_threshold_change(self, proposal_id: str) -> None:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        if proposal_id not in self.threshold_proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.threshold_proposals[proposal_id]
        if p.executed:
            raise gl.vm.UserError("ALREADY_EXECUTED")

        voters_csv = self.threshold_voters_of[proposal_id]
        if f",{key}," in f",{voters_csv},":
            raise gl.vm.UserError("ALREADY_VOTED")
        self.threshold_voters_of[proposal_id] = voters_csv + "," + key
        p.votes += u256(1)
        self._maybe_execute_threshold_change(proposal_id)

    def _maybe_execute_threshold_change(self, proposal_id: str) -> None:
        p = self.threshold_proposals[proposal_id]
        # Strict majority of ACTIVE guardians; the owner has no vote here.
        active = self._active_guardian_count()
        if int(p.votes) * 2 > active and int(p.new_threshold) <= active:
            self.threshold = p.new_threshold
            p.executed = True

    @gl.public.view
    def get_threshold_proposal(self, proposal_id: str) -> dict:
        if proposal_id not in self.threshold_proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.threshold_proposals[proposal_id]
        return {
            "new_threshold": int(p.new_threshold),
            "votes": int(p.votes),
            "active_guardian_count": self._active_guardian_count(),
            "executed": p.executed,
        }

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

    @gl.public.write
    def propose_pause(self, justification_text: str) -> str:
        key = _key(gl.message.sender_address)
        if not self._is_active_guardian(key):
            raise gl.vm.UserError("NOT_GUARDIAN")
        bond = int(self.bonds[key]) if key in self.bonds else 0
        if bond < MIN_BOND:
            raise gl.vm.UserError("INSUFFICIENT_BOND")

        pause_id = hashlib.sha256(
            f"pause:{justification_text}:{gl.message_raw['datetime']}:{key}".encode()
        ).hexdigest()
        self.proposals[pause_id] = PauseProposal(
            justification_text=justification_text,
            signature_count=u256(1),
            executed=False,
            resolved=False,
            request_id="",
            paused_at_snapshot=u64(0),
        )
        self.signers_of[pause_id] = key
        self._bump_active_signed(key, +1)

        if u256(1) >= self.threshold:
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

        signers_csv = self.signers_of[pause_id]
        if f",{key}," in f",{signers_csv},":
            raise gl.vm.UserError("ALREADY_SIGNED")
        self.signers_of[pause_id] = signers_csv + "," + key
        p.signature_count += u256(1)
        self._bump_active_signed(key, +1)

        if p.signature_count >= self.threshold:
            self._execute_pause(pause_id)

    def _execute_pause(self, pause_id: str) -> None:
        p = self.proposals[pause_id]
        p.executed = True
        self.paused = True
        self.paused_at = u64(_now())
        p.paused_at_snapshot = self.paused_at
        # request_id is set by a SEPARATE tx, link_ratification_request():
        # the request is created externally, not written into another contract from here.

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
            raise gl.vm.UserError("NOT_A_SIGNER_OF_THIS_PAUSE")

        # The request must be about THIS pause — otherwise someone could attach
        # another approved IN_SCOPE verdict and bypass ratification/slashing.
        req = self._read_request(request_id)
        if req["capability"] != CAP_RATIFY_GUARDIAN_PAUSE:
            raise gl.vm.UserError("WRONG_CAPABILITY")
        expected_justification_hash = hashlib.sha256(p.justification_text.encode()).hexdigest()
        if req["justification_hash"] != expected_justification_hash:
            raise gl.vm.UserError("JUSTIFICATION_MISMATCH")

        p.request_id = request_id

    @gl.public.write
    def resolve_ratification(self, pause_id: str) -> None:
        if pause_id not in self.proposals:
            raise gl.vm.UserError("NO_PROPOSAL")
        p = self.proposals[pause_id]
        if not p.executed:
            raise gl.vm.UserError("NOT_EXECUTED")
        if p.resolved:
            raise gl.vm.UserError("ALREADY_RESOLVED")
        if p.request_id == "":
            raise gl.vm.UserError("NOT_LINKED")

        verdict = self._read_verdict(p.request_id)
        # Uncertainty must not slash immediately: allow one appeal (strict,
        # fail-closed), after the grace period uncertainty = refusal.
        if verdict["decision"] == "INCONCLUSIVE" and not bool(verdict["appealed"]):
            if _now() < int(p.paused_at_snapshot) + RATIFICATION_GRACE_SECONDS:
                raise gl.vm.UserError("AWAITING_APPEAL")

        p.resolved = True
        signer_keys = [s for s in self.signers_of[pause_id].split(",") if s]

        for key in signer_keys:
            self._bump_active_signed(key, -1)

        if verdict["decision"] == "IN_SCOPE":
            return  # pause stays, guardians were right — bonds untouched

        for key in signer_keys:
            bond = int(self.bonds[key]) if key in self.bonds else 0
            slashed = min(bond, SLASH_AMOUNT)
            self.bonds[key] = u256(bond - slashed)
            self.slashed_pending = u256(int(self.slashed_pending) + slashed)

        # Unpause ONLY if `paused` hasn't changed since THIS pause — otherwise a
        # long-stale resolve would wipe out someone else's legitimate pause.
        if self.paused_at == p.paused_at_snapshot:
            self.paused = False
            self.paused_at = u64(_now())

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
        # checks-effects-interactions: state first, then the transfer
        self.bonds[key] = u256(bond - amount)
        _Recipient(gl.message.sender_address).emit_transfer(value=u256(amount))

    @gl.public.write
    def set_slash_recipient(self, recipient: Address) -> None:
        """Owner only, once: who receives slashed bonds."""
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        if self.slash_recipient_set:
            raise gl.vm.UserError("SLASH_RECIPIENT_ALREADY_SET")
        addr = _coerce_address(recipient)
        if bytes(addr.as_bytes) == bytes(Address.SIZE):
            raise gl.vm.UserError("BAD_RECIPIENT")
        self.slash_recipient = addr
        self.slash_recipient_set = True

    @gl.public.write
    def sweep_slashed(self) -> None:
        """Callable by anyone: funds go ONLY to the configured recipient."""
        if not self.slash_recipient_set:
            raise gl.vm.UserError("SLASH_RECIPIENT_NOT_SET")
        amount = int(self.slashed_pending)
        if amount <= 0:
            raise gl.vm.UserError("NOTHING_TO_SWEEP")
        # checks-effects-interactions: zero the balance first, then transfer
        self.slashed_pending = u256(0)
        _Recipient(self.slash_recipient).emit_transfer(value=u256(amount))

    @gl.public.view
    def get_slash_info(self) -> dict:
        return {
            "recipient": self.slash_recipient.as_hex if self.slash_recipient_set else "",
            "pending": int(self.slashed_pending),
        }

    @gl.public.view
    def get_status(self) -> dict:
        return {"paused": self.paused, "paused_at": self.paused_at}

    # ------------------------------------------------------------------ #
    # Proof-path getters
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
            "justification_text": p.justification_text,
            "signature_count": int(p.signature_count),
            "threshold": int(self.threshold),
            "executed": p.executed,
            "resolved": p.resolved,
            "request_id": p.request_id,
            "paused_at_snapshot": p.paused_at_snapshot,
        }

    @gl.public.view
    def get_bond(self, guardian: Address) -> int:
        key = _key(guardian)
        return int(self.bonds[key]) if key in self.bonds else 0

    @gl.public.view
    def get_active_signed_count(self, guardian: Address) -> int:
        key = _key(guardian)
        return int(self.active_signed_count[key]) if key in self.active_signed_count else 0

    @gl.public.write
    def remove_guardian(self, guardian: Address) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("NOT_OWNER")
        key = _key(guardian)
        if key in self.guardians:
            self.guardians[key] = False
