"""Template-only spam checks.

The node mempool is not touched. A transaction that fails to parse is kept.
"""
from __future__ import annotations

import hashlib
from typing import Optional


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _read_varint(buf: bytes, off: int) -> tuple[int, int]:
    if off >= len(buf):
        raise ValueError("varint")
    n = buf[off]
    off += 1
    if n < 0xFD:
        return n, off
    if n == 0xFD:
        if off + 2 > len(buf):
            raise ValueError("varint")
        return int.from_bytes(buf[off:off + 2], "little"), off + 2
    if n == 0xFE:
        if off + 4 > len(buf):
            raise ValueError("varint")
        return int.from_bytes(buf[off:off + 4], "little"), off + 4
    raise ValueError("varint")


def _push_len(script: bytes, off: int) -> tuple[int, int]:
    if off >= len(script):
        raise ValueError("push")
    op = script[off]
    off += 1
    if 0 < op < 0x4C:
        return op, off
    if op == 0x4C:
        if off >= len(script):
            raise ValueError("push")
        return script[off], off + 1
    if op == 0x4D:
        if off + 2 > len(script):
            raise ValueError("push")
        return int.from_bytes(script[off:off + 2], "little"), off + 2
    if op == 0x4E:
        if off + 4 > len(script):
            raise ValueError("push")
        n = int.from_bytes(script[off:off + 4], "little")
        if n > 1_000_000:
            raise ValueError("push")
        return n, off + 4
    raise ValueError("not a push")


def _bytes_repeat(data: bytes) -> bool:
    if len(data) < 6:
        return False
    counts = [0] * 256
    run = 1
    for i, b in enumerate(data):
        counts[b] += 1
        if i and b == data[i - 1]:
            run += 1
            if run >= 6:
                return True
        else:
            run = 1
    return any(c >= 8 for c in counts)


def _program_is_data(script: bytes) -> bool:
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        prog = script[2:]
    elif len(script) == 34 and script[0] in (0x00, 0x51) and script[1] == 0x20:
        prog = script[2:]
    else:
        return False
    if not any(prog):
        return False
    return _bytes_repeat(prog)


def _payload_is_token(payload: bytes, flags: dict) -> bool:
    if flags.get("rejecttokenmessages") and len(payload) >= 4 and payload[:4] == b"omni":
        return True
    if flags.get("rejectcounterparty") and len(payload) >= 8 and payload[:8] == b"CNTRPRTY":
        return True
    if flags.get("rejectstamps") and len(payload) >= 6 and payload[:6] == b"stamp:":
        return True
    if flags.get("rejecttokenmessages") and len(payload) >= 8 and payload[0] == ord("{"):
        window = payload[:48]
        for i in range(1, len(window) - 3):
            if window[i:i + 4] == b'"p":':
                return True
    return False


def _script_spam(script: bytes, as_output: bool, flags: dict) -> Optional[str]:
    if flags.get("rejectrunestones") and len(script) >= 2 and script[0] == 0x6A and script[1] == 0x5D:
        return "runestone"
    if len(script) >= 2 and script[0] == 0x6A:
        try:
            off = 1
            push, off = _push_len(script, off)
            if off + push <= len(script) and _payload_is_token(script[off:off + push], flags):
                return "token"
        except ValueError:
            return None
        if flags.get("datacarrier") is False:
            return "datacarrier"
        limit = flags.get("datacarriersize")
        if isinstance(limit, int) and limit >= 0:
            try:
                off = 1
                total = 0
                while off < len(script):
                    push, off = _push_len(script, off)
                    total += push
                    off += push
                if total > limit:
                    return "datacarriersize"
            except ValueError:
                return None
    if flags.get("rejectfakeoutputs") and _program_is_data(script):
        return "fakeoutput"
    if flags.get("permitbarepubkey") is False and as_output and len(script) in (35, 67):
        if script[0] in (0x21, 0x41) and script[-1] == 0xAC and script[0] == len(script) - 2:
            return "barepubkey"
    off = 0
    keys = 0
    only_pushes = True
    try:
        while off < len(script):
            op = script[off]
            if 0 < op <= 0x4E:
                push, off = _push_len(script, off)
                if push == 33:
                    keys += 1
                if off + push > len(script):
                    return None
                off += push
                continue
            off += 1
            if op in (0x75, 0x6D) and only_pushes and flags.get("rejectbareenvelopes"):
                return "bareenvelope"
            if op in (0xAE, 0xAF) and flags.get("rejectfakemultisig"):
                if as_output or keys > 10:
                    return "fakemultisig"
            if flags.get("permitbaremultisig") is False and op in (0xAE, 0xAF) and as_output:
                return "baremultisig"
            if op != 0x00 and not (0x51 <= op <= 0x60):
                only_pushes = False
            if flags.get("rejectdeadbranches") and op == 0x64 and off >= 2 and script[off - 2] == 0x51:
                return "deadbranch"
            if flags.get("rejectdeadbranches") and op == 0x63 and off >= 2 and script[off - 2] == 0x00:
                return "deadbranch"
    except ValueError:
        return None
    return None


def _dust_threshold(script: bytes, sat_per_kvb: int) -> int:
    if not script or script[0] == 0x6A:
        return 0
    n_size = 8 + (1 if len(script) < 0xFD else 3) + len(script)
    witness = (
        (len(script) in (22, 34) and script[0] in (0x00, 0x51))
    )
    if witness:
        n_size += 32 + 4 + 1 + (107 // 4) + 4
    else:
        n_size += 32 + 4 + 1 + 107 + 4
    fee = sat_per_kvb * n_size // 1000
    if fee == 0 and sat_per_kvb > 0:
        fee = 1
    return fee


def tx_reject_reason(raw: bytes, flags: dict) -> Optional[str]:
    """Return a short reason to drop this tx, or None to keep it."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        segwit = off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01
        if segwit:
            off += 2
        vin, off = _read_varint(raw, off)
        input_scripts = []
        for _ in range(vin):
            off += 36
            slen, off = _read_varint(raw, off)
            script = raw[off:off + slen]
            input_scripts.append(script)
            off += slen + 4
        vout, off = _read_varint(raw, off)
        outputs = []
        p2wsh_same = 0
        p2wsh_value = None
        for _ in range(vout):
            value = int.from_bytes(raw[off:off + 8], "little")
            off += 8
            slen, off = _read_varint(raw, off)
            script = raw[off:off + slen]
            off += slen
            outputs.append((value, script))
            reason = _script_spam(script, True, flags)
            if reason:
                return reason
            if (
                flags.get("rejectfakeoutputs")
                and len(script) == 34
                and script[0] == 0x00
                and script[1] == 0x20
                and value <= 546
            ):
                if p2wsh_value is None or value == p2wsh_value:
                    p2wsh_value = value
                    p2wsh_same += 1
        if flags.get("rejectfakeoutputs") and p2wsh_same >= 3:
            return "fakeoutput"
        dust_rate = flags.get("dust_sat_per_kvb")
        if isinstance(dust_rate, int) and dust_rate > 0:
            for value, script in outputs:
                if value < _dust_threshold(script, dust_rate):
                    return "dust"
        lock_off = off
        if segwit:
            for _ in range(vin):
                stack_n, off = _read_varint(raw, off)
                for _k in range(stack_n):
                    item_len, off = _read_varint(raw, off)
                    item = raw[off:off + item_len]
                    off += item_len
                    reason = _script_spam(item, False, flags)
                    if reason:
                        return reason
            lock_off = off
        for script in input_scripts:
            reason = _script_spam(script, False, flags)
            if reason:
                return reason
        if flags.get("rejectparasites") and lock_off + 4 <= len(raw):
            locktime = int.from_bytes(raw[lock_off:lock_off + 4], "little")
            if locktime == 21:
                return "parasite"
    except (ValueError, IndexError):
        return None
    return None


def witness_commitment_hex(wtxid_hexes: list[str]) -> str:
    """BIP141 commitment for a coinbase whose witness reserved value is 32 zeros.

    wtxid hex strings are the getblocktemplate display order. The merkle uses
    the reversed bytes, then SHA256d(root || 32 zero bytes).
    """
    level = [b"\x00" * 32]
    for hx in wtxid_hexes:
        raw = bytes.fromhex(hx)
        level.append(raw[::-1])
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    commit = _sha256d(level[0] + (b"\x00" * 32))
    return "6a24aa21a9ed" + commit.hex()
