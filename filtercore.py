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
                if flags.get("datacarrierfullcount"):
                    total = max(0, len(script) - 1)
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
            if flags.get("rejecttokens") and op == 0x63 and off >= 2 and script[off - 2] == 0x00 and b"\x03ord" in script[:80]:
                return "token"
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


def _is_taproot_control_block(item: bytes) -> bool:
    """BIP341 tapscript control block: 33 + 32*n bytes, leaf version 0xc0."""
    if len(item) < 33 or (len(item) - 33) % 32:
        return False
    return (item[0] & 0xFE) == 0xC0


def _witness_script(items: list[bytes]) -> Optional[bytes]:
    """The witness item that is a script, or None when the witness has no script.

    Signatures and public keys are not scripts. Parsing them flags ordinary
    spends when those bytes happen to contain OP_DROP or OP_0 OP_IF.
    """
    if not items:
        return None
    stack = items
    if stack[-1][:1] == b"\x50":
        stack = stack[:-1]
    if not stack:
        return None
    if len(stack) >= 2 and _is_taproot_control_block(stack[-1]):
        return stack[-2]
    if len(stack) == 1:
        # A lone 64 or 65 byte item is a Taproot key-path signature.
        if len(stack[0]) in (64, 65):
            return None
        return stack[0]
    if len(stack) == 2 and len(stack[1]) in (33, 65):
        # P2WPKH, and P2SH-P2WPKH: signature then pubkey.
        return None
    return stack[-1]


def _legacy_sigops(script: bytes) -> int:
    count = 0
    off = 0
    while off < len(script):
        op = script[off]
        if 0 < op <= 0x4E:
            push, off = _push_len(script, off)
            off += push
            continue
        off += 1
        if op in (0xAC, 0xAD):
            count += 1
        elif op in (0xAE, 0xAF):
            count += 20
    return count


def _datacarrier_bytes(script: bytes, fullcount: bool) -> int:
    if not script or script[0] != 0x6A:
        return 0
    if fullcount:
        return max(0, len(script) - 1)
    total = 0
    off = 1
    while off < len(script):
        push, off = _push_len(script, off)
        total += push
        off += push
    return total


CONSENSUS_MAX_BLOCK_WEIGHT = 4_000_000
CONSENSUS_MAX_BLOCK_SIGOPS = 80_000
ANCHOR_SCRIPT = bytes.fromhex("51024e73")


def clamp_template_request(req: dict, flags: dict) -> dict:
    """Copy Knots block limits onto the template request, never above consensus."""
    out = dict(req)
    weight = flags.get("blockmaxweight")
    if isinstance(weight, int) and weight > 0:
        out["blockmaxweight"] = min(weight, CONSENSUS_MAX_BLOCK_WEIGHT)
    size = flags.get("blockmaxsize")
    if isinstance(size, int) and size > 0:
        out["blockmaxsize"] = min(size, CONSENSUS_MAX_BLOCK_WEIGHT)
    reserved_weight = flags.get("blockreservedweight")
    if isinstance(reserved_weight, int) and reserved_weight >= 0:
        cap = out.get("blockmaxweight", CONSENSUS_MAX_BLOCK_WEIGHT)
        out["blockreservedweight"] = min(reserved_weight, cap)
    reserved_size = flags.get("blockreservedsize")
    if isinstance(reserved_size, int) and reserved_size >= 0:
        cap = out.get("blockmaxsize", CONSENSUS_MAX_BLOCK_WEIGHT)
        out["blockreservedsize"] = min(reserved_size, cap)
    reserved_sigops = flags.get("blockreservedsigops")
    if isinstance(reserved_sigops, int) and reserved_sigops >= 0:
        out["blockreservedsigops"] = min(reserved_sigops, CONSENSUS_MAX_BLOCK_SIGOPS)
    return out


def tx_reject_reason(raw: bytes, flags: dict, fee: int | None = None, weight: int | None = None, sigops: int | None = None) -> Optional[str]:
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
                if flags.get("permitephemeral") is True and value == 0 and script == ANCHOR_SCRIPT:
                    continue
                if value < _dust_threshold(script, dust_rate):
                    return "dust"
        witness_scripts = []
        lock_off = off
        if segwit:
            for _ in range(vin):
                stack_n, off = _read_varint(raw, off)
                items = []
                for _k in range(stack_n):
                    item_len, off = _read_varint(raw, off)
                    items.append(raw[off:off + item_len])
                    off += item_len
                script = _witness_script(items)
                if script is not None:
                    witness_scripts.append(script)
                    reason = _script_spam(script, False, flags)
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
        scripts = [script for _value, script in outputs] + input_scripts + witness_scripts
        limit = flags.get("maxscriptsize")
        if isinstance(limit, int) and limit >= 0:
            for script in scripts:
                if len(script) > limit:
                    return "scriptsize"
        legacy_limit = flags.get("maxtxlegacysigops")
        if isinstance(legacy_limit, int) and legacy_limit >= 0:
            legacy = sum(_legacy_sigops(script) for script in input_scripts)
            legacy += sum(_legacy_sigops(script) for _value, script in outputs)
            if legacy > legacy_limit:
                return "legacysigops"
        if flags.get("permitbaredatacarrier") is False and outputs and all(script[:1] == b"\x6a" for _value, script in outputs):
            return "baredatacarrier"
        if flags.get("permitbareanchor") is False and outputs and all(script == ANCHOR_SCRIPT for _value, script in outputs):
            return "bareanchor"
        per_sigop = flags.get("bytespersigop")
        if isinstance(per_sigop, int) and per_sigop > 0 and isinstance(sigops, int) and sigops > 0:
            vsize = max(1, int(weight) // 4) if isinstance(weight, int) and weight > 0 else len(raw)
            if vsize < sigops * per_sigop:
                return "bytespersigop"
        cost = flags.get("datacarriercost")
        rate = flags.get("minfeerate_sat_vb")
        if isinstance(cost, int) and cost > 0 and isinstance(rate, (int, float)) and isinstance(fee, int) and isinstance(weight, int):
            data_bytes = sum(_datacarrier_bytes(script, bool(flags.get("datacarrierfullcount"))) for _value, script in outputs)
            if data_bytes:
                effective_vsize = (weight + data_bytes * cost) / 4
                if fee < rate * effective_vsize:
                    return "datacarriercost"
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


# Knots default -blockreservedweight. The coinbase has to fit under weightlimit.
COINBASE_RESERVE_WEIGHT = 8000


def weight_ceiling(weightlimit: int, reserve: int = COINBASE_RESERVE_WEIGHT) -> int:
    if weightlimit <= reserve:
        return 0
    return weightlimit - reserve


def tx_vsize_bytes(tx: dict) -> int:
    data = tx.get("data")
    if isinstance(data, str):
        return len(data) // 2
    return 0


def tx_input_outpoints(raw: bytes) -> list[tuple[bytes, int]] | None:
    """Prevouts this transaction spends. None when the raw tx cannot be read."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        if off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01:
            off += 2
        vin, off = _read_varint(raw, off)
        points = []
        for _ in range(vin):
            if off + 36 > len(raw):
                return None
            prev = raw[off:off + 32]
            vout = int.from_bytes(raw[off + 32:off + 36], "little")
            off += 36
            slen, off = _read_varint(raw, off)
            if off + slen + 4 > len(raw):
                return None
            off += slen + 4
            points.append((prev, vout))
        return points
    except (ValueError, IndexError):
        return None


def _template_outpoints(tx: dict) -> list[tuple[bytes, int]] | None:
    data = tx.get("data")
    if not isinstance(data, str) or not data:
        return None
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        return None
    return tx_input_outpoints(raw)


def take_refill(
    kept: list,
    candidates: list,
    ceiling: int,
    banned: set,
    size_ceiling: int | None = None,
    sigop_ceiling: int | None = None,
) -> list:
    """Append candidates that pass the first filter's ban and still fit.

    `candidates` are in the node's order. A candidate is skipped when it was
    filtered, when a parent is missing, when it would pass a block limit, or
    when it spends an input already spent by a transaction in the template.
    The second snapshot can contain a higher-fee replacement of a payment the
    first snapshot already kept. Both must not be in the block.
    """
    have = {tx["txid"] for tx in kept}
    out = list(kept)
    spent: set[tuple[bytes, int]] = set()
    for tx in kept:
        points = _template_outpoints(tx)
        if points:
            spent.update(points)
    total = sum(int(tx["weight"]) for tx in kept)
    total_size = sum(tx_vsize_bytes(tx) for tx in kept)
    total_sigops = sum(int(tx.get("sigops") or 0) for tx in kept)
    for tx in candidates:
        txid = tx["txid"]
        if txid in have or txid in banned:
            continue
        parents = tx.get("depends_txids") or []
        if any(parent not in have for parent in parents):
            continue
        points = _template_outpoints(tx)
        if points is None and isinstance(tx.get("data"), str) and tx.get("data"):
            continue
        if points and any(point in spent for point in points):
            print(f"refill skipped {txid} spent input already in the template", flush=True)
            continue
        weight = int(tx["weight"])
        size = tx_vsize_bytes(tx)
        sigops = int(tx.get("sigops") or 0)
        if total + weight > ceiling:
            continue
        if size_ceiling is not None and total_size + size > size_ceiling:
            continue
        if sigop_ceiling is not None and total_sigops + sigops > sigop_ceiling:
            continue
        out.append(tx)
        have.add(txid)
        if points:
            spent.update(points)
        total += weight
        total_size += size
        total_sigops += sigops
    return out
