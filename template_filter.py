#!/usr/bin/env python3
"""JSON-RPC proxy that filters a getblocktemplate answer.

Point a gateway's bitcoind.rpcurl at listen. The proxy forwards every call
to upstream and, for a template request, removes matching transactions.
submitblock and the tip poll pass through unchanged. If a filtered template
cannot be rebuilt safely, the node's original answer is returned.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from filtercore import clamp_template_request, take_refill, tx_reject_reason, weight_ceiling, witness_commitment_hex

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("TEMPLATE_FILTER_CONFIG", ROOT / "config.json"))
RESTORE_PATH = ROOT / "run" / "priority-restore.json"
COINBASE_SIZE_RESERVE = 1000
COINBASE_SIGOP_RESERVE = 400
_state_lock = threading.Lock()
_priority_lock = threading.Lock()
_best: dict[tuple, dict] = {}
_inflight: set[tuple] = set()
_settled: set[tuple] = set()


def load_config() -> dict:
    cfg = json.loads(CONFIG_PATH.read_text())
    if "profiles" not in cfg:
        cfg = {
            "upstream": cfg["upstream"],
            "profiles": [{
                "name": "default",
                "listen": cfg["listen"],
                "filters": cfg.get("filters") or {},
            }],
        }
    for profile in cfg["profiles"]:
        profile.setdefault("filters", {})
        profile.setdefault("name", profile.get("listen", "profile"))
    return cfg


def _rpc(url: str, body: bytes, headers: dict, timeout: float) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("Content-Type", "application/json")


def _augment_request(payload: dict, flags: dict) -> dict:
    params = payload.get("params")
    if not isinstance(params, list) or not params or not isinstance(params[0], dict):
        return payload
    req = dict(params[0])
    if req.get("mode") == "proposal":
        return payload
    if isinstance(flags.get("minfeerate_sat_vb"), (int, float)):
        req["minfeerate"] = flags["minfeerate_sat_vb"]
    req = clamp_template_request(req, flags)
    out = dict(payload)
    out["params"] = [req] + list(params[1:])
    return out


def _filter_template(result: dict, flags: dict) -> tuple[dict, dict]:
    txs = result.get("transactions")
    if not isinstance(txs, list):
        raise ValueError("template has no transactions")
    original_commit = result.get("default_witness_commitment")
    if not (isinstance(original_commit, str) and original_commit.startswith("6a24aa21a9ed") and len(original_commit) == 76):
        raise ValueError("template witness commitment is not the 38-byte form")

    drop = [False] * len(txs)
    reasons: dict[str, int] = {}
    for i, tx in enumerate(txs):
        data = tx.get("data")
        if not isinstance(data, str):
            continue
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            continue
        reason = tx_reject_reason(
            raw,
            flags,
            fee=tx.get("fee") if isinstance(tx.get("fee"), int) else None,
            weight=tx.get("weight") if isinstance(tx.get("weight"), int) else None,
            sigops=tx.get("sigops") if isinstance(tx.get("sigops"), int) else None,
        )
        if reason:
            drop[i] = True
            reasons[reason] = reasons.get(reason, 0) + 1
    changed = True
    while changed:
        changed = False
        for i, tx in enumerate(txs):
            if drop[i]:
                continue
            deps = tx.get("depends") or []
            if not isinstance(deps, list):
                continue
            for parent in deps:
                if isinstance(parent, int) and 1 <= parent <= len(txs) and drop[parent - 1]:
                    drop[i] = True
                    reasons["depends"] = reasons.get("depends", 0) + 1
                    changed = True
                    break
    if not any(drop):
        return result, {"dropped": 0, "reasons": {}}

    kept = []
    new_index = {}
    fee_dropped = 0
    for i, tx in enumerate(txs):
        if drop[i]:
            fee = tx.get("fee")
            if not isinstance(fee, int):
                raise ValueError("dropped transaction has no integer fee")
            fee_dropped += fee
            continue
        new_index[i + 1] = len(kept) + 1
        kept.append(tx)
    for tx in kept:
        deps = tx.get("depends") or []
        if isinstance(deps, list):
            tx["depends"] = [new_index[d] for d in deps if isinstance(d, int) and d in new_index]
    value = result.get("coinbasevalue")
    if not isinstance(value, int) or fee_dropped > value:
        raise ValueError("coinbase value would underflow")
    wtxids = []
    for tx in kept:
        hx = tx.get("hash") or tx.get("txid")
        if not isinstance(hx, str) or len(hx) != 64:
            raise ValueError("kept transaction has no wtxid")
        wtxids.append(hx)
    commit = witness_commitment_hex(wtxids)
    out = dict(result)
    out["transactions"] = kept
    out["coinbasevalue"] = value - fee_dropped
    out["default_witness_commitment"] = commit
    return out, {"dropped": len(txs) - len(kept), "fee_sats": fee_dropped, "reasons": reasons, "kept": len(kept)}


def _template_weight(result: dict) -> int:
    return sum(int(tx.get("weight") or 0) for tx in result.get("transactions") or [])


def _choose_template(name: str, prevhash: str | None, filtered: dict) -> dict:
    if not prevhash:
        return filtered
    with _state_lock:
        best = _best.get((name, prevhash))
    if best is None or _template_weight(best) < _template_weight(filtered):
        return filtered
    return best


def _with_fresh_clock(served: dict, fresh: dict) -> dict:
    """Put Knots' current curtime on a saved template.

    The saved list keeps its transactions. The gateway copies curtime into
    the header, so a saved template has to carry the clock from the template
    Knots just built. A later clock stays valid for the same transactions.
    """
    if served is fresh:
        return served
    try:
        fresh_time = int(fresh.get("curtime") or 0)
        saved_time = int(served.get("curtime") or 0)
    except (TypeError, ValueError):
        return served
    if fresh_time <= saved_time:
        return served
    out = dict(served)
    out["curtime"] = fresh_time
    return out


def _rpc_call(url: str, auth: str | None, method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "1.0", "id": "refill", "method": method, "params": params}).encode()
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    status, raw, _ctype = _rpc(url, body, headers, 180)
    if status != 200:
        raise RuntimeError(f"upstream status {status}")
    msg = json.loads(raw.decode("utf-8"))
    if msg.get("error"):
        raise RuntimeError(str(msg["error"])[:200])
    return msg.get("result")


def _write_restore(deltas: list[tuple[str, int]]) -> None:
    RESTORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESTORE_PATH.write_text(json.dumps([{"txid": txid, "delta": delta} for txid, delta in deltas]))


def _clear_restore() -> None:
    RESTORE_PATH.unlink(missing_ok=True)


def _restore_deltas(url: str, auth: str | None, deltas: list[tuple[str, int]]) -> None:
    for txid, delta in deltas:
        _rpc_call(url, auth, "prioritisetransaction", [txid, 0, -delta])
    _clear_restore()


def _restore_file(url: str, auth: str | None) -> None:
    if not RESTORE_PATH.exists():
        return
    try:
        saved = json.loads(RESTORE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return
    deltas = [(item["txid"], int(item["delta"])) for item in saved if item.get("txid")]
    if deltas:
        _restore_deltas(url, auth, deltas)
        print(f"restored {len(deltas)} set-aside transactions from the last run", flush=True)


def _candidates(second: dict, flags: dict, banned: set[str], have: set[str]) -> tuple[list, int]:
    ids = [tx["txid"] for tx in second.get("transactions") or []]
    fresh = []
    skipped = 0
    for tx in second.get("transactions") or []:
        if tx["txid"] in have or tx["txid"] in banned:
            continue
        parents = []
        for dep in tx.get("depends") or []:
            if isinstance(dep, int) and 1 <= dep <= len(ids):
                parents.append(ids[dep - 1])
        try:
            raw = bytes.fromhex(tx["data"])
        except (ValueError, TypeError):
            skipped += 1
            continue
        if tx_reject_reason(raw, flags):
            skipped += 1
            continue
        item = dict(tx)
        item["depends_txids"] = parents
        fresh.append(item)
    return fresh, skipped


def _assemble(base: dict, transactions: list, source: list) -> dict | None:
    source_fee = sum(int(tx.get("fee") or 0) for tx in source)
    final_fee = sum(int(tx.get("fee") or 0) for tx in transactions)
    value = int(base["coinbasevalue"]) - source_fee + final_fee
    if value < 0:
        return None
    index = {tx["txid"]: i + 1 for i, tx in enumerate(transactions)}
    cleaned = []
    for tx in transactions:
        item = dict(tx)
        parents = item.pop("depends_txids", None)
        if parents is not None:
            item["depends"] = [index[parent] for parent in parents if parent in index]
        cleaned.append(item)
    out = dict(base)
    out["transactions"] = cleaned
    out["coinbasevalue"] = value
    out["default_witness_commitment"] = witness_commitment_hex(
        [tx.get("hash") or tx["txid"] for tx in cleaned]
    )
    return out


def _refill_round(url: str, auth: str | None, dropped: list[dict]) -> dict | None:
    deltas: list[tuple[str, int]] = []
    with _priority_lock:
        try:
            _restore_file(url, auth)
            for tx in dropped:
                delta = -(int(tx.get("fee") or 0) + 1)
                _rpc_call(url, auth, "prioritisetransaction", [tx["txid"], 0, delta])
                deltas.append((tx["txid"], delta))
            _write_restore(deltas)
            time.sleep(6)
            second = _rpc_call(url, auth, "getblocktemplate", [{"rules": ["segwit", "blake2b"]}])
            return second if isinstance(second, dict) else None
        finally:
            if deltas:
                try:
                    _restore_deltas(url, auth, deltas)
                except Exception as exc:
                    print(f"refill restore failed: {exc}", flush=True)


def _refill_worker(cfg: dict, auth: str | None, filtered: dict, original: dict, flags: dict, key: tuple) -> None:
    name, prevhash, _kept_key = key
    settled = False
    try:
        current = filtered
        banned = {
            tx["txid"]
            for tx in original.get("transactions") or []
            if tx["txid"] not in {item["txid"] for item in current["transactions"]}
        }
        ceilings_weight = weight_ceiling(int(original.get("weightlimit") or 0))
        size_ceiling = None
        sigop_ceiling = None
        if isinstance(original.get("sizelimit"), int):
            size_ceiling = max(0, original["sizelimit"] - COINBASE_SIZE_RESERVE)
        if isinstance(original.get("sigoplimit"), int):
            sigop_ceiling = max(0, original["sigoplimit"] - COINBASE_SIGOP_RESERVE)
        for _round in range(3):
            if not banned:
                settled = True
                break
            second = _refill_round(cfg["upstream"], auth, [
                tx for tx in original.get("transactions") or [] if tx["txid"] in banned
            ])
            if not isinstance(second, dict):
                break
            if second.get("previousblockhash") != prevhash:
                print(f"refill tip moved on {name}; stopping", flush=True)
                settled = True
                break
            have = {tx["txid"] for tx in current["transactions"]}
            candidates, skipped = _candidates(second, flags, banned, have)
            fresh_ids = {tx["txid"] for tx in candidates}
            for tx in second.get("transactions") or []:
                txid = tx.get("txid")
                if txid and txid not in have and txid not in banned and txid not in fresh_ids:
                    banned.add(txid)
            filled_txs = take_refill(
                current["transactions"],
                candidates,
                ceilings_weight,
                banned,
                size_ceiling,
                sigop_ceiling,
            )
            added = len(filled_txs) - len(current["transactions"])
            print(
                f"refill height {original.get('height')} profile {name} "
                f"new {len(candidates)} filtered {skipped} added {added}",
                flush=True,
            )
            if added <= 0:
                settled = True
                break
            assembled = _assemble(original, filled_txs, original.get("transactions") or [])
            if assembled is None or _template_weight(assembled) > ceilings_weight:
                break
            # The gateway only receives this list after the node has accepted it.
            verdict = _proposal(assembled)
            n_tx = len(assembled.get("transactions") or [])
            if verdict not in ("ok", "null", ""):
                print(
                    f"refill height {original.get('height')} profile {name} "
                    f"node rejected txs {n_tx}: {verdict}",
                    flush=True,
                )
                settled = True
                break
            print(
                f"refill height {original.get('height')} profile {name} "
                f"node accepted txs {n_tx}",
                flush=True,
            )
            _publish(name, prevhash, assembled)
            current = assembled
            if _template_weight(assembled) >= ceilings_weight:
                settled = True
                break
    except Exception as exc:
        print(f"refill failed: {exc}", flush=True)
        traceback.print_exc()
    finally:
        with _state_lock:
            _inflight.discard(key)
            if settled:
                _settled.add(key)


def _publish(name: str, prevhash: str, template: dict) -> None:
    with _state_lock:
        stale = [item for item in _best if item[0] == name and item[1] != prevhash]
        for item in stale:
            _best.pop(item, None)
        previous = _best.get((name, prevhash))
        if previous is None or _template_weight(template) >= _template_weight(previous):
            _best[(name, prevhash)] = template


def _schedule_refill(cfg: dict, headers: dict, filtered: dict, original: dict, flags: dict) -> None:
    prevhash = original.get("previousblockhash")
    name = cfg.get("name") or ""
    auth = headers.get("Authorization")
    if not isinstance(prevhash, str) or not auth:
        return
    kept_ids = {tx["txid"] for tx in filtered.get("transactions") or []}
    dropped = [tx for tx in original.get("transactions") or [] if tx.get("txid") not in kept_ids]
    if not dropped:
        return
    key = (name, prevhash, tuple(tx["txid"] for tx in filtered.get("transactions") or []))
    with _state_lock:
        if key in _inflight or key in _settled:
            return
        _inflight.add(key)
    threading.Thread(
        target=_refill_worker,
        args=(cfg, auth, filtered, original, flags, key),
        daemon=True,
    ).start()


def handle_rpc(body: bytes, headers: dict, cfg: dict) -> tuple[int, bytes, str]:
    flags = cfg.get("filters") or {}
    timeout = 30
    payload = None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        payload = None
    method = payload.get("method") if isinstance(payload, dict) else None
    if method == "getblocktemplate":
        timeout = 180
        mode = None
        params = payload.get("params") if isinstance(payload, dict) else None
        if isinstance(params, list) and params and isinstance(params[0], dict):
            mode = params[0].get("mode")
        if mode != "proposal":
            payload = _augment_request(payload, flags)
            body = json.dumps(payload).encode()
    fwd_headers = {"Content-Type": headers.get("Content-Type", "application/json")}
    if headers.get("Authorization"):
        fwd_headers["Authorization"] = headers["Authorization"]
    status, raw, ctype = _rpc(cfg["upstream"], body, fwd_headers, timeout)
    if method != "getblocktemplate" or status != 200:
        return status, raw, ctype
    try:
        msg = json.loads(raw.decode("utf-8"))
        result = msg.get("result")
        if not isinstance(result, dict) or result.get("transactions") is None:
            return status, raw, ctype
        # Proposal results are a string or null, not a template object.
        if "coinbasevalue" not in result:
            return status, raw, ctype
        new_result, info = _filter_template(result, flags)
        served = _choose_template(cfg.get("name") or "", result.get("previousblockhash"), new_result)
        served = _with_fresh_clock(served, new_result)
        msg["result"] = served
        if served is not new_result:
            print(
                f"height {result.get('height')} refill served "
                f"txs {len(served.get('transactions') or [])} "
                f"weight {_template_weight(served)} curtime {served.get('curtime')}",
                flush=True,
            )
        elif info.get("dropped"):
            print(
                f"height {result.get('height')} dropped {info['dropped']} "
                f"kept {info['kept']} fee_sats {info['fee_sats']} {info['reasons']}",
                flush=True,
            )
        _schedule_refill(cfg, headers, new_result, result, flags)
        return status, json.dumps(msg).encode(), ctype
    except Exception as exc:
        print(f"filter fail-open: {exc}", flush=True)
        traceback.print_exc()
        return status, raw, ctype
    return status, raw, ctype


def _profile(cfg: dict, name: str | None = None) -> dict:
    profiles = cfg["profiles"]
    if name:
        for profile in profiles:
            if profile.get("name") == name:
                return profile
    return profiles[0]


def check(cfg: dict) -> int:
    """Prove the witness formula, then proposal-check a filtered template.

    The node login is read from the environment for this one call. It is not
    written to disk and it is not printed.
    """
    import base64
    import os
    user = os.environ.get("TEMPLATE_FILTER_RPC_USER", "")
    password = os.environ.get("TEMPLATE_FILTER_RPC_PASSWORD", "")
    if not user or not password:
        print("Set TEMPLATE_FILTER_RPC_USER and TEMPLATE_FILTER_RPC_PASSWORD to run --check.")
        return 1
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    body = json.dumps({
        "jsonrpc": "1.0",
        "id": "check",
        "method": "getblocktemplate",
        "params": [{"rules": ["segwit", "blake2b"]}],
    }).encode()
    status, raw, _ = _rpc(cfg["upstream"], body, {"Authorization": "Basic " + auth, "Content-Type": "application/json"}, 120)
    if status != 200:
        print(f"upstream status {status}")
        return 1
    result = json.loads(raw.decode())["result"]
    wtxids = [tx.get("hash") or tx["txid"] for tx in result["transactions"]]
    got = witness_commitment_hex(wtxids)
    node = result["default_witness_commitment"]
    print(f"unfiltered height {result['height']} txs {len(wtxids)} commitment_match {got == node}")
    if got != node:
        print("formula does not match the node; proxy will fail open rather than serve this")
        return 1
    profile = _profile(cfg, "strict")
    filtered, info = _filter_template(result, profile.get("filters") or {})
    print(
        f"profile {profile.get('name')} dropped {info.get('dropped', 0)} "
        f"reasons {info.get('reasons', {})} coinbase {filtered['coinbasevalue']}"
    )
    if info.get("dropped"):
        again = witness_commitment_hex([tx.get("hash") or tx["txid"] for tx in filtered["transactions"]])
        print(f"rebuilt_commitment_stable {again == filtered['default_witness_commitment']}")
        verdict = _proposal(filtered)
        print(f"proposal {verdict}")
        if verdict not in ("ok", "null", ""):
            return 1
    return 0


def _sha256d(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _merkle(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    if not level:
        return b"\x00" * 32
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _proposal(template: dict) -> str:
    """Ask the node if this filtered template would make a valid block, apart from proof of work."""
    import struct
    import subprocess

    height = int(template["height"])
    value = int(template["coinbasevalue"])
    commit = bytes.fromhex(template["default_witness_commitment"])
    h = height.to_bytes(4, "little").rstrip(b"\x00") or b"\x00"
    script = bytes([len(h)]) + h
    pay = b"\x00\x14" + b"\x11" * 20
    nw = b"\x01\x00\x00\x00" + b"\x01" + (b"\x00" * 32) + b"\xff\xff\xff\xff"
    nw += bytes([len(script)]) + script + b"\xff\xff\xff\xff" + b"\x02"
    nw += value.to_bytes(8, "little") + bytes([len(pay)]) + pay
    nw += (0).to_bytes(8, "little") + bytes([len(commit)]) + commit
    nw += b"\x00\x00\x00\x00"
    witnessed = nw[:4] + b"\x00\x01" + nw[4:-4] + b"\x01\x20" + (b"\x00" * 32) + nw[-4:]
    cb_txid = _sha256d(nw)
    txids = [cb_txid]
    raws = []
    for tx in template["transactions"]:
        txids.append(bytes.fromhex(tx["txid"])[::-1])
        raws.append(bytes.fromhex(tx["data"]))
    header = bytearray(164)
    struct.pack_into("<I", header, 0, int(template.get("version") or 0x20000000) | 0x80000000)
    header[4:36] = bytes.fromhex(template["previousblockhash"])[::-1]
    header[36:68] = _merkle(txids)
    struct.pack_into("<I", header, 68, int(template["curtime"]))
    struct.pack_into("<I", header, 72, int(template["bits"], 16))
    struct.pack_into("<H", header, 108, len(raws) + 1)
    struct.pack_into("<I", header, 128, height)
    count = len(raws) + 1
    if count < 0xFD:
        varint = bytes([count])
    elif count <= 0xFFFF:
        varint = b"\xfd" + struct.pack("<H", count)
    else:
        varint = b"\xfe" + struct.pack("<I", count)
    block = bytes(header) + varint + witnessed + b"".join(raws)
    payload = json.dumps({
        "mode": "proposal",
        "data": block.hex(),
        "rules": ["segwit", "blake2b"],
    }).encode()
    proc = subprocess.run(
        ["sudo", "-n", "docker", "exec", "-i", "knots-local", "bitcoin-cli", "-datadir=/home/bitcoin/.bitcoin", "-stdin", "getblocktemplate"],
        input=payload, capture_output=True, timeout=120,
    )
    out = (proc.stdout or b"").decode().strip()
    err = (proc.stderr or b"").decode().strip()
    if proc.returncode == 0 and out in ("", "null"):
        return "ok"
    return (err or out or f"rc {proc.returncode}")[:300]


def make_handler(profile_cfg: dict):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            return

        def do_GET(self) -> None:
            if self.path not in ("/", "/health"):
                self.send_error(404)
                return
            flags = profile_cfg.get("filters") or {}
            body = json.dumps({
                "ok": True,
                "name": profile_cfg.get("name"),
                "listen": profile_cfg.get("listen"),
                "upstream": profile_cfg.get("upstream"),
                "filters": flags,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()}
            try:
                status, raw, ctype = handle_rpc(body, headers, profile_cfg)
            except Exception as exc:
                print(f"proxy error: {exc}", flush=True)
                traceback.print_exc()
                raw = json.dumps({"error": "proxy failure", "id": None, "result": None}).encode()
                status, ctype = 502, "application/json"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def _bitcoin_cli(args: list[str], payload: bytes | None = None) -> str:
    import subprocess
    cmd = ["sudo", "-n", "docker", "exec"]
    if payload is not None:
        cmd.append("-i")
    cmd += ["knots-local", "bitcoin-cli", "-datadir=/home/bitcoin/.bitcoin"]
    if payload is not None:
        cmd.append("-stdin")
    cmd += args
    proc = subprocess.run(cmd, input=payload, capture_output=True, timeout=180)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode().strip()
        raise RuntimeError(err[:300] or f"bitcoin-cli rc {proc.returncode}")
    return (proc.stdout or b"").decode()


def _gbt() -> dict:
    raw = _bitcoin_cli(["getblocktemplate"], json.dumps({"rules": ["segwit", "blake2b"]}).encode())
    return json.loads(raw)


def fill_once(cfg: dict, profile_name: str = "strict") -> int:
    """Filter one template, ask the node to refill, and stay under the weight limit.

    Dropped transactions are set aside with prioritisetransaction for the second
    request, then restored. Nothing is submitted as a block.
    """
    profile = _profile(cfg, profile_name)
    flags = profile.get("filters") or {}
    first = _gbt()
    filtered, info = _filter_template(first, flags)
    kept = filtered["transactions"]
    kept_ids = {tx["txid"] for tx in kept}
    dropped = [tx for tx in first["transactions"] if tx["txid"] not in kept_ids]
    used = sum(int(tx["weight"]) for tx in first["transactions"])
    limit = int(first["weightlimit"])
    ceiling = weight_ceiling(limit)
    print(
        f"height {first.get('height')} profile {profile.get('name')} "
        f"txs {len(first['transactions'])} weight {used} limit {limit} ceiling {ceiling}"
    )
    print(f"dropped {len(dropped)} weight {sum(int(tx['weight']) for tx in dropped)} reasons {info.get('reasons', {})}")
    if not dropped:
        print("nothing to refill")
        return 0
    deltas: list[tuple[str, int]] = []
    second = None
    try:
        for tx in dropped:
            delta = -(int(tx.get("fee") or 0) + 1)
            _bitcoin_cli(["prioritisetransaction", tx["txid"], "0", str(delta)])
            deltas.append((tx["txid"], delta))
        # Knots reuses the last template until the mempool counter changes and
        # five seconds have passed. Wait before asking for the refill.
        time.sleep(6)
        second = _gbt()
    finally:
        restored = 0
        for txid, delta in deltas:
            try:
                _bitcoin_cli(["prioritisetransaction", txid, "0", str(-delta)])
                restored += 1
            except Exception as exc:
                print(f"restore failed: {exc}")
        print(f"restored {restored} of {len(deltas)}")
    if second is None:
        return 1
    if second.get("height") != first.get("height") or second.get("previousblockhash") != first.get("previousblockhash"):
        print("tip moved during refill; kept the filtered template only")
        return 0
    banned = {tx["txid"] for tx in dropped}
    ids = [tx["txid"] for tx in second["transactions"]]
    still_there = sum(1 for txid in ids if txid in banned)
    candidates = []
    skipped_filter = 0
    for tx in second["transactions"]:
        parents = []
        for dep in tx.get("depends") or []:
            if isinstance(dep, int) and 1 <= dep <= len(ids):
                parents.append(ids[dep - 1])
        if tx["txid"] in kept_ids or tx["txid"] in banned:
            continue
        try:
            raw = bytes.fromhex(tx["data"])
        except ValueError:
            skipped_filter += 1
            continue
        if tx_reject_reason(raw, flags):
            skipped_filter += 1
            continue
        item = dict(tx)
        item["depends_txids"] = parents
        candidates.append(item)
    print(
        f"second txs {len(ids)} still_dropped {still_there} "
        f"new_ok {len(candidates)} new_filtered {skipped_filter}"
    )
    filled = take_refill(kept, candidates, ceiling, banned)
    added = [tx for tx in filled if tx["txid"] not in kept_ids]
    final_weight = sum(int(tx["weight"]) for tx in filled)
    added_fee = sum(int(tx.get("fee") or 0) for tx in added)
    dropped_fee = sum(int(tx.get("fee") or 0) for tx in dropped)
    value = int(first["coinbasevalue"]) - dropped_fee + added_fee
    commit = witness_commitment_hex([tx.get("hash") or tx["txid"] for tx in filled])
    proposal_template = dict(first)
    proposal_template["transactions"] = filled
    proposal_template["coinbasevalue"] = value
    proposal_template["default_witness_commitment"] = commit
    print(
        f"added {len(added)} weight {sum(int(tx['weight']) for tx in added)} "
        f"final {final_weight} under_ceiling {final_weight <= ceiling} coinbase {value}"
    )
    verdict = _proposal(proposal_template)
    print(f"proposal {verdict}")
    if final_weight > ceiling:
        return 1
    if verdict not in ("ok", "null", ""):
        return 1
    return 0


def main() -> int:
    import threading
    cfg = load_config()
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        return check(cfg)
    if len(sys.argv) > 1 and sys.argv[1] == "--fill":
        profile_name = sys.argv[2] if len(sys.argv) > 2 else "strict"
        return fill_once(cfg, profile_name)
    servers = []
    for profile in cfg["profiles"]:
        merged = {
            "name": profile.get("name"),
            "listen": profile["listen"],
            "upstream": cfg["upstream"],
            "filters": profile.get("filters") or {},
        }
        host, port_s = profile["listen"].rsplit(":", 1)
        server = ThreadingHTTPServer((host, int(port_s)), make_handler(merged))
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"profile {merged['name']} listening on {merged['listen']} upstream {cfg['upstream']}", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
