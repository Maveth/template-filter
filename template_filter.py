#!/usr/bin/env python3
"""JSON-RPC proxy that filters a getblocktemplate answer.

Point a gateway's bitcoind.rpcurl at listen. The proxy forwards every call
to upstream and, for a template request, removes matching transactions.
submitblock and the tip poll pass through unchanged. If a filtered template
cannot be rebuilt safely, the node's original answer is returned.
"""
from __future__ import annotations

import json
import sys
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from filtercore import tx_reject_reason, witness_commitment_hex

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"


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
    if isinstance(flags.get("blockmaxweight"), int):
        req["blockmaxweight"] = flags["blockmaxweight"]
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
        reason = tx_reject_reason(raw, flags)
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
        if info.get("dropped"):
            msg["result"] = new_result
            print(
                f"height {result.get('height')} dropped {info['dropped']} "
                f"kept {info['kept']} fee_sats {info['fee_sats']} {info['reasons']}",
                flush=True,
            )
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


def main() -> int:
    import threading
    cfg = load_config()
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        return check(cfg)
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
