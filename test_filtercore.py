#!/usr/bin/env python3
"""Small checks for the template filter. No node and no gateway."""
import hashlib
import unittest

from filtercore import clamp_template_request, take_refill, tx_input_outpoints, tx_reject_reason, weight_ceiling, witness_commitment_hex
import template_filter

FLAGS = {
    "rejectfakeoutputs": True,
    "rejectdeadbranches": True,
    "rejectbareenvelopes": True,
    "rejectfakemultisig": True,
    "rejecttokenmessages": True,
    "rejectrunestones": True,
    "rejectcounterparty": True,
    "rejectstamps": True,
    "rejectparasites": True,
    "permitbaremultisig": False,
    "permitbarepubkey": False,
    "datacarrier": True,
    "datacarriersize": None,
}


def tx_one_in_one_out(script: bytes, value: int = 1000, locktime: int = 0) -> bytes:
    raw = b"\x01\x00\x00\x00"  # version
    raw += b"\x01"  # one input
    raw += b"\x11" * 32 + b"\x00\x00\x00\x00"  # prevout
    raw += b"\x00"  # empty scriptsig
    raw += b"\xff\xff\xff\xff"
    raw += b"\x01"
    raw += value.to_bytes(8, "little")
    raw += bytes([len(script)]) + script
    raw += locktime.to_bytes(4, "little")
    return raw


class FilterTests(unittest.TestCase):
    def test_plain_payment_kept(self):
        script = b"\x00\x14" + bytes(range(20))
        self.assertIsNone(tx_reject_reason(tx_one_in_one_out(script), FLAGS))

    def test_token_and_runestone_dropped(self):
        token = b"\x6a" + bytes([len(b'{"p":"a"}')]) + b'{"p":"a"}'
        rune = b"\x6a\x5d" + b"\x01\x00"
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(token), FLAGS), "token")
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(rune), FLAGS), "runestone")

    def test_ordinary_op_return_kept(self):
        note = b"\x6a" + bytes([2]) + b"hi"
        self.assertIsNone(tx_reject_reason(tx_one_in_one_out(note), FLAGS))

    def test_parasite_locktime(self):
        script = b"\x00\x14" + bytes(range(20))
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(script, locktime=21), FLAGS), "parasite")

    def _segwit(self, witness):
        out_script = b"\x00\x14" + bytes(range(20))
        raw = b"\x01\x00\x00\x00\x00\x01"
        raw += b"\x01" + b"\x22" * 32 + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff\xff\xff"
        raw += b"\x01" + (1000).to_bytes(8, "little") + bytes([len(out_script)]) + out_script
        raw += bytes([len(witness)])
        for item in witness:
            raw += bytes([len(item)]) + item
        raw += b"\x00\x00\x00\x00"
        return raw

    def test_p2wpkh_signature_not_parsed_as_script(self):
        # 0x30 is also PUSHBYTES_48, so byte 49 is read as an opcode.
        signature = b"\x30" + b"\x00" * 48 + b"\x75" + b"\x01"
        pubkey = b"\x02" + b"\x11" * 32
        self.assertIsNone(tx_reject_reason(self._segwit([signature, pubkey]), FLAGS))

    def test_p2wsh_envelope_still_dropped(self):
        self.assertEqual(tx_reject_reason(self._segwit([b"\x75"]), FLAGS), "bareenvelope")

    def test_tapscript_envelope_still_dropped(self):
        control = b"\xc0" + b"\x33" * 32
        self.assertEqual(tx_reject_reason(self._segwit([b"\x75", control]), FLAGS), "bareenvelope")

    def test_taproot_keypath_signature_kept(self):
        signature = b"\x30" + b"\x00" * 48 + b"\x75" + b"\x00" * 14
        self.assertEqual(len(signature), 64)
        self.assertIsNone(tx_reject_reason(self._segwit([signature]), FLAGS))

    def test_knots_policy_checks(self):
        op_return = b"\x6a\x04" + b"data"
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(op_return), {"permitbaredatacarrier": False}), "baredatacarrier")
        anchor = bytes.fromhex("51024e73")
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(anchor), {"permitbareanchor": False}), "bareanchor")
        long_script = b"\x6a" + b"\x4c" + bytes([80]) + b"x" * 80
        self.assertEqual(tx_reject_reason(tx_one_in_one_out(long_script), {"maxscriptsize": 10}), "scriptsize")
        self.assertEqual(
            tx_reject_reason(tx_one_in_one_out(b"\x00\x14" + bytes(range(20))), {"bytespersigop": 20}, weight=80, sigops=5),
            "bytespersigop",
        )
        self.assertEqual(
            tx_reject_reason(
                tx_one_in_one_out(op_return),
                {"datacarriercost": 4, "minfeerate_sat_vb": 1},
                fee=1,
                weight=400,
            ),
            "datacarriercost",
        )
        capped = clamp_template_request({}, {"blockmaxweight": 9_000_000, "blockreservedsigops": 90_000})
        self.assertEqual(capped["blockmaxweight"], 4_000_000)
        self.assertEqual(capped["blockreservedsigops"], 80_000)

    def test_refill_stops_at_the_ceiling(self):
        self.assertEqual(weight_ceiling(800000), 792000)
        kept = [{"txid": "aa", "weight": 100}]
        candidates = [
            {"txid": "bb", "weight": 50, "depends_txids": []},
            {"txid": "cc", "weight": 1000, "depends_txids": []},
            {"txid": "dd", "weight": 40, "depends_txids": ["bb"]},
            {"txid": "ee", "weight": 40, "depends_txids": ["zz"]},
            {"txid": "aa", "weight": 100, "depends_txids": []},
        ]
        filled = take_refill(kept, candidates, ceiling=200, banned={"bb"})
        self.assertEqual([tx["txid"] for tx in filled], ["aa"])
        allowed = [
            {"txid": "bb", "weight": 50, "depends_txids": []},
            {"txid": "dd", "weight": 40, "depends_txids": ["bb"]},
            {"txid": "cc", "weight": 1000, "depends_txids": []},
        ]
        filled = take_refill(kept, allowed, ceiling=200, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["aa", "bb", "dd"])
        self.assertLessEqual(sum(tx["weight"] for tx in filled), 200)
        wide = [{"txid": "aa", "weight": 10, "data": "aa"}]
        huge = [{"txid": "hh", "weight": 10, "data": "bb" * 50, "depends_txids": []}]
        self.assertEqual(
            [tx["txid"] for tx in take_refill(wide, huge, 100, set(), size_ceiling=20)],
            ["aa"],
        )

    def _spend(self, prev: bytes, vout: int = 0) -> str:
        raw = b"\x01\x00\x00\x00\x01" + prev + vout.to_bytes(4, "little")
        raw += b"\x00\xff\xff\xff\xff\x01" + (1000).to_bytes(8, "little") + b"\x00\x00\x00\x00\x00"
        return raw.hex()

    def test_refill_skips_a_second_spend_of_the_same_input(self):
        prev = b"\x11" * 32
        other = b"\x22" * 32
        kept = [{"txid": "aa", "weight": 100, "data": self._spend(prev)}]
        candidates = [
            {"txid": "bb", "weight": 50, "depends_txids": [], "data": self._spend(prev)},
            {"txid": "cc", "weight": 40, "depends_txids": [], "data": self._spend(other)},
            {"txid": "dd", "weight": 40, "depends_txids": [], "data": self._spend(other, 1)},
        ]
        filled = take_refill(kept, candidates, ceiling=400, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["bb", "cc", "dd"])
        # The replacement is heavier than the transaction it retires. A
        # lower-fee neighbor is dropped so the replacement fits.
        crowded = [
            {"txid": "aa", "weight": 100, "fee": 10, "data": self._spend(prev)},
            {"txid": "low", "weight": 50, "fee": 1, "data": self._spend(b"\x55" * 32)},
        ]
        replacement = [{
            "txid": "bb",
            "weight": 80,
            "fee": 100,
            "depends_txids": [],
            "data": self._spend(prev),
        }]
        filled = take_refill(crowded, replacement, ceiling=120, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["bb"])
        # Too big even after the old spend and the cheap neighbor are gone.
        huge = [{
            "txid": "bb",
            "weight": 200,
            "fee": 100,
            "depends_txids": [],
            "data": self._spend(prev),
        }]
        filled = take_refill(crowded, huge, ceiling=120, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["aa", "low"])
        # Two newcomers that spend one input: only the first stays.
        fresh = [{"txid": "zz", "weight": 10, "data": self._spend(b"\x33" * 32)}]
        pair = [
            {"txid": "bb", "weight": 10, "depends_txids": [], "data": self._spend(b"\x44" * 32)},
            {"txid": "ee", "weight": 10, "depends_txids": [], "data": self._spend(b"\x44" * 32)},
        ]
        filled = take_refill(fresh, pair, ceiling=400, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["zz", "bb"])
        # A child that spends a different input is still added.
        child_prev = bytes.fromhex("ab" * 32)
        child = [{"txid": "kid", "weight": 20, "depends_txids": ["aa"], "data": self._spend(child_prev)}]
        filled = take_refill(kept, child, ceiling=400, banned=set())
        self.assertEqual([tx["txid"] for tx in filled], ["aa", "kid"])
        # A child of the transaction being replaced cannot stay.
        kept_child = [
            {"txid": "aa", "weight": 100, "fee": 5, "data": self._spend(prev)},
            {"txid": "kid", "weight": 20, "fee": 1, "depends_txids": ["aa"], "data": self._spend(b"\x66" * 32)},
        ]
        filled = take_refill(
            kept_child,
            [{"txid": "bb", "weight": 50, "fee": 20, "depends_txids": [], "data": self._spend(prev)}],
            ceiling=400,
            banned=set(),
        )
        self.assertEqual([tx["txid"] for tx in filled], ["bb"])
        self.assertEqual(len(tx_input_outpoints(bytes.fromhex(self._spend(prev)))), 1)


class FreshClockTest(unittest.TestCase):
    def test_saved_template_takes_the_newer_clock(self):
        saved = {"curtime": 100, "transactions": [{"txid": "aa"}], "coinbasevalue": 5}
        fresh = {"curtime": 250, "transactions": []}
        out = template_filter._with_fresh_clock(saved, fresh)
        self.assertEqual(out["curtime"], 250)
        self.assertEqual(out["transactions"], [{"txid": "aa"}])
        self.assertEqual(saved["curtime"], 100)

    def test_saved_template_keeps_a_newer_clock(self):
        saved = {"curtime": 300, "transactions": []}
        fresh = {"curtime": 250}
        self.assertIs(template_filter._with_fresh_clock(saved, fresh), saved)

    def test_fresh_template_is_left_alone(self):
        fresh = {"curtime": 250, "transactions": []}
        self.assertIs(template_filter._with_fresh_clock(fresh, fresh), fresh)

    def test_saved_list_expires_after_two_minutes(self):
        now = 1_000.0
        fresh = {"_saved_at": now, "transactions": []}
        old = {"_saved_at": now - 121, "transactions": []}
        self.assertTrue(template_filter._saved_is_fresh(fresh, now))
        self.assertFalse(template_filter._saved_is_fresh(old, now))
        self.assertFalse(template_filter._saved_is_fresh({}, now))

    def test_saved_at_is_not_sent_to_the_gateway(self):
        saved = {"curtime": 10, "_saved_at": 1.0, "transactions": [{"txid": "aa"}]}
        out = template_filter._for_gateway(saved)
        self.assertNotIn("_saved_at", out)
        self.assertEqual(out["transactions"], [{"txid": "aa"}])
        self.assertIn("_saved_at", saved)

    def test_commitment_shape(self):
        wtxid = "11" * 32
        commit = witness_commitment_hex([wtxid])
        self.assertEqual(len(commit), 76)
        self.assertTrue(commit.startswith("6a24aa21a9ed"))
        # No other transactions: the witness root is the coinbase's 32 zero bytes.
        expect = hashlib.sha256(hashlib.sha256(b"\x00" * 64).digest()).digest().hex()
        self.assertEqual(witness_commitment_hex([]), "6a24aa21a9ed" + expect)


if __name__ == "__main__":
    unittest.main()
