#!/usr/bin/env python3
"""Small checks for the template filter. No node and no gateway."""
import hashlib
import unittest

from filtercore import tx_reject_reason, witness_commitment_hex

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
