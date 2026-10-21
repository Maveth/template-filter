# template-filter

A block-template filter that sits between a mining gateway and a Bitcoin node. Released under the [MIT license](LICENSE).

The node keeps its mempool. The gateway keeps its own block builder. This program only changes the template the gateway asked for.

## Concept

A pool node has two jobs. It must remember enough transactions to check blocks other people find. It also builds the template its own miners work on. Those jobs want different rules. A strict mempool makes compact-block checking fetch transactions the node refused. A loose mempool puts transactions into the template that the pool does not want to mine.

The usual place for a rule like Plumb's is inside the node, so the transaction is refused for relay and for mining. This filter applies the same kind of rule one step later. The node still accepts the transaction. When a gateway asks for a template, the filter takes the node's answer, removes the transactions the rules name, and hands the gateway a smaller template.

The gateway already trusts three fields in that answer: the transaction list, the coinbase value, and the witness commitment. If those three stay consistent, the gateway builds a valid block without a code change. If the filter is not sure the rewrite is safe, it returns the node's original template unchanged.

## How to connect it

Run the node as you do now. Run the filter on another port and set `upstream` to the node's RPC URL. Point the gateway's node URL at the filter. Leave the gateway's RPC username and password where they already are.

The filter does not have a setting for the node password, and it does not store one. On each call the gateway sends its normal login header. The filter forwards that header to the node. Do not put a password in `config.json`. The real `config.json` is gitignored. Copy `config.example.json` and edit that copy on the machine that runs the filter.

One filter process can listen on several ports. Each port is a profile with its own rules. Every profile talks to the same node. A gateway that should see the raw mempool stays pointed at the node and never touches the filter.

```text
gateway  --RPC-->  filter :8336 strict  --RPC-->  node
gateway  --RPC-->  filter :8337 open    --RPC-->  node
gateway  --RPC-->  node
```

A found block is submitted back through the same path. `submitblock` and the tip check are forwarded unchanged. The filter does not broadcast anything itself.

Restart the filter after a config change. There is no web editor. `GET /health` on a listen port returns that profile's name and rules as JSON.

## What a template request does

1. The gateway sends `getblocktemplate`, usually with the rules it already sends (`segwit`, and `blake2b` on a Blake2b chain).
2. If the profile sets `minfeerate_sat_vb` or `blockmaxweight`, those are added to the request. `minfeerate_sat_vb` is in sat/vB and tells the node to build a fresh template instead of using its cached one. Leave it unset to keep the node's normal fee floor and its cached template.
3. The node builds the full template from its mempool.
4. The filter drops transactions the rules match, then drops any transaction that spends a dropped one (`depends`).
5. It subtracts the dropped transactions' fees from `coinbasevalue`. A dropped transaction with no integer fee fails the rewrite, and the original template is returned.
6. It recomputes `default_witness_commitment`. The commitment is `SHA256d(witness merkle root || 32 zero bytes)`, written as the script `6a24aa21a9ed || commitment`. Hashing the witness root alone does not match the node, and the block would be rejected.
7. If nothing was dropped, the node's commitment and coinbase value are left as they arrived.

Other RPC methods are proxied and not rewritten. A `getblocktemplate` proposal is also proxied unchanged.

## Rules

The strict example turns on the Plumb template checks:

| Key | What it drops |
|---|---|
| `rejectfakeoutputs` | Repeated-byte witness programs, and three or more small P2WSH outputs paying the same dust value |
| `rejectdeadbranches` | `OP_FALSE OP_IF` and `OP_1 OP_NOTIF` envelopes |
| `rejectbareenvelopes` | A script of only pushes ending in `OP_DROP` or `OP_2DROP` |
| `rejectfakemultisig` | A bare multisig output, or a spend with more than 10 pubkey pushes |
| `rejecttokenmessages` | Omni, and a short JSON `OP_RETURN` whose payload contains `"p":` |

These are also on in the strict example. They are the usual Knots data-carrier refusals, or stricter than a node that still relays data:

| Key | What it drops |
|---|---|
| `rejectrunestones` | Runestone `OP_RETURN` (`OP_13` after `OP_RETURN`) |
| `rejectcounterparty` | Counterparty payload |
| `rejectstamps` | `stamp:` payload |
| `rejectparasites` | Locktime 21 (CAT-21) |
| `permitbaremultisig: false` | Bare multisig outputs |
| `permitbarepubkey: false` | Bare pubkey outputs |
| `datacarrier: false` | Any `OP_RETURN` |
| `datacarriersize` | `OP_RETURN` whose pushed payload is larger than this many bytes |
| `dust_sat_per_kvb` | A spendable output under that dust rate. `null` leaves dust to the node |

A transaction that does not parse is kept. The filter will not drop something it cannot read.

Two Plumb details are narrower here. A wrapped multisig is dropped when it pushes more than 10 pubkeys. The filter does not check which keys a signature proves. A taproot key that is not on the curve is not checked.

## StartOS 0.4

This repo also builds a sideload package for StartOS 0.4. It does not install on StartOS 0.3.

The service depends on Bitcoin and Datum Gateway both running. It calls Bitcoin for templates and listens for Datum. Leave the node host blank to use Bitcoin on the same server, port 8332. A port such as 65495 is the LAN port StartOS assigned on one server, not the default. Set Datum's Bitcoin RPC URL to this service's filter address, port 8336 unless you change it.

GitHub Actions builds `template-filter_aarch64.s9pk` and `template-filter_x86_64.s9pk` and attaches them to a release.

## Run

Python 3.11 or newer. No packages beyond the standard library.

```bash
cp config.example.json config.json
# edit upstream and the listen ports
python3 template_filter.py
```

Tests, with no node:

```bash
python3 test_filtercore.py
```

`--check` asks the upstream node for one template, checks that the witness formula matches the node's commitment, filters it, and can ask `bitcoin-cli` on a local `knots-local` container whether the result would be a valid block apart from proof of work. The node login for that one call comes from the environment. It is not written to a file and it is not printed.

```bash
TEMPLATE_FILTER_RPC_USER=... TEMPLATE_FILTER_RPC_PASSWORD=... python3 template_filter.py --check
```

## Implementation

`filtercore.py` walks a raw transaction, including the segwit marker and witness stack. `tx_reject_reason` returns a short reason or `None`. `witness_commitment_hex` takes getblocktemplate wtxid strings (display order), reverses each into internal byte order, builds the witness merkle tree with a 32-zero coinbase leaf, and appends 32 zero bytes before the second hash.

`template_filter.py` is a small HTTP server, one thread per profile. It forwards the gateway's `Authorization` header and rewrites only a template result. A broken rewrite, a missing fee, or a commitment that is not the 38-byte form returns the original response. That fail-open path is the safety property: a bad filter must not be the template a miner finds a block on.
