# Template Filter

Sits between Datum Gateway and Bitcoin on a StartOS 0.4 server. Datum asks this service for a block template. This service asks Bitcoin, drops the transactions the rules name, and hands Datum a smaller template. The miners stay pointed at Datum.

Install Bitcoin and Datum Gateway first, and leave both running. Then sideload this package and start it.

## Addresses

Open **Template Filter**, then **Rules**.

- Leave **Node host** blank. Leave **Node port** at **8332**. That uses Bitcoin on this same server. A LAN port such as 65495 is not the default.
- Leave **Listen host** at `0.0.0.0` and **Listen port** at **8336**. That is the address Datum must call.

On the **Interfaces** page, copy the **Filter RPC** address. In Datum, set the Bitcoin RPC address to that copied address. Leave Datum’s login alone. This service does not take a node password. Datum keeps sending its cookie, and the filter passes it through.

New block notices still go straight from Bitcoin to Datum. A found block is sent back through the filter to Bitcoin.

The StartOS Datum package writes its Bitcoin RPC address itself and points it at Bitcoin on every start. It has no box for another address. Until that address can be set to this filter, Datum keeps talking to Bitcoin directly.

## Rules

The same **Rules** screen holds the switches. They start strict: the reject options on, bare multisig and bare pubkey off, OP_RETURN off. Change any of them and save. Saving restarts the filter, which is when the new rules load.
