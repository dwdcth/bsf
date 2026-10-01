# bsf Cloudflare Worker (rendezvous + relay)

One Worker runs the **whole no-VPS deployment**:

- `/ws` — the wormhole rendezvous (mailbox) protocol: peers exchange
  offers and hole-punch candidates here (a Durable Object with storage,
  state survives hibernation; idle mailboxes are swept after a day)
- `/relay` — the `relay-ws-v1` transit relay on wss port 443, the
  fallback when no direct path and no UDP punch succeeds; the edge only
  ever sees PAKE-encrypted ciphertext

With public STUN (bilibili/cloudflare are in bsf's defaults) the full
connection chain works without a single server of your own:
punch (P2P) → ws relay.

## Deploy

```sh
npm install -g wrangler   # or: npx wrangler
wrangler login
wrangler deploy
```

The deploy output gives the worker URL. Bind a **custom domain**
(replace the commented `routes` entry in wrangler.toml with a hostname
on a zone in your account) — `*.workers.dev` is blocked in mainland
China, a custom domain is not.

## Use (no-VPS mode)

Both peers point `--relay-url` at the worker; that is the entire
setup:

```sh
# side A
bsf --relay-url wss://bsf.example.org/ws --ws-relay wss://bsf.example.org/relay send FILE

# side B
bsf --relay-url wss://bsf.example.org/ws --ws-relay wss://bsf.example.org/relay CODE
```

`--ws-relay` makes the same worker the fallback relay; without it the
punch falls back to the public TCP transit relay instead. Shell
completion of nameplates works too (the worker implements `list`).

Notes:

- python magic-wormhole clients can use this rendezvous as well (the
  protocol is the standard one) but ignore `bsf-ice`/`relay-ws-v1`
- free tier: 100k requests/day for the worker, Durable Object storage
  is capped far above mailbox traffic; the relay's ~1300 messages per
  20MB transfer is well within reach
- every pairing state lives in socket attachments and DO storage —
  hibernation between messages is harmless
