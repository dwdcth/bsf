// bsf on Cloudflare Workers: a rendezvous (mailbox) server plus a
// websocket transit relay, so a full no-VPS deployment needs only this
// worker and public STUN servers.
//
//   /ws     the wormhole rendezvous protocol (RendezvousDO): peers
//           exchange offers and hole-punch candidates through mailboxes
//   /relay  the websocket transit relay (RelayDO): peers connect with
//           ?token=<hex>&side=<hex> (the same token the TCP relay
//           handshake derives) and — once a second connection presents
//           the same token with a different side — both receive
//           {"ok":true} and pipe binary frames verbatim. The frames
//           carry the transit handshake and PAKE-encrypted records, so
//           the edge only ever sees ciphertext.
//
// Uses the Durable Object hibernation API: the pairing state lives in
// socket attachments (surviving DO hibernation) and messages arrive as
// webSocketMessage callbacks — there is no in-memory map to lose and no
// accepted socket keeps the DO billed awake.
//
// Deploy with `wrangler deploy` and point bsf at it (a custom domain is
// required for reachability from mainland China, *.workers.dev is
// blocked there):
//
//	bsf --ws-relay wss://bsf.example.org/relay send FILE
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      const id = env.RENDEZVOUS.idFromName("router");
      return env.RENDEZVOUS.get(id).fetch(request);
    }

    if (url.pathname === "/relay") {
      const token = url.searchParams.get("token") || "";
      const side = url.searchParams.get("side") || "";
      if (token.length < 16 || !/^[0-9a-f]+$/.test(token) || !/^[0-9a-f]+$/.test(side)) {
        return new Response("bad token or side\n", { status: 400 });
      }

      // every connection lands in one DO; pairing happens per token
      const id = env.RELAY.idFromName("router");
      return env.RELAY.get(id).fetch(request);
    }

    return new Response("bsf on cloudflare: /ws (rendezvous) /relay?token=<hex>&side=<hex> (transit relay)\n", {
      status: 200,
      headers: { "content-type": "text/plain" },
    });
  },
};

export class RelayDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    const side = url.searchParams.get("side");
    const tokenTag = "t:" + token;

    // a stray redial of the same peer: keep the original connection
    const sameSide = this.state
      .getWebSockets(tokenTag)
      .filter((ws) => ws.deserializeAttachment().side === side);
    if (sameSide.length > 0) {
      return new Response("duplicate side\n", { status: 409 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server, [tokenTag]);
    server.serializeAttachment({ token, side });

    const peers = this.state.getWebSockets(tokenTag);
    if (peers.length >= 2) {
      const ack = JSON.stringify({ ok: true });
      for (const p of peers) p.send(ack);
      console.log("relay: paired token", token.slice(0, 8));
    } else {
      console.log("relay: waiting token", token.slice(0, 8), "side", side);
    }

    // 101 is only valid on a Response that carries the websocket; the
    // client end goes back to the caller, the server end stays here
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    // forward to the other socket of the same token; the pairing state
    // lives in the attachments, so this survives hibernation
    const { token } = ws.deserializeAttachment();
    const peers = this.state.getWebSockets("t:" + token).filter((p) => p !== ws);
    for (const peer of peers) {
      try {
        peer.send(message);
      } catch {}
    }
  }

  async webSocketClose(ws, code, reason, closedByClient) {
    this.closePeers(ws);
  }

  async webSocketError(ws, error) {
    this.closePeers(ws);
  }

  closePeers(ws) {
    try {
      const { token } = ws.deserializeAttachment();
      for (const peer of this.state.getWebSockets("t:" + token)) {
        if (peer !== ws) {
          try {
            peer.close(1000, "peer went away");
          } catch {}
        }
      }
    } catch {}
  }
}

// ---- rendezvous (mailbox) ----

// RendezvousDO speaks the wormhole rendezvous protocol over websockets:
// nameplates are allocated and claimed, claims hand out mailbox ids,
// opened mailboxes replay their spooled messages and then fan new ones
// out to every connected side. All state lives in DO storage keyed by
// nameplate/mailbox, so hibernation between messages is harmless.
export class RendezvousDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (!(await this.state.storage.getAlarm())) {
      await this.state.storage.setAlarm(Date.now() + 6 * 3600 * 1000);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ side: null, mailbox: null });
    server.send(
      JSON.stringify({
        type: "welcome",
        welcome: { motd: "bsf rendezvous on cloudflare workers" },
        server_tx: Date.now() / 1000,
      })
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, data) {
    let m;
    try {
      m = JSON.parse(data);
    } catch {
      return;
    }
    if (!m || typeof m.type !== "string") return;

    const att = ws.deserializeAttachment() || {};
    const ack = () => ws.send(JSON.stringify({ type: "ack", id: m.id, server_tx: Date.now() / 1000 }));
    const errMsg = (reason) =>
      ws.send(JSON.stringify({ type: "error", error: reason, orig: m, server_tx: Date.now() / 1000 }));

    switch (m.type) {
      case "bind": {
        if (att.side) {
          ack();
          errMsg("already bound");
          return;
        }
        if (!m.side) {
          ack();
          errMsg("bind requires 'side'");
          return;
        }
        att.side = m.side;
        ws.serializeAttachment(att);
        ack();
        return;
      }

      case "allocate": {
        ack();
        for (let i = 0; i < 64; i++) {
          const candidate = 1000 + Math.floor(Math.random() * 31768);
          if (await this.state.storage.get("np:" + candidate)) continue;
          const mboxId = randHex(20);
          await this.state.storage.put("np:" + candidate, mboxId);
          await this.state.storage.put("mb:" + mboxId, emptyMailbox());
          ws.send(JSON.stringify({ type: "allocated", nameplate: String(candidate), server_tx: Date.now() / 1000 }));
          return;
        }
        errMsg("failed to allocate nameplate");
        return;
      }

      case "claim": {
        ack();
        if (!/^\d+$/.test(String(m.nameplate))) {
          errMsg("nameplate is not an int");
          return;
        }
        // claiming an unknown nameplate creates its mailbox, matching
        // the go server (it is how mirrored codes work)
        let mboxId = await this.state.storage.get("np:" + m.nameplate);
        if (!mboxId) {
          mboxId = randHex(20);
          await this.state.storage.put("np:" + m.nameplate, mboxId);
          await this.state.storage.put("mb:" + mboxId, emptyMailbox());
        }
        const mb = (await this.state.storage.get("mb:" + mboxId)) || emptyMailbox();
        if (mb.claimCount > 1) {
          errMsg("crowded");
          return;
        }
        mb.claimCount++;
        mb.activity = Date.now();
        await this.state.storage.put("mb:" + mboxId, mb);
        ws.send(JSON.stringify({ type: "claimed", mailbox: mboxId, server_tx: Date.now() / 1000 }));
        return;
      }

      case "open": {
        ack();
        if (att.mailbox) {
          errMsg("only one open per connection");
          return;
        }
        const mb = await this.state.storage.get("mb:" + m.mailbox);
        if (!mb) {
          errMsg("mailbox not found");
          return;
        }
        att.mailbox = m.mailbox;
        ws.serializeAttachment(att);
        // replay everything spooled before this side showed up
        for (const s of mb.msgs) {
          ws.send(JSON.stringify({ type: "message", side: s.side, phase: s.phase, body: s.body, server_rx: s.rx / 1000, server_tx: Date.now() / 1000 }));
        }
        return;
      }

      case "add": {
        ack();
        if (!att.mailbox) {
          errMsg("no mailbox open");
          return;
        }
        const mb = await this.state.storage.get("mb:" + att.mailbox);
        if (!mb) {
          errMsg("mailbox not found");
          return;
        }
        const rx = Date.now();
        mb.msgs.push({ side: att.side, phase: m.phase, body: m.body, rx });
        mb.activity = rx;
        await this.state.storage.put("mb:" + att.mailbox, mb);

        // fan out to every connected side of the mailbox, the sender
        // included (clients drop their own side, like the go server)
        const packet = JSON.stringify({ type: "message", side: att.side, phase: m.phase, body: m.body, server_rx: rx / 1000, server_tx: rx / 1000 });
        for (const peer of this.state.getWebSockets()) {
          const pa = safeAttachment(peer);
          if (pa.mailbox === att.mailbox) {
            try {
              peer.send(packet);
            } catch {}
          }
        }
        return;
      }

      case "release": {
        ack();
        await this.state.storage.delete("np:" + m.nameplate);
        ws.send(JSON.stringify({ type: "released", server_tx: Date.now() / 1000 }));
        return;
      }

      case "close": {
        ack();
        ws.send(JSON.stringify({ type: "closed", server_tx: Date.now() / 1000 }));
        return;
      }

      case "list": {
        ack();
        const listed = await this.state.storage.list({ prefix: "np:" });
        const nameplates = [...listed.keys()].map((k) => ({ id: k.slice(3) }));
        ws.send(JSON.stringify({ type: "nameplates", nameplates, server_tx: Date.now() / 1000 }));
        return;
      }

      default:
        return;
    }
  }

  async webSocketClose(ws) {
    // per-connection state lives in the socket attachment; nothing to do
  }

  async webSocketError(ws) {}

  // alarm sweeps mailboxes idle for a day and the nameplates that
  // pointed at them
  async alarm() {
    const cutoff = Date.now() - 24 * 3600 * 1000;
    const mbs = await this.state.storage.list({ prefix: "mb:" });
    for (const [k, v] of mbs) {
      if ((v.activity || 0) < cutoff) await this.state.storage.delete(k);
    }
    const nps = await this.state.storage.list({ prefix: "np:" });
    for (const [k, mboxId] of nps) {
      if (!(await this.state.storage.get("mb:" + mboxId))) await this.state.storage.delete(k);
    }
    await this.state.storage.setAlarm(Date.now() + 6 * 3600 * 1000);
  }
}

function emptyMailbox() {
  return { claimCount: 0, msgs: [], activity: Date.now() };
}

function randHex(nBytes) {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeAttachment(ws) {
  try {
    return ws.deserializeAttachment() || {};
  } catch {
    return {};
  }
}
