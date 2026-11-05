# Federated Cipher network (no single relay)

Cipher clients load **`client-core/network_bundle.default.json`** or a custom file:

```bash
export CIPHER_NETWORK_BUNDLE=/path/to/my-network.json
```

## Bundle format (v1)

```json
{
  "version": 1,
  "bundle_id": "my-community-v1",
  "http_relays": [
    "https://relay-a.example.com",
    "https://relay-b.example.com"
  ],
  "signal_ws": [
    "wss://signal-a.example.com/ws",
    "wss://signal-b.example.com/ws"
  ],
  "rpc_http": [
    "https://rpc.tokenkickstarter.com",
    "http://127.0.0.1:9944"
  ]
}
```

## Runtime discovery (automatic on transport start)

1. **On-chain** — for each `rpc_http` URL, JSON-RPC **`tks_listSwarmValidators`**.  
   Active validators’ `endpoint` field is merged (HTTPS as-is, or libp2p `/ip4/…/tcp/4002` → `http://host:4002`).

2. **Relay mesh** — **`GET /discovery`** on every known HTTP relay; merge `relays[].http_base` where **`message_relay: true`** (shard ingest hosts are excluded).

3. **Signal WebSocket pool** — same discovery pass builds an RTT-ranked list of `wss://…/ws` endpoints (nearest first). Persistent WS + relay **`/internal/push`** after **`/store`** targets ~100ms delivery when both peers use a nearby validator.

Relays **refresh automatically** when messaging starts (then every 5 minutes) and before each store/fetch if the cache is stale.

Inspect the pool (always live-refreshes):

```bash
cipher-cli network
```

## Store / fetch / ack / push

- **Send:** nearest relay (RTT-ranked) until `POST /store` succeeds; co-located signal server gets an instant push.
- **Receive (online):** WebSocket `type: message` push; HTTP `POST /fetch` is fallback when WS is down.
- **Ack:** `POST /ack` on federated HTTP relays after delivery.

## Host a relay

See **[RUN-A-RELAY.md](./RUN-A-RELAY.md)** — run `tks-chain-node` with cipher flags and **`register_validator`** on TKS.

## Roadmap

- Ed25519-signed network bundles (multisig release key)
- libp2p HyperSwarm client path (aligned with TKS node)
- Stake/slash for relay operators
