# Run a Cipher relay (community host)

Cipher messages are **encrypted on the client**. Relays only store **ciphertext** and forward batch metadata to optional shard ingest. Anyone can run a relay and register it on **TKS L1** so all clients discover you via `tks_listSwarmValidators`.

## Requirements

- Public HTTPS (or HTTP for lab) to **port 4002** cipher-relay API (`/store`, `/fetch`, `/ack`, `/discovery`)
- **Signal WebSocket** on **port 4003** (`vps-signal-server` or equivalent) proxied as `wss://YOUR.domain/ws` for ~100ms push delivery
- A **TKS full node** or the same binary with embedded cipher services
- Validator **AccountId20** key with balance for `register_validator` extrinsic

## Start node (from [tks-substrate-node](https://github.com/TokenKickstarter/tokenkickstarter-node))

```bash
tks-chain-node ... \
  --chain tks-network-spec-raw.json \
  --enable-cipher-relay --cipher-relay-port=4002 \
  --enable-cipher-hyperswarm --cipher-hyperswarm-port=4001 \
  --cipher-public-relay-url=https://YOUR.domain \
  --cipher-public-signal-ws=wss://YOUR.domain/ws \
  --cipher-signal-push-url=http://127.0.0.1:4003/internal/push \
  --enable-cipher-shard-executor --cipher-shard-port=4010
```

Run **`vps-signal-server`** on `:4003` (see repo folder). Put nginx/Caddy in front: `/` → relay `:4002`, `/ws` → signal `:4003`. After **`POST /store`**, the relay notifies the signal server so online peers get instant WS push.

## Register on-chain

Use your operator key (see `network/VALIDATORS.md` and `shard-setup` tooling in the node repo):

- **`ShardRegistry.register_validator(region, endpoint)`**
- **`endpoint`**: prefer `https://relay.YOUR.domain` for mobile clients, or `/ip4/PUBLIC_IP/tcp/4002` for libp2p-style registration (clients map tcp/4002 → HTTP).

After inclusion, any Cipher client calling **`tks_listSwarmValidators`** on **any** TKS RPC will merge your URL into its relay pool.

## Verify

```bash
curl -s https://rpc.tokenkickstarter.com -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tks_listSwarmValidators","params":[]}' | jq .

curl -s https://relay.YOUR.domain/discovery | jq .
```

From Cipher CLI:

```bash
cipher-cli network
```

## Client bootstrap order

1. Embedded **`network_bundle.default.json`** (default: **empty** relays — discovery-only via `rpc_http` + chain)
2. **`CIPHER_NETWORK_BUNDLE`** file (optional override)
3. **`tks_listSwarmValidators`** on each RPC in the bundle
4. **`GET /discovery`** on each known relay

No single hostname is required if the pool has multiple entries.
