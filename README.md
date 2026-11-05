# ⚔️ Cipher CLI

Encrypted messaging from the terminal, powered by **TKS Blockchain**.

Send & receive E2EE messages, register usernames on-chain, transfer files — all from the command line. Uses the same encryption and transport as the [Cipher mobile app](https://github.com/tokenkickstarter).

## Features

- 🔐 **AES-256-GCM** end-to-end encryption (Double Ratchet)
- ⛓️ **TKS Blockchain** username registry (`@username` → address)
- 💸 **Native TKS Transfers** — Send TKS coins to addresses or `@usernames` directly
- 👥 **Multi-User Groups** — Create private groups, manage members, and chat
- 📢 **Broadcast Channels** — Public announcements and channels with subscribers
- 🛡️ **Privacy Transport Modes** — Direct, Tor (3-hop), Nym Mixnet (5-hop), and Domain-Fronting
- 💻 **Interactive Shell** — Unified inbox bridging all commands with or without slash prefixes
- 📎 **File transfer** — images, video, documents (512 KiB / 2MB encrypted chunks + Merkle tree)
- 🌐 **Federated relays** — `network_bundle.default.json` + `GET /discovery` merge (no single hardcoded relay); see [docs/NETWORK-FEDERATION.md](docs/NETWORK-FEDERATION.md)
- 🔑 **BIP-39 identity** — Ed25519 + X25519 + Sr25519 + secp256k1

## Quick Start

```bash
# Build from source
cargo build --release
sudo cp target/release/cipher-cli /usr/local/bin/

# Generate identity
cipher-cli init

# Check your address & keys
cipher-cli whoami

# Register username on TKS blockchain (FREE)
cipher-cli register @ninja

# Launch unified interactive shell
cipher-cli shell

# Send a native TKS coin transfer
cipher-cli transfer @recipient 1.5

# Check TKS balance
cipher-cli balance

# Manage groups and channels
cipher-cli group create "Core Team"
cipher-cli channel create "Announcements" @tks_announcements

# Privacy mode selector (Direct, Tor, Nym, Front, Auto)
cipher-cli mode tor
```

## All Commands

| Command | Description |
|---------|-------------|
| `shell` | Launch interactive chat shell (unified inbox with live dispatch) |
| `init` | Generate new identity (BIP-39 seed phrase) |
| `restore` | Restore identity from existing seed phrase |
| `whoami` | Display your addresses & public keys |
| `export` | Export seed phrase (with warning) |
| `login` | Unlock session cache (4 hours) |
| `logout` | Destroy session cache |
| `send` | Send encrypted text message |
| `send-file` | Send encrypted file (image, video, document) |
| `recv` | Poll for incoming messages (`-f` for live follow) |
| `chat` | Interactive bidirectional 1-on-1 chat |
| `contacts` | List conversation peers |
| `status` | Network & transport status |
| `register` | Register @username on TKS blockchain (FREE) |
| `lookup` | Resolve @username ↔ address on-chain |
| `balance` | Check TKS token balance |
| `transfer` | Send TKS native coins to address or @username |
| `node-info` | Query TKS blockchain node info |
| `mode` | View or set privacy transport mode (`direct`, `tor`, `nym`, `front`, `auto`) |
| `group` | Multi-user groups (`create`, `list`, `info`, `add`, `send`, `leave`) |
| `channel` | Broadcast channels (`create`, `list`, `post`, `sub`, `unsub`) |

### Interactive Shell Commands
Inside `cipher-cli shell`, all commands work directly with or without a leading slash:
- `@username <msg>` — Send an encrypted message
- `/chat <@user>` or `chat <@user>` — Focus on one conversation
- `/all` or `all` — Show all conversations
- `/register <@name>` or `register <@name>` — Register username on-chain
- `/transfer <@user> <amt>` or `transfer <@user> <amt>` — Transfer TKS coins
- `/balance` or `balance` — Check your TKS balance
- `/whoami` or `whoami` — Display address & keys
- `/mode [direct|tor|nym|front|auto]` — Switch privacy routing
- `/group create|list|send|add|info` — Group chat actions
- `/channel create|list|post|sub` — Channel broadcast actions
- `/node-info` or `node-info` — TKS blockchain height & state
- `/help` or `help` — Show full categorized command help
- `/quit` or `exit` — Exit shell

## Architecture

```
cipher-cli
├── src/
│   ├── main.rs              ← CLI entry (clap subcommands)
│   ├── identity_store.rs    ← Encrypted identity (~/.cipher/identity.json)
│   └── commands/
│       ├── init.rs           ← Generate identity
│       ├── restore.rs        ← Restore from seed phrase
│       ├── whoami.rs         ← Show addresses
│       ├── send.rs           ← Send E2EE message
│       ├── send_file.rs      ← Send encrypted file
│       ├── recv.rs           ← Receive messages
│       ├── chat.rs           ← Interactive chat
│       ├── register.rs       ← Register @username on TKS
│       ├── lookup.rs         ← Resolve @username on-chain
│       ├── balance.rs        ← Check TKS balance
│       ├── node_info.rs      ← Query blockchain node
│       ├── contacts.rs       ← List peers
│       ├── status.rs         ← Network status
│       └── export.rs         ← Export seed phrase
└── Cargo.toml
```

## Network

| Service | Endpoint |
|---------|----------|
| TKS Blockchain RPC | `https://rpc.tokenkickstarter.com` |
| Signal Relay (WSS) | `wss://signal.tokenkickstarter.com` |
| Seed Node (US) | `seed.tokenkickstarter.com` |
| Seed Node (EU) | `seed.tkstoken.com` |
| Seed Node (Asia) | `seed.tksscan.com` |

## Security

- Identity stored at `~/.cipher/identity.json`, encrypted with AES-256-GCM
- Messages encrypted end-to-end (sender → recipient only)
- Files split into 2MB chunks, each AES-256-GCM encrypted with Merkle tree integrity
- Username registration is FREE (no gas) — uses TKS NameRegistry pallet
- No data on blockchain — messages are temporary encrypted chunks on relay nodes

## Build from Source

```bash
# Prerequisites: Rust 1.70+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone & build
git clone https://github.com/tokenkickstarter/Cipher-cli.git
cd Cipher-cli
cargo build --release

# Install
sudo cp target/release/cipher-cli /usr/local/bin/
```

## License

MIT — TokenKickstarter
