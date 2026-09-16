# ⚔️ Cipher CLI

Encrypted messaging from the terminal, powered by **TKS Blockchain**.

Send & receive E2EE messages, register usernames on-chain, transfer files — all from the command line. Uses the same encryption and transport as the [Cipher mobile app](https://github.com/tokenkickstarter).

## Features

- 🔐 **AES-256-GCM** end-to-end encryption (Double Ratchet)
- ⛓️ **TKS Blockchain** username registry (`@username` → address)
- 📎 **File transfer** — images, video, documents (2MB encrypted chunks + Merkle tree)
- 💬 **Interactive chat** mode (bidirectional real-time)
- 🌐 **Decentralized relay** at `wss://signal.tokenkickstarter.com`
- 🔑 **BIP-39 identity** — Ed25519 + X25519 + Sr25519 + secp256k1

## Quick Start

```bash
# Build from source
cargo build --release
sudo cp target/release/cipher-cli /usr/local/bin/

# Generate identity
cipher-cli init

# Check your address
cipher-cli whoami

# Register username on TKS blockchain (FREE)
cipher-cli register @ninja

# Send a message
cipher-cli send 0xRecipientAddress "Hello from Cipher!"

# Send a file
cipher-cli send-file 0xRecipientAddress ./photo.jpg

# Receive messages
cipher-cli recv -f

# Interactive chat
cipher-cli chat 0xPeerAddress

# Check TKS blockchain
cipher-cli node-info
cipher-cli balance
cipher-cli lookup @ninja
```

## All Commands

| Command | Description |
|---------|-------------|
| `init` | Generate new identity (BIP-39 seed phrase) |
| `restore` | Restore identity from existing seed phrase |
| `whoami` | Display your addresses & public keys |
| `export` | Export seed phrase (with warning) |
| `send` | Send encrypted text message |
| `send-file` | Send encrypted file (image, video, document) |
| `recv` | Poll for incoming messages |
| `recv -f` | Live listen mode |
| `chat` | Interactive bidirectional chat |
| `contacts` | List conversation peers |
| `status` | Network & transport status |
| `register` | Register @username on TKS blockchain (FREE) |
| `lookup` | Resolve @username ↔ address on-chain |
| `balance` | Check TKS token balance |
| `node-info` | Query TKS blockchain node info |

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
