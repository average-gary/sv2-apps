# Coinbase Rotation for SV2 Mining Pools

**Deterministic address derivation for quantum-resistant payout hygiene**

> **Disclaimer:** This is independent research and development. The views and work presented here are my own and do not represent the official position, strategy, or endorsement of my employer.

---

## Testnet4 Validation

On January 28, 2026, we validated coinbase rotation on Bitcoin testnet4: two blocks mined back to back, each paying its coinbase to a fresh address derived from a single extended public key—an address whose public key had never been exposed on-chain.

Since then the descriptor has kept producing. A full scan of every address the wildcard descriptor can derive (mempool.space testnet4, 2026-09-03) finds:

- **2,042 coinbase outputs** paid to addresses derived from this one descriptor
- **31 distinct derivation indices** used (of 0–50 scanned, gap limit 30)
- **Block heights 91,282–150,815** (2025-07-15 to 2026-09-03 UTC)
- **102,113.98 tBTC** total coinbase value

Rotation was not enabled for this whole span, which is why the blocks are not spread one-per-index. Most of the time the pool ran with rotation off, pinned to a single derivation index, so every block in that stretch landed on the same address:

- **Rotation on** (2026-01-28 → 2026-02-02): 28 blocks across 25 distinct indices, the index climbing 0 → 48 as blocks were found. Heights 120,436–121,241, 1,401.04 tBTC.
- **Rotation off** (everything else): 2,014 blocks across 11 pinned indices — e.g. 1,413 blocks all paid to index 9, 223 to index 2. Same descriptor, no rotation, so those indices reuse a public key exactly the way a static coinbase address would.

(A separate non-rotating instance mining to index 9 found 4 blocks during the rotation window, so the two runs overlap slightly.)

The full block list, with per-index breakdown and explorer links, is on the [project site](https://average-gary.github.io/sv2-apps/#all-blocks).

```
2026-01-28T17:44:24.925747Z  INFO pool_sv2::channel_manager::mining_message_handler:
    SubmitSharesExtended: 💰 Block Found!!! 💰
    0000000000000000b2d658e434cb1383eb41853a1b8bb23df1993a6c9036f2f7

2026-01-28T19:10:00.262347Z  INFO pool_sv2::channel_manager::mining_message_handler:
    SubmitSharesExtended: 💰 Block Found!!! 💰
    00000000000000005a65b2d963bc3117c3b0f92d5674483e7ab6af1e03d51267
```

### Mined Blocks

**Block 1**
- Time: 2026-01-28 17:44:24 UTC
- Derivation Index: 4
- Address: `tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x`
- [View on mempool.space](https://mempool.space/testnet4/block/0000000000000000b2d658e434cb1383eb41853a1b8bb23df1993a6c9036f2f7)

**Block 2**
- Time: 2026-01-28 19:10:00 UTC
- Derivation Index: 5
- Address: `tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp`
- [View on mempool.space](https://mempool.space/testnet4/block/00000000000000005a65b2d963bc3117c3b0f92d5674483e7ab6af1e03d51267)

### Descriptor Used

```
wpkh(tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw/0/*)
```

The wildcard `/*` at the end enables automatic rotation. Each block found increments the derivation index, producing a new unique address with an unexposed public key.

---

## The Quantum Threat to Bitcoin

Bitcoin's security model relies on the Elliptic Curve Digital Signature Algorithm (ECDSA) and the secp256k1 curve. The security assumption is that deriving a private key from a public key is computationally infeasible—a problem known as the Elliptic Curve Discrete Logarithm Problem (ECDLP).

**Quantum computers change this calculus.** Shor's algorithm, running on a sufficiently powerful quantum computer, can solve ECDLP in polynomial time. While such computers don't exist today, the cryptographic community takes this threat seriously. Bitcoin's long-term security depends on proactive measures.

### BIP-360: Pay to Quantum Resistant Hash (P2QRH)

The Bitcoin community is actively developing quantum-resistant solutions. [BIP-360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki) proposes a new output type using post-quantum cryptographic signatures. Key features include:

- **Lattice-based signatures** (e.g., FALCON, SPHINCS+) resistant to Shor's algorithm
- **Backward compatibility** via soft fork activation
- **Migration path** for existing UTXOs to quantum-safe addresses

Until P2QRH or similar solutions are deployed, **minimizing public key exposure is the most effective defense-in-depth measure** available today.

### Understanding Public Key Exposure

Bitcoin addresses are derived from public keys through a one-way hash function:

```
Address = RIPEMD160(SHA256(PublicKey))  // P2PKH
Address = SHA256(PublicKey)[0:20]        // P2WPKH (simplified)
```

This hash provides a layer of protection: even if an attacker can derive private keys from public keys (the quantum threat), they still cannot derive public keys from addresses (hash preimage resistance). **The public key remains hidden until the first spend.**

### The ECDSA Exposure Window

```
┌───────────────────────────────┐
│  FRESH ADDRESS                │
│  (never spent from)           │
├───────────────────────────────┤
│ • Pubkey hidden behind hash   │
│ • Quantum-safe                │
│ • No known attack             │
└───────────────────────────────┘
              │
              │ First spend
              ▼
┌───────────────────────────────┐
│  EXPOSED ADDRESS              │
│  (spent from)                 │
├───────────────────────────────┤
│ • Transaction reveals pubkey  │
│ • Quantum vulnerable          │
│ • Future deposits at risk     │
└───────────────────────────────┘
```

### Why Address Reuse is Dangerous

When you spend from an address, the full ECDSA public key is revealed in the transaction's witness data (for SegWit) or scriptSig (for legacy). A quantum attacker could then:

1. **Extract the public key** from any historical transaction spending from that address
2. **Run Shor's algorithm** to derive the private key
3. **Steal any funds** subsequently deposited to that address

This is particularly dangerous for mining pools that reuse a single coinbase address. After the first consolidation transaction, **every future block reward sent to that address is quantum-vulnerable from the moment it's mined.**

### The "Harvest Now, Decrypt Later" Attack

Nation-state adversaries are already archiving encrypted data and blockchain transactions with the expectation that future quantum computers will enable decryption. This is known as a **"harvest now, decrypt later" (HNDL)** attack.

For Bitcoin, this means:

- Public keys exposed today are recorded permanently on-chain
- When quantum computers become viable, historical public keys can be attacked
- Funds in addresses with exposed public keys become immediately vulnerable

> **Mining Pool Coinbases: A High-Value Target**
>
> Mining pools accumulate significant value in coinbase outputs. A pool using a single static address creates an attractive target: one public key exposure compromises all future deposits. Coinbase rotation eliminates this single point of failure.

### Coinbase Rotation: Defense in Depth

By deriving a fresh address for each block, coinbase rotation ensures:

- **No public key reuse:** Each coinbase output has a unique, unexposed public key
- **Isolated exposure:** Spending from one address doesn't compromise others
- **Time-limited vulnerability:** Each address is only at risk after its first spend
- **Reduced attack surface:** An attacker must crack each address individually

### Quantum Timeline Considerations

| Era | Timeframe | Status |
|-----|-----------|--------|
| Current | 2024-2026 | NISQ devices (noisy, limited qubits). No threat to ECDSA. Time to implement defensive measures. |
| Near-Term | 2030-2035 | Early fault-tolerant systems. Potential threat to weak keys. BIP-360 activation target. |
| Long-Term | 2035+ | Cryptographically relevant quantum computers. ECDSA potentially broken. P2QRH protects new UTXOs. |

*Timeline is speculative. Estimates vary widely among cryptographers. The prudent approach is to minimize exposure now rather than react after quantum capabilities emerge.*

---

## Additional Benefits

Beyond quantum resistance, coinbase rotation provides operational benefits:

- **Reduced chain analysis surface:** Blocks aren't trivially linkable by address
- **Simplified UTXO management:** Smaller, distributed UTXOs vs. one large accumulator
- **Standard wallet compatibility:** Uses BIP-32/44/84 HD derivation paths

---

## The Solution: Wildcard Descriptor Rotation

Coinbase rotation leverages Bitcoin's hierarchical deterministic (HD) wallet standard (BIP-32/44/84) combined with miniscript descriptors. By specifying a wildcard (`/*`) in the descriptor, the pool automatically derives sequential addresses from a single extended public key—each with a unique, unexposed public key.

### Configuration Example

```toml
# pool-config.toml

# Wildcard descriptor enables rotation
coinbase_reward_script = "wpkh(tpub.../0/*)"

# Persistence file (survives restarts)
coinbase_index_file = "/var/lib/pool/coinbase_index.dat"

# Starting derivation index (default: 0)
coinbase_start_index = 0
```

### Supported Descriptor Types

| Type | Descriptor Format | Address Type |
|------|-------------------|--------------|
| Native SegWit | `wpkh(xpub.../0/*)` | bc1q... (P2WPKH) |
| Taproot | `tr(xpub.../0/*)` | bc1p... (P2TR) |
| Legacy SegWit | `sh(wpkh(xpub.../0/*))` | 3... (P2SH-P2WPKH) |

### How It Works

```
Miner ──> Pool: Block found!
               │
Pool ──> Derivator:
               rotate_coinbase()
               │
Derivator:     index++ (atomic)
               derive(xpub, index)
               → new scriptPubKey
               │
Derivator ──> Disk:
               persist("seq:N")
               │
Pool:          Update outputs
               │
Pool ──> Miner: Success
```

---

## Security Comparison: Static vs. Rotating Addresses

**Static Address (Vulnerable)**
```
┌───────────────────────────────┐
│ Block 1 ─┐                    │
│ Block 2 ─┼─> Single  ─> ONE   │
│ Block 3 ─┤   Address    key   │
│ Block N ─┘              breaks│
│                         ALL   │
└───────────────────────────────┘
```

**Rotating Addresses (Defense in Depth)**
```
┌───────────────────────────────┐
│ Block 1 ──> Addr 1 ─┐         │
│ Block 2 ──> Addr 2 ─┼─> Each  │
│ Block 3 ──> Addr 3 ─┤  isolated│
│ Block N ──> Addr N ─┘         │
└───────────────────────────────┘
```

---

## Implementation Details

The implementation uses Rust's `miniscript` crate for descriptor parsing and derivation. The current index is stored atomically in memory and persisted to disk after each rotation, ensuring crash-safety and restart resilience.

### Key Components

**`XpubDerivator`** — `stratum-apps/src/config_helpers/xpub_derivation.rs`
- Parses wildcard descriptors
- Derives scriptPubKey at arbitrary indices
- Thread-safe index management via `AtomicU32`
- Persistent storage with format: `seq:N`

**`CoinbaseRewardScript`** — `stratum-apps/src/config_helpers/coinbase_output/`
- Detects wildcard descriptors via `has_wildcard()` method
- Returns raw descriptor string for derivator initialization

**`ChannelManager`** — `pool-apps/pool/src/lib/channel_manager/`
- Calls `rotate_coinbase_address()` after block found
- Updates `coinbase_outputs` in channel manager data

### Persistence Format

```
# Index format
seq:42

# Legacy format (treated as sequential)
42
```

---

## Verify It Yourself

Don't trust, verify. You can independently confirm that the testnet4 blocks used the correct derived addresses by running the derivation yourself.

### Rust

```rust
use miniscript::{Descriptor, descriptor::DescriptorPublicKey, bitcoin::{Network, Address}};

fn main() {
    let descriptor_str = "wpkh(tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw/0/*)";
    
    let desc: Descriptor<DescriptorPublicKey> = descriptor_str.parse().unwrap();
    
    // Derive at indices 4 and 5 (the two testnet4 blocks)
    for i in 4..=5 {
        let derived = desc.at_derivation_index(i).unwrap();
        let script = derived.script_pubkey();
        let address = Address::from_script(&script, Network::Testnet).unwrap();
        println!("Index {}: {}", i, address);
    }
}

// Expected output:
// Index 4: tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x
// Index 5: tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp
```

### Python (with python-bitcoinlib)

```python
from bitcoin.wallet import CBitcoinExtPubKey
from bitcoin.core import Hash160
from bitcoin.bech32 import encode_segwit_address

# tpub from the descriptor (BIP84 account key)
tpub = "tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw"

# Parse the extended public key
xpub = CBitcoinExtPubKey(tpub)

# Derive at m/0/4 and m/0/5 (relative to the tpub)
for i in [4, 5]:
    child = xpub.derive(0).derive(i)
    pubkey_hash = Hash160(child.pub.serialize())
    address = encode_segwit_address("tb", 0, pubkey_hash)
    print(f"Index {i}: {address}")

# Expected output:
# Index 4: tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x
# Index 5: tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp
```

### Bitcoin Core (bitcoin-cli)

```bash
# Import the descriptor (watch-only)
bitcoin-cli -testnet4 importdescriptors '[{
  "desc": "wpkh(tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw/0/*)#checksum",
  "timestamp": "now",
  "range": [0, 10],
  "watchonly": true
}]'

# Derive addresses at indices 4 and 5
bitcoin-cli -testnet4 deriveaddresses \
  "wpkh(tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw/0/*)#checksum" \
  "[4,5]"

# Expected output:
# [
#   "tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x",
#   "tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp"
# ]
```

### JavaScript (bitcoinjs-lib)

```javascript
const bitcoin = require('bitcoinjs-lib');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');

const bip32 = BIP32Factory(ecc);
const network = bitcoin.networks.testnet;

// Parse the tpub
const tpub = "tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw";
const node = bip32.fromBase58(tpub, network);

// Derive at m/0/4 and m/0/5
for (const i of [4, 5]) {
    const child = node.derivePath(`0/${i}`);
    const { address } = bitcoin.payments.p2wpkh({ 
        pubkey: child.publicKey, 
        network 
    });
    console.log(`Index ${i}: ${address}`);
}

// Expected output:
// Index 4: tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x
// Index 5: tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp
```

### Expected Derivation Table

| Index | ScriptPubKey (hex) | Testnet Address |
|-------|-------------------|-----------------|
| 0 | `0014798fb52bc77ba8e028dfad1b522505223c7e7ca0` | `tb1q0x8m22780w5wq2xl45d4yfg9yg78ul9qcgs54f` |
| 1 | `00143acc8d6d349a24a198fb9eec0e27b822c589d407` | `tb1q8txg6mf5ngj2rx8mnmkqufacytzcn4q8v4yt8n` |
| 2 | `0014dd4da77967b0a8c59ee3026af582de496abad124` | `tb1qm4x6w7t8kz5vt8hrqf40tqk7f94t45fy88fzal` |
| 3 | `001401b85a64c3c8d8dcf46f49230d938ec1245fcd8e` | `tb1qqxu95exrervdear0fy3smyuwcyj9lnvwqhc2cv` |
| **4** | `0014a72ae2dddcc84c99a0abe43f4fbef1a46d153b8e` | **`tb1q5u4w9hwuepxfng9tusl5l0h353k32wuwv56s5x`** |
| **5** | `0014f809b88453f6802a6712f123a1b86830c678866e` | **`tb1qlqym3pzn76qz5ecj7y36rwrgxrr83pnwxtc5rp`** |
| 6 | `00148bbd1dcaa404a72cc4ad712fced24cb5b1b1e24d` | `tb1q3w73mj4yqjnje39dwyhua5jvkkcmrcjdqtq83p` |
| 7 | `00144df4dd5500202f6165daed18170b0a505a63f7f3` | `tb1qfh6d64gqyqhkzew6a5vpwzc22pdx8aln9cselq` |
| 8 | `001450b0ab4797d5b2b037448384d21f2c1e18d390d3` | `tb1q2zc2k3uh6ketqd6yswzdy8evrcvd8yxn4sw0f5` |
| 9 | `001464134027166341446e3e959acc940e0fb03da2b4` | `tb1qvsf5qfckvdq5gm37jkdve9qwp7crmg45dxknkv` |

*Indices 4 and 5 (bold) correspond to the testnet4 blocks mined.*

---

## Getting Started

### Clone and Build

```bash
# Clone the feature branch
git clone -b feat/coinbase-rotation \
  https://github.com/average-gary/sv2-apps.git

cd sv2-apps/pool-apps

# Build the pool
cargo build --release -p pool_sv2
```

### Configure Rotation

```toml
# In your pool-config.toml
coinbase_reward_script = "wpkh(YOUR_TPUB_OR_XPUB/0/*)"
coinbase_index_file = "/path/to/coinbase_index.dat"
```

### Descriptor Conversion

If you have a descriptor from Sparrow or Bitcoin Core in a different format, use:

- [sv2-descriptor-cli](https://github.com/average-gary/sv2-descriptor-cli) — Convert descriptors between formats

---

## Further Reading

- [BIP-360: Pay to Quantum Resistant Hash (P2QRH)](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki)
- [Bitcoin Wiki: Quantum Computing and Bitcoin](https://en.bitcoin.it/wiki/Quantum_computing_and_Bitcoin)
- [Quantum Attacks on Bitcoin, and How to Protect Against Them (Aggarwal et al.)](https://arxiv.org/abs/1710.10377)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

---

**Links:**
- [GitHub: feat/coinbase-rotation](https://github.com/average-gary/sv2-apps/tree/feat/coinbase-rotation)
- [Stratum V2 Reference Implementation](https://github.com/stratum-mining/stratum)
- [SRI Documentation](https://stratumprotocol.org/)

*License: MIT / Apache-2.0*

*Last updated: January 29, 2026*
