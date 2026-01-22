# Solo Mining on Bitcoin Testnet4 with Stratum V2 (SV2)

A comprehensive guide for running a complete solo mining setup using the Stratum V2 Reference Implementation (SRI). This guide prioritizes Docker for ease of use, with a native Linux alternative for advanced users.

> **Repository**: This solo mining setup is available at:
> ```
> git clone git@github.com:average-gary/sv2-apps.git
> cd sv2-apps
> git checkout solo-mining-testnet4
> cd docker/solo-mining
> ```

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start (Docker)](#quick-start-docker)
4. [Detailed Docker Setup](#detailed-docker-setup)
5. [Native Linux Setup](#native-linux-setup)
6. [Connecting Miners](#connecting-miners)
7. [Monitoring & Metrics](#monitoring--metrics)
8. [Verifying Your Setup](#verifying-your-setup)
9. [Troubleshooting](#troubleshooting)
10. [Architecture Deep Dive](#architecture-deep-dive)

---

## Overview

### What is Stratum V2?

Stratum V2 (SV2) is the next-generation mining protocol that replaces the legacy Stratum V1. Key improvements include:

- **Encrypted connections** - No more plain-text mining traffic
- **Job declaration** - Miners can propose their own block templates
- **Reduced bandwidth** - Binary protocol is more efficient than JSON
- **Better security** - Protection against man-in-the-middle attacks

### What is Solo Mining?

Solo mining means you mine directly to your own Bitcoin node without joining a pool. When you find a valid block:

- **You keep 100% of the block reward** (subsidy + transaction fees)
- **Your coinbase address receives the coins directly**
- **You're competing against the entire network** (very unlikely to find blocks on mainnet!)

On **testnet4**, solo mining is practical for learning and testing because:
- Difficulty is much lower than mainnet
- Coins have no monetary value (safe to experiment)
- You can realistically find blocks with modest hardware

### What This Setup Provides

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Mining Setup                             │
│                                                                      │
│  ┌──────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │  Your Miner  │───▶│ Translator  │───▶│  Job Declarator Client  │ │
│  │   (SV1)      │    │   Proxy     │    │        (JDC)            │ │
│  │              │    │             │    │                         │ │
│  │ ASIC/CPU/GPU │    │ SV1 ──▶ SV2 │    │  Pure Solo Mining Mode  │ │
│  └──────────────┘    └─────────────┘    └───────────┬─────────────┘ │
│                                                     │               │
│                                                     ▼               │
│                                         ┌───────────────────────┐   │
│                                         │    Bitcoin Core       │   │
│                                         │     (Testnet4)        │   │
│                                         │                       │   │
│                                         │  ┌─────────────────┐  │   │
│                                         │  │ Block Templates │  │   │
│                                         │  │   via IPC       │  │   │
│                                         │  └─────────────────┘  │   │
│                                         └───────────────────────┘   │
│                                                                      │
│  ┌──────────────┐    ┌─────────────┐                                │
│  │   Grafana    │◀───│ Prometheus  │◀─── Metrics from JDC/Translator│
│  │  Dashboard   │    │             │                                │
│  └──────────────┘    └─────────────┘                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 50 GB SSD | 100+ GB SSD |
| Network | Stable internet | Low latency connection |

> **Note**: Testnet4 blockchain is ~5-10 GB. SSD strongly recommended for Bitcoin Core.

### Software Requirements

**For Docker Setup:**
- Docker Engine 20.10+
- Docker Compose v2+
- Git

**For Native Linux Setup:**
- Ubuntu 22.04+ / Debian 12+ (or similar)
- Rust 1.85.0+
- Bitcoin Core 28.0+
- capnproto libraries

### Generate a Testnet4 Address

You'll need a testnet4 address to receive mining rewards. Options:

**Option A: Using Bitcoin Core (after setup)**
```bash
# After Bitcoin Core is running
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  getnewaddress "solo-mining" bech32
```

**Option B: Using Sparrow Wallet**
1. Download [Sparrow Wallet](https://sparrowwallet.com/)
2. Create a new wallet, select "Testnet4" network
3. Get a receive address

---

## Quick Start (Docker)

For the impatient - get mining in 5 minutes:

### Option A: Use the Interactive Setup Wizard (Recommended)

```bash
# 1. Clone the repository (use the solo-mining branch)
git clone git@github.com:average-gary/sv2-apps.git
cd sv2-apps
git checkout solo-mining-testnet4
cd docker/solo-mining

# 2. Run the setup wizard
./setup-wizard.sh
```

The wizard will:
- Check all prerequisites (Docker, disk space, ports)
- Guide you through configuration (reward address, miner type, identity)
- Generate your `docker_env.solo` file
- Start all services
- Show you how to monitor progress and connect miners

### Option B: Manual Setup

```bash
# 1. Clone the repository (use the solo-mining branch)
git clone git@github.com:average-gary/sv2-apps.git
cd sv2-apps
git checkout solo-mining-testnet4
cd docker/solo-mining

# 2. Copy and edit environment file
cp docker_env.solo.example docker_env.solo

# 3. IMPORTANT: Edit docker_env.solo and set YOUR testnet4 address
#    Find this line and replace with your address:
#    JDC_COINBASE_REWARD_SCRIPT=addr(tb1qYOUR_TESTNET4_ADDRESS_HERE)
nano docker_env.solo  # or vim, or your preferred editor

# 4. Start the stack
docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d

# 5. Wait for Bitcoin Core to sync (check progress)
./scripts/check-ibd-status.sh

# 6. Once synced, point your miner to:
#    stratum+tcp://YOUR_SERVER_IP:34255
#    Username: anything (e.g., worker1)
#    Password: anything (e.g., x)
```

**Access Points:**
- Grafana Dashboard: http://localhost:3000 (admin/sv2mining)
- Prometheus: http://localhost:9090
- JDC Metrics: http://localhost:9091/metrics
- Translator Metrics: http://localhost:9092/metrics

---

## Detailed Docker Setup

### Step 1: Clone the Repository

```bash
# Clone the fork with solo mining setup
git clone git@github.com:average-gary/sv2-apps.git
cd sv2-apps
git checkout solo-mining-testnet4
cd docker/solo-mining
```

> **Tip**: You can run `./setup-wizard.sh` for an interactive guided setup instead of following these manual steps.

### Step 2: Understand the Directory Structure

```
solo-mining/
├── docker-compose-solo.yml      # Main compose file
├── docker_env.solo.example      # Environment template
├── setup-wizard.sh              # Interactive setup wizard
├── config/
│   ├── jdc-solo-config.toml.template      # JDC configuration
│   └── translator-solo-config.toml.template  # Translator configuration
├── prometheus/
│   └── prometheus.yml           # Prometheus scrape config
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── datasources.yml  # Prometheus datasource
│   │   └── dashboards/
│   │       └── dashboards.yml   # Dashboard provisioning
│   └── dashboards/
│       └── sv2-solo-mining.json # Pre-built dashboard
└── scripts/
    └── check-ibd-status.sh      # Bitcoin sync status checker
```

### Step 3: Configure Environment

```bash
# Copy the example file
cp docker_env.solo.example docker_env.solo

# Edit with your settings
nano docker_env.solo
```

**Critical settings to change:**

```bash
# YOUR MINING REWARD ADDRESS - CHANGE THIS!
JDC_COINBASE_REWARD_SCRIPT=addr(tb1qYOUR_ACTUAL_TESTNET4_ADDRESS)

# Your custom block signature (optional but fun)
JDC_SIGNATURE=MyFirstSoloBlock

# If connecting real ASICs, adjust hashrate:
# S19 XP: 140_000_000_000_000.0 (140 TH/s)
# S9:      14_000_000_000_000.0 (14 TH/s)
# For CPU testing: 1_000_000.0 (1 MH/s)
TPROXY_MIN_INDIVIDUAL_MINER_HASHRATE=1_000_000.0
```

### Step 4: Start the Stack

```bash
# Start all services
docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d

# View logs for all services
docker compose -f docker-compose-solo.yml logs -f

# Or view specific service logs
docker logs -f bitcoind-testnet4  # Bitcoin Core
docker logs -f jdc-solo           # JDC
docker logs -f translator-solo    # Translator
```

### Step 5: Wait for Initial Block Download (IBD)

Bitcoin Core needs to sync the testnet4 blockchain. This can take 30 minutes to several hours depending on your connection.

**Important**: JDC and Translator will NOT start until IBD is complete! The Docker healthcheck ensures `initialblockdownload: false` before dependent services start.

```bash
# Use the included helper script to check IBD status
./scripts/check-ibd-status.sh

# Or watch continuously (updates every 10 seconds)
watch -n 10 ./scripts/check-ibd-status.sh

# Manual check
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  getblockchaininfo

# Look for these indicators:
# "blocks": <current_height>
# "headers": <total_headers>
# "verificationprogress": 0.9999...  (1.0 = fully synced)
# "initialblockdownload": false      (false = synced, JDC will start!)
```

### Step 6: Verify Services Are Running

```bash
# Check all containers
docker ps

# Expected output:
# CONTAINER ID   IMAGE                           STATUS          PORTS
# xxxx           bitcoin/bitcoin:28.0            Up (healthy)    48332-48333
# xxxx           stratumv2/jd_client_sv2:main    Up (healthy)    9091, 34265
# xxxx           stratumv2/translator_sv2:main   Up (healthy)    9092, 34255
# xxxx           prom/prometheus:v2.51.0         Up              9090
# xxxx           grafana/grafana:10.4.0          Up              3000
```

### Step 7: Generate Your Reward Address (If Needed)

If you haven't already generated a testnet4 address:

```bash
# Create a wallet in Bitcoin Core
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  createwallet "solo-mining"

# Get a new address
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  -rpcwallet=solo-mining \
  getnewaddress "rewards" bech32

# Copy this address and update docker_env.solo:
# JDC_COINBASE_REWARD_SCRIPT=addr(<your_new_address>)

# Restart JDC to apply the new address
docker compose -f docker-compose-solo.yml --env-file docker_env.solo restart jd_client
```

---

## Native Linux Setup

For users who prefer running directly on the host system.

### Step 1: Install Dependencies

**Ubuntu/Debian:**
```bash
# System packages
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
  capnproto libcapnp-dev git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify Rust version (need 1.85.0+)
rustc --version
```

**Fedora:**
```bash
sudo dnf install -y gcc openssl-devel capnproto capnproto-devel git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Step 2: Install Bitcoin Core

```bash
# Download Bitcoin Core 28.0
wget https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-linux-gnu.tar.gz

# Verify (optional but recommended)
wget https://bitcoincore.org/bin/bitcoin-core-28.0/SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing

# Extract
tar -xzf bitcoin-28.0-x86_64-linux-gnu.tar.gz
sudo cp bitcoin-28.0/bin/* /usr/local/bin/
```

### Step 3: Configure Bitcoin Core

```bash
# Create data directory
mkdir -p ~/.bitcoin

# Create configuration file
cat > ~/.bitcoin/bitcoin.conf << 'EOF'
# Testnet4 configuration
[testnet4]
server=1
txindex=1

# RPC settings
rpcuser=sv2user
rpcpassword=sv2password
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Performance
dbcache=1000
EOF
```

### Step 4: Start Bitcoin Core with IPC

```bash
# Start in background with IPC enabled
bitcoind -testnet4 -ipcbind=unix -daemon

# Check it's running
bitcoin-cli -testnet4 getblockchaininfo

# Monitor sync progress
watch -n 10 'bitcoin-cli -testnet4 getblockchaininfo | grep -E "blocks|headers|progress"'
```

### Step 5: Build SV2 Applications

```bash
# Clone repository
git clone https://github.com/stratum-mining/sv2-apps.git
cd sv2-apps

# Build JDC (Job Declarator Client)
cd miner-apps/jd-client
cargo build --release

# Build Translator Proxy
cd ../translator
cargo build --release

# Binaries are in target/release/
ls ../../target/release/jd_client_sv2
ls ../../target/release/translator_sv2
```

### Step 6: Configure JDC for Solo Mining

```bash
# Copy example config
cd ~/sv2-apps/miner-apps/jd-client
cp config-examples/testnet4/jdc-config-bitcoin-core-ipc-local-infra-example.toml \
   jdc-solo-config.toml

# Edit configuration
nano jdc-solo-config.toml
```

**Key changes for pure solo mining:**

```toml
# Change listening address if needed
listening_address = "127.0.0.1:34265"

# SET YOUR REWARD ADDRESS!
coinbase_reward_script = "addr(tb1qYOUR_TESTNET4_ADDRESS_HERE)"

# Your custom block signature
jdc_signature = "MySoloMiner"

# REMOVE or COMMENT OUT the [[upstreams]] section entirely!
# This forces pure solo mining mode.
# [[upstreams]]
# authority_pubkey = "..."
# pool_address = "..."
# ...

# Ensure Bitcoin Core IPC is configured
[template_provider_type.BitcoinCoreIpc]
network = "testnet4"
fee_threshold = 100
min_interval = 5
```

### Step 7: Configure Translator Proxy

```bash
cd ~/sv2-apps/miner-apps/translator
cp config-examples/testnet4/tproxy-config-local-jdc-example.toml \
   tproxy-solo-config.toml

nano tproxy-solo-config.toml
```

**Key settings:**

```toml
# Listen for SV1 miners
downstream_address = "0.0.0.0"
downstream_port = 34255

# Connect to local JDC
[[upstreams]]
address = "127.0.0.1"
port = 34265
authority_pubkey = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"

# Adjust for your miners' hashrate
[downstream_difficulty_config]
min_individual_miner_hashrate = 1_000_000.0  # 1 MH/s for testing
shares_per_minute = 6.0
enable_vardiff = false
```

### Step 8: Run the Stack

```bash
# Terminal 1: Run JDC
cd ~/sv2-apps
./target/release/jd_client_sv2 -c miner-apps/jd-client/jdc-solo-config.toml

# Terminal 2: Run Translator
./target/release/translator_sv2 -c miner-apps/translator/tproxy-solo-config.toml
```

**Using systemd (recommended for production):**

```bash
# Create JDC service
sudo tee /etc/systemd/system/jdc-solo.service << 'EOF'
[Unit]
Description=SV2 Job Declarator Client (Solo Mining)
After=network.target bitcoind.service

[Service]
Type=simple
User=YOUR_USER
ExecStart=/home/YOUR_USER/sv2-apps/target/release/jd_client_sv2 \
  -c /home/YOUR_USER/sv2-apps/miner-apps/jd-client/jdc-solo-config.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create Translator service
sudo tee /etc/systemd/system/translator-solo.service << 'EOF'
[Unit]
Description=SV2 Translator Proxy (Solo Mining)
After=network.target jdc-solo.service

[Service]
Type=simple
User=YOUR_USER
ExecStart=/home/YOUR_USER/sv2-apps/target/release/translator_sv2 \
  -c /home/YOUR_USER/sv2-apps/miner-apps/translator/tproxy-solo-config.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now jdc-solo translator-solo

# Check status
sudo systemctl status jdc-solo translator-solo
```

---

## Connecting Miners

### SV1 Miners (Most ASICs)

Point your miner to the Translator Proxy:

| Setting | Value |
|---------|-------|
| **Pool URL** | `stratum+tcp://YOUR_SERVER_IP:34255` |
| **Username** | Anything (e.g., `worker1`, `miner.001`) |
| **Password** | Anything (e.g., `x`, `password`) |

**Example configurations:**

**Antminer S19:**
```
Pool 1: stratum+tcp://192.168.1.100:34255
Worker: s19-rack1
Password: x
```

**Whatsminer M30S:**
```
Pool 1: 192.168.1.100:34255
Worker: m30s-001
Password: x
```

### SV2 Native Miners

If you have an SV2-compatible miner, connect directly to JDC:

| Setting | Value |
|---------|-------|
| **Address** | `YOUR_SERVER_IP:34265` |
| **Authority Public Key** | `9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72` |

### CPU Mining (For Testing)

Use the included mining device simulator:

```bash
# Docker method
docker run --rm --network sv2_solo \
  stratumv2/mining_device:main \
  --address-pool 172.30.0.21:34255 \
  --id-device cpu-test \
  --handicap 1000

# Native method
cd ~/sv2-apps/miner-apps/mining-device
cargo run --release -- \
  --address-pool 127.0.0.1:34255 \
  --id-device cpu-test \
  --handicap 1000  # Slow down to prevent overheating
```

---

## Monitoring & Metrics

### Grafana Dashboard

Access at: **http://localhost:3000**

Default credentials:
- Username: `admin`
- Password: `sv2mining`

The pre-configured dashboard shows:
- JDC and Translator status
- Connected miners count
- Share submission rate
- Block templates received
- Memory usage

### Prometheus

Access at: **http://localhost:9090**

Useful queries:
```promql
# Service health
up{job=~"jdc|translator"}

# Share rate
rate(sv2_shares_submitted_total[5m])

# Connected miners
sv2_downstream_connections_total

# Memory usage
process_resident_memory_bytes{job=~"jdc|translator"}
```

### Raw Metrics Endpoints

- JDC: http://localhost:9091/metrics
- Translator: http://localhost:9092/metrics

---

## Verifying Your Setup

### 1. Check Bitcoin Core Sync

```bash
# Docker
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  getblockchaininfo

# Native
bitcoin-cli -testnet4 getblockchaininfo
```

Look for:
- `"initialblockdownload": false`
- `"verificationprogress": 0.9999...`

### 2. Check JDC is in Solo Mining Mode

Look for these log messages:

```
INFO Fallback to solo mining mode
INFO Template Receiver is running
INFO Downstream server listening on 0.0.0.0:34265
```

### 3. Check Translator is Connected

```
INFO Connected to upstream JDC at 172.30.0.20:34265
INFO Downstream server listening on 0.0.0.0:34255
```

### 4. Verify Miner Connection

When a miner connects, you should see:

```
INFO New downstream connection from 192.168.1.50:54321
INFO Opened standard channel for worker1
```

### 5. Check Shares Are Being Submitted

```
INFO Received share from worker1
INFO Share accepted
```

### 6. Monitor for Found Blocks

If you find a block (rare on testnet4 without significant hashrate):

```
INFO Found valid block at height XXXXX!
INFO Block submitted to Bitcoin network
```

Check your reward address:
```bash
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  getbalance
```

---

## Troubleshooting

### Bitcoin Core Won't Start

**Issue:** Container exits immediately

```bash
# Check logs
docker logs bitcoind-testnet4

# Common fixes:
# 1. Insufficient disk space
df -h

# 2. Permission issues
sudo chown -R 1000:1000 /var/lib/docker/volumes/sv2-solo-bitcoin-data

# 3. Port conflict
sudo lsof -i :48332
```

### JDC Can't Connect to Bitcoin Core

**Issue:** "Failed to connect to Bitcoin Core IPC"

```bash
# Check Bitcoin Core is running and synced
docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \
  -rpcuser=sv2user -rpcpassword=sv2password \
  getblockchaininfo

# Check IPC socket exists
docker exec bitcoind-testnet4 ls -la /home/bitcoin/.bitcoin/testnet4/node.sock

# Verify volume mount
docker inspect jdc-solo | grep -A5 Mounts
```

### Translator Can't Connect to JDC

**Issue:** "Connection refused to JDC"

```bash
# Check JDC is running
docker ps | grep jdc

# Check JDC logs for errors
docker logs jdc-solo

# Test connectivity
docker exec translator-solo wget -q --spider http://172.30.0.20:9091/metrics && echo "OK"
```

### Miner Can't Connect

**Issue:** Miner shows "Connection failed"

```bash
# Check Translator is listening
docker exec translator-solo netstat -tlnp | grep 34255

# Check firewall
sudo ufw status
sudo ufw allow 34255/tcp

# Test from miner's network
nc -zv YOUR_SERVER_IP 34255
```

### Shares Rejected

**Issue:** "Share rejected" or "Invalid share"

Common causes:
1. **Difficulty too high**: Lower `min_individual_miner_hashrate` in translator config
2. **Stale shares**: Check network latency, reduce `min_interval` in JDC config
3. **Clock skew**: Ensure NTP is working: `timedatectl status`

### Certificate Errors

**Issue:** "InvalidCertificate" errors

```bash
# Sync system time
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd

# Verify time is correct
date
```

### Out of Memory

**Issue:** Containers getting OOM killed

```bash
# Check memory usage
docker stats

# Increase Bitcoin Core dbcache or reduce it
# Edit docker-compose-solo.yml, add to bitcoind command:
- -dbcache=500  # Reduce from default
```

---

## Architecture Deep Dive

### Component Responsibilities

**Bitcoin Core (bitcoind)**
- Maintains the testnet4 blockchain
- Provides block templates via IPC
- Validates and broadcasts found blocks
- Manages mempool for transaction selection

**Job Declarator Client (JDC)**
- Receives block templates from Bitcoin Core
- Constructs mining jobs with YOUR coinbase address
- Sends jobs to downstream (Translator/miners)
- Validates shares and submits valid blocks
- In solo mode: No upstream pool, direct block submission

**Translator Proxy**
- Accepts SV1 (legacy Stratum) connections
- Translates SV1 ↔ SV2 protocol messages
- Manages difficulty for individual miners
- Routes shares to JDC

### Data Flow

```
1. Bitcoin Core generates block template (via IPC)
         ↓
2. JDC receives template, creates mining job with your coinbase
         ↓
3. JDC sends job to Translator (SV2 protocol)
         ↓
4. Translator converts job to SV1 format
         ↓
5. Miner receives job, starts hashing
         ↓
6. Miner finds share, sends to Translator (SV1)
         ↓
7. Translator converts share to SV2, sends to JDC
         ↓
8. JDC validates share
   - If valid share (meets difficulty): Acknowledged
   - If valid block (meets network difficulty): Submitted to Bitcoin Core!
         ↓
9. Bitcoin Core broadcasts block to network
```

### Network Ports

| Port | Service | Protocol | Purpose |
|------|---------|----------|---------|
| 48332 | Bitcoin Core | RPC | JSON-RPC interface |
| 48333 | Bitcoin Core | P2P | Bitcoin network |
| 34265 | JDC | SV2 | Mining protocol (Translator connects here) |
| 34255 | Translator | SV1 | Legacy Stratum (miners connect here) |
| 9090 | Prometheus | HTTP | Metrics UI |
| 9091 | JDC | HTTP | Prometheus metrics |
| 9092 | Translator | HTTP | Prometheus metrics |
| 3000 | Grafana | HTTP | Dashboard UI |

---

## Additional Resources

- [Stratum V2 Documentation](https://stratumprotocol.org)
- [SRI GitHub Repository](https://github.com/stratum-mining/sv2-apps)
- [Bitcoin Core Documentation](https://bitcoincore.org/en/doc/)
- [SV2 Discord Community](https://discord.gg/fsEW23wFYs)

---

## License

This guide and the associated configuration files are part of the SV2 Apps repository, licensed under Apache 2.0 or MIT.

---

*Happy Solo Mining! May your hashes be ever valid.* 
