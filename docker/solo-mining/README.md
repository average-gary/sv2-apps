# SV2 Solo Mining on Bitcoin Testnet4

A complete, self-contained Docker setup for solo mining on Bitcoin testnet4 using Stratum V2.

## Repository

```bash
git clone git@github.com:average-gary/sv2-apps.git
cd sv2-apps
git checkout solo-mining-testnet4
cd docker/solo-mining
```

## What's Included

- **Bitcoin Core** - Testnet4 node with IPC enabled
- **JDC (Job Declarator Client)** - Pure solo mining mode, no pool required
- **Translator Proxy** - Bridges SV1 miners to SV2
- **Prometheus** - Metrics collection
- **Grafana** - Pre-configured dashboard

## Quick Start

### Option A: Interactive Setup Wizard (Recommended)

```bash
./setup-wizard.sh
```

The wizard will guide you through:
- Checking prerequisites (Docker, disk space, ports)
- Configuring your reward address
- Setting up for your miner type (CPU, USB, ASIC)
- Choosing your mining identity and block signature
- Starting all services

### Option B: Manual Setup

```bash
# 1. Configure your reward address
cp docker_env.solo.example docker_env.solo
# Edit docker_env.solo and set JDC_COINBASE_REWARD_SCRIPT to YOUR testnet4 address!

# 2. Start everything
docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d

# 3. Wait for Bitcoin Core to sync (JDC won't start until IBD is complete!)
./scripts/check-ibd-status.sh
# Or watch progress:
watch -n 10 ./scripts/check-ibd-status.sh

# 4. Connect your miner to: stratum+tcp://YOUR_IP:34255
```

## Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | admin / sv2mining |
| Prometheus | http://localhost:9090 | - |
| JDC Metrics | http://localhost:9091/metrics | - |
| Translator Metrics | http://localhost:9092/metrics | - |

## Miner Configuration

| Setting | Value |
|---------|-------|
| Pool URL | `stratum+tcp://YOUR_SERVER_IP:34255` |
| Username | anything (e.g., `worker1`) |
| Password | anything (e.g., `x`) |

## Documentation

See [SOLO-MINING-GUIDE.md](./SOLO-MINING-GUIDE.md) for comprehensive documentation including:

- Detailed setup instructions
- Native Linux installation
- Connecting different miner types
- Troubleshooting guide
- Architecture explanation

## Files

```
solo-mining/
├── docker-compose-solo.yml          # Main compose file
├── docker_env.solo.example          # Environment template (COPY THIS!)
├── config/
│   ├── jdc-solo-config.toml.template
│   └── translator-solo-config.toml.template
├── prometheus/
│   └── prometheus.yml
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/datasources.yml
│   │   └── dashboards/dashboards.yml
│   └── dashboards/
│       └── sv2-solo-mining.json
├── scripts/
│   └── check-ibd-status.sh          # Helper to check Bitcoin sync status
├── setup-wizard.sh                  # Interactive setup wizard
├── README.md                        # This file
└── SOLO-MINING-GUIDE.md            # Full guide (for GitHub Gist)
```

## Important Notes

1. **Set your reward address!** Edit `docker_env.solo` before starting
2. **JDC waits for IBD** - JDC and Translator won't start until Bitcoin Core finishes syncing (healthcheck verifies `initialblockdownload: false`)
3. **Testnet4 only** - This setup is configured for testnet4, not mainnet
4. **NTP required** - Ensure your system clock is synced for certificate validation
