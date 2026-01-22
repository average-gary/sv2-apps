#!/bin/bash
# =============================================================================
# SV2 Solo Mining Setup Wizard for Bitcoin Testnet4
# =============================================================================
#
# This interactive wizard will guide you through setting up a complete
# solo mining environment using Stratum V2 on Bitcoin testnet4.
#
# Usage: ./setup-wizard.sh
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/docker_env.solo"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose-solo.yml"

# =============================================================================
# Helper Functions
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║   ███████╗██╗   ██╗██████╗     ███████╗ ██████╗ ██╗      ██████╗  ║"
    echo "║   ██╔════╝██║   ██║╚════██╗    ██╔════╝██╔═══██╗██║     ██╔═══██╗ ║"
    echo "║   ███████╗██║   ██║ █████╔╝    ███████╗██║   ██║██║     ██║   ██║ ║"
    echo "║   ╚════██║╚██╗ ██╔╝██╔═══╝     ╚════██║██║   ██║██║     ██║   ██║ ║"
    echo "║   ███████║ ╚████╔╝ ███████╗    ███████║╚██████╔╝███████╗╚██████╔╝ ║"
    echo "║   ╚══════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝  ║"
    echo "║                                                                   ║"
    echo "║            Solo Mining Setup Wizard - Bitcoin Testnet4            ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${GREEN}STEP $1:${NC} ${BOLD}$2${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_info() {
    echo -e "${CYAN}ℹ${NC}  $1"
}

print_success() {
    echo -e "${GREEN}✓${NC}  $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

print_error() {
    echo -e "${RED}✗${NC}  $1"
}

prompt_continue() {
    echo ""
    read -p "Press Enter to continue..."
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" response
    response="${response:-$default}"
    
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

validate_address() {
    local address="$1"
    # Basic validation for testnet4 bech32 addresses
    if [[ "$address" =~ ^tb1[a-zA-HJ-NP-Z0-9]{25,62}$ ]]; then
        return 0
    else
        return 1
    fi
}

# =============================================================================
# Prerequisite Checks
# =============================================================================

check_prerequisites() {
    print_step "1" "Checking Prerequisites"
    
    local all_good=true
    
    # Check Docker
    echo -n "Checking Docker... "
    if command -v docker &> /dev/null; then
        local docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
        print_success "Docker $docker_version found"
    else
        print_error "Docker not found"
        echo "       Please install Docker: https://docs.docker.com/get-docker/"
        all_good=false
    fi
    
    # Check Docker Compose
    echo -n "Checking Docker Compose... "
    if docker compose version &> /dev/null; then
        local compose_version=$(docker compose version | grep -oE '[0-9]+\.[0-9]+' | head -1)
        print_success "Docker Compose $compose_version found"
    else
        print_error "Docker Compose not found"
        echo "       Please install Docker Compose v2+"
        all_good=false
    fi
    
    # Check Docker daemon
    echo -n "Checking Docker daemon... "
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_error "Docker daemon is not running"
        echo "       Please start Docker Desktop or the Docker service"
        all_good=false
    fi
    
    # Check disk space
    echo -n "Checking disk space... "
    local available_gb=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$available_gb" -ge 50 ]; then
        print_success "${available_gb}GB available (50GB+ recommended)"
    else
        print_warning "${available_gb}GB available (50GB+ recommended for testnet4)"
    fi
    
    # Check if ports are available
    echo -n "Checking port availability... "
    local ports_in_use=""
    for port in 3000 9090 9091 9092 34255 34265 48332 48333; do
        if lsof -Pi :$port -sTCP:LISTEN -t &> /dev/null; then
            ports_in_use="$ports_in_use $port"
        fi
    done
    
    if [ -z "$ports_in_use" ]; then
        print_success "All required ports are available"
    else
        print_warning "Ports in use:$ports_in_use"
        echo "       You may need to stop other services or modify the compose file"
    fi
    
    if [ "$all_good" = false ]; then
        echo ""
        print_error "Some prerequisites are missing. Please install them and try again."
        exit 1
    fi
    
    prompt_continue
}

# =============================================================================
# Configuration
# =============================================================================

configure_reward_address() {
    print_step "2" "Configure Mining Reward Address"
    
    echo -e "When you find a block, the mining reward goes to YOUR address."
    echo -e "You need a ${BOLD}Bitcoin testnet4${NC} address (starts with 'tb1')."
    echo ""
    echo -e "${YELLOW}How to get a testnet4 address:${NC}"
    echo ""
    echo "  Option 1: We'll generate one using Bitcoin Core after it syncs"
    echo "            (Recommended - keys stay on your machine)"
    echo ""
    echo "  Option 2: Use Sparrow Wallet"
    echo "            - Download from https://sparrowwallet.com/"
    echo "            - Create wallet on 'Testnet4' network"
    echo "            - Get a receive address"
    echo ""
    
    if prompt_yes_no "Do you already have a testnet4 address?"; then
        while true; do
            echo ""
            read -p "Enter your testnet4 address (tb1...): " reward_address
            
            if validate_address "$reward_address"; then
                print_success "Address format looks valid"
                REWARD_ADDRESS="$reward_address"
                break
            else
                print_error "Invalid address format. Testnet4 addresses start with 'tb1'"
                if ! prompt_yes_no "Try again?"; then
                    echo ""
                    print_info "We'll use a placeholder. You can update it later in docker_env.solo"
                    REWARD_ADDRESS="GENERATE_AFTER_SYNC"
                    break
                fi
            fi
        done
    else
        echo ""
        print_info "No problem! We'll generate one after Bitcoin Core syncs."
        print_info "The wizard will remind you to update the configuration."
        REWARD_ADDRESS="GENERATE_AFTER_SYNC"
    fi
    
    prompt_continue
}

configure_miner_settings() {
    print_step "3" "Configure Miner Settings"
    
    echo "What type of miner will you be connecting?"
    echo ""
    echo "  1) CPU Miner (testing/development)"
    echo "  2) USB Miner (e.g., FutureBit Apollo, GekkoScience)"
    echo "  3) ASIC - Low power (e.g., Antminer S9, ~14 TH/s)"
    echo "  4) ASIC - Mid power (e.g., Antminer S19, ~100 TH/s)"
    echo "  5) ASIC - High power (e.g., S19 XP, S21, ~140+ TH/s)"
    echo "  6) Custom (enter your own hashrate)"
    echo ""
    
    read -p "Select option [1-6]: " miner_choice
    
    case "$miner_choice" in
        1)
            MINER_HASHRATE="1_000_000.0"
            MINER_TYPE="CPU Miner"
            ;;
        2)
            MINER_HASHRATE="500_000_000_000.0"
            MINER_TYPE="USB Miner"
            ;;
        3)
            MINER_HASHRATE="14_000_000_000_000.0"
            MINER_TYPE="ASIC (S9 class)"
            ;;
        4)
            MINER_HASHRATE="100_000_000_000_000.0"
            MINER_TYPE="ASIC (S19 class)"
            ;;
        5)
            MINER_HASHRATE="140_000_000_000_000.0"
            MINER_TYPE="ASIC (S19 XP/S21 class)"
            ;;
        6)
            echo ""
            echo "Enter hashrate in H/s (e.g., 14000000000000 for 14 TH/s)"
            read -p "Hashrate: " custom_hashrate
            MINER_HASHRATE="${custom_hashrate}.0"
            MINER_TYPE="Custom"
            ;;
        *)
            print_warning "Invalid choice, defaulting to CPU Miner"
            MINER_HASHRATE="1_000_000.0"
            MINER_TYPE="CPU Miner"
            ;;
    esac
    
    print_success "Configured for: $MINER_TYPE"
    
    prompt_continue
}

configure_identity() {
    print_step "4" "Configure Your Mining Identity"
    
    echo "Choose a username and block signature for your mining operation."
    echo ""
    
    # Username
    read -p "Mining username [solo_miner]: " username
    MINER_USERNAME="${username:-solo_miner}"
    
    echo ""
    
    # Block signature
    echo "Block signature appears in the coinbase of blocks you mine."
    echo "It's like graffiti - your mark on the blockchain!"
    echo ""
    read -p "Block signature [SoloMinedWithSV2]: " signature
    BLOCK_SIGNATURE="${signature:-SoloMinedWithSV2}"
    
    echo ""
    print_success "Username: $MINER_USERNAME"
    print_success "Block signature: $BLOCK_SIGNATURE"
    
    prompt_continue
}

configure_grafana() {
    print_step "5" "Configure Monitoring (Grafana)"
    
    echo "Grafana provides a web dashboard for monitoring your mining operation."
    echo "Access it at: http://localhost:3000"
    echo ""
    
    read -p "Grafana admin username [admin]: " grafana_user
    GRAFANA_USER="${grafana_user:-admin}"
    
    while true; do
        read -sp "Grafana admin password [sv2mining]: " grafana_pass
        echo ""
        GRAFANA_PASS="${grafana_pass:-sv2mining}"
        
        if [ ${#GRAFANA_PASS} -lt 4 ]; then
            print_warning "Password should be at least 4 characters"
        else
            break
        fi
    done
    
    echo ""
    print_success "Grafana credentials configured"
    
    prompt_continue
}

# =============================================================================
# Generate Configuration
# =============================================================================

generate_config() {
    print_step "6" "Generating Configuration"
    
    # Check if config already exists
    if [ -f "$ENV_FILE" ]; then
        print_warning "Configuration file already exists: docker_env.solo"
        if prompt_yes_no "Overwrite existing configuration?" "n"; then
            cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
            print_info "Backup created"
        else
            print_info "Keeping existing configuration"
            return
        fi
    fi
    
    # Generate the configuration file
    cat > "$ENV_FILE" << EOF
# =============================================================================
# SV2 Solo Mining Configuration
# Generated by setup wizard on $(date)
# =============================================================================

# Bitcoin Core RPC credentials
BITCOIN_RPC_USER=sv2user
BITCOIN_RPC_PASS=sv2password

# JDC Settings
JDC_USER_IDENTITY=${MINER_USERNAME}
JDC_SHARES_PER_MINUTE=6.0
JDC_SHARE_BATCH_SIZE=10
JDC_SIGNATURE=${BLOCK_SIGNATURE}
JDC_FEE_THRESHOLD=100
JDC_MIN_INTERVAL=5

# Coinbase reward address
# $(if [ "$REWARD_ADDRESS" = "GENERATE_AFTER_SYNC" ]; then echo "TODO: Update this after Bitcoin Core syncs!"; else echo "Your testnet4 reward address"; fi)
JDC_COINBASE_REWARD_SCRIPT=addr(${REWARD_ADDRESS})

# Translator Settings
TPROXY_USER_IDENTITY=${MINER_USERNAME}
TPROXY_MIN_INDIVIDUAL_MINER_HASHRATE=${MINER_HASHRATE}
TPROXY_SHARES_PER_MINUTE=6.0

# Grafana Settings
GRAFANA_ADMIN_USER=${GRAFANA_USER}
GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASS}
EOF

    print_success "Configuration saved to: docker_env.solo"
}

# =============================================================================
# Start Services
# =============================================================================

start_services() {
    print_step "7" "Starting Services"
    
    echo "Ready to start the solo mining stack!"
    echo ""
    echo "This will start:"
    echo "  - Bitcoin Core (testnet4) - will sync blockchain"
    echo "  - JDC (Job Declarator Client) - starts after sync"
    echo "  - Translator Proxy - starts after sync"
    echo "  - Prometheus - metrics collection"
    echo "  - Grafana - monitoring dashboard"
    echo ""
    
    if ! prompt_yes_no "Start the mining stack now?"; then
        echo ""
        print_info "You can start later with:"
        echo "       cd $SCRIPT_DIR"
        echo "       docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d"
        return
    fi
    
    echo ""
    print_info "Starting services..."
    echo ""
    
    cd "$SCRIPT_DIR"
    docker compose -f docker-compose-solo.yml --env-file docker_env.solo up -d
    
    echo ""
    print_success "Services started!"
}

# =============================================================================
# Post-Setup Instructions
# =============================================================================

show_post_setup() {
    print_step "8" "Setup Complete!"
    
    echo -e "${GREEN}Your solo mining stack is now starting!${NC}"
    echo ""
    
    if [ "$REWARD_ADDRESS" = "GENERATE_AFTER_SYNC" ]; then
        echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  IMPORTANT: You still need to set your reward address!            ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "After Bitcoin Core syncs, run these commands to generate an address:"
        echo ""
        echo -e "  ${CYAN}# Create a wallet${NC}"
        echo "  docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \\"
        echo "    -rpcuser=sv2user -rpcpassword=sv2password \\"
        echo "    createwallet \"solo-mining\""
        echo ""
        echo -e "  ${CYAN}# Get a new address${NC}"
        echo "  docker exec bitcoind-testnet4 bitcoin-cli -testnet4 \\"
        echo "    -rpcuser=sv2user -rpcpassword=sv2password \\"
        echo "    -rpcwallet=solo-mining getnewaddress \"rewards\" bech32"
        echo ""
        echo "Then update docker_env.solo with your address and restart JDC:"
        echo "  nano docker_env.solo"
        echo "  docker compose -f docker-compose-solo.yml --env-file docker_env.solo restart jd_client"
        echo ""
    fi
    
    echo -e "${BOLD}Monitor Bitcoin Core sync progress:${NC}"
    echo "  ./scripts/check-ibd-status.sh"
    echo "  watch -n 10 ./scripts/check-ibd-status.sh"
    echo ""
    
    echo -e "${BOLD}View logs:${NC}"
    echo "  docker compose -f docker-compose-solo.yml logs -f           # All services"
    echo "  docker logs -f bitcoind-testnet4                            # Bitcoin Core"
    echo "  docker logs -f jdc-solo                                     # JDC"
    echo "  docker logs -f translator-solo                              # Translator"
    echo ""
    
    echo -e "${BOLD}Access points (after sync):${NC}"
    echo "  Grafana Dashboard:    http://localhost:3000  (${GRAFANA_USER}/${GRAFANA_PASS})"
    echo "  Prometheus:           http://localhost:9090"
    echo "  JDC Metrics:          http://localhost:9091/metrics"
    echo "  Translator Metrics:   http://localhost:9092/metrics"
    echo ""
    
    echo -e "${BOLD}Connect your miner to:${NC}"
    echo "  Pool URL:   stratum+tcp://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_SERVER_IP"):34255"
    echo "  Username:   ${MINER_USERNAME} (or any string)"
    echo "  Password:   x (or any string)"
    echo ""
    
    echo -e "${BOLD}Useful commands:${NC}"
    echo "  # Stop all services"
    echo "  docker compose -f docker-compose-solo.yml down"
    echo ""
    echo "  # Stop and remove all data (start fresh)"
    echo "  docker compose -f docker-compose-solo.yml down -v"
    echo ""
    echo "  # Restart a specific service"
    echo "  docker compose -f docker-compose-solo.yml restart jd_client"
    echo ""
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}Happy Solo Mining! May your hashes be ever valid.${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    print_banner
    
    echo "Welcome to the SV2 Solo Mining Setup Wizard!"
    echo ""
    echo "This wizard will help you set up a complete solo mining environment"
    echo "on Bitcoin testnet4 using Stratum V2."
    echo ""
    echo "What you'll need:"
    echo "  - Docker and Docker Compose installed"
    echo "  - ~50GB disk space for testnet4 blockchain"
    echo "  - A Bitcoin testnet4 address (we can help generate one)"
    echo ""
    
    if ! prompt_yes_no "Ready to begin?"; then
        echo ""
        echo "No problem! Run this script again when you're ready."
        exit 0
    fi
    
    check_prerequisites
    configure_reward_address
    configure_miner_settings
    configure_identity
    configure_grafana
    generate_config
    start_services
    show_post_setup
}

# Run main function
main "$@"
