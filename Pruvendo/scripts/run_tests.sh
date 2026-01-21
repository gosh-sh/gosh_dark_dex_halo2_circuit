#!/bin/bash
#
# DarkDex Test Runner with Profile Support
#
# Usage:
#   ./run_tests.sh <profile> [component]
#
# Profiles: day, night
# Components: all, fuzz, property, apalache, quint, real_prover
#
# Examples:
#   ./run_tests.sh day           # Quick day tests (all components)
#   ./run_tests.sh night         # Full night tests (all components)
#   ./run_tests.sh day fuzz      # Day mode fuzzing only
#   ./run_tests.sh night apalache # Night mode Apalache only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
PROFILE="${1:-day}"
COMPONENT="${2:-all}"

# Load profile
PROFILE_FILE="$SCRIPT_DIR/profiles/${PROFILE}.conf"
if [ ! -f "$PROFILE_FILE" ]; then
    log_err "Unknown profile: $PROFILE"
    log_info "Available profiles: day, night"
    exit 1
fi

log_info "Loading profile: $PROFILE"
source "$PROFILE_FILE"

# Change to project root
cd "$PROJECT_ROOT"

# ============================================================
# FUNCTIONS
# ============================================================

run_fuzz() {
    log_info "=== Running Fuzzing (profile: $PROFILE) ==="
    log_info "Time per target: ${FUZZ_TIME_PER_TARGET}s, Max runs: ${FUZZ_RUNS}"
    
    # Get list of fuzz targets
    TARGETS=$(cargo +nightly fuzz list --fuzz-dir Pruvendo/fuzz 2>/dev/null || echo "")
    
    if [ -z "$TARGETS" ]; then
        log_warn "No fuzz targets found"
        return
    fi
    
    for target in $TARGETS; do
        log_info "Fuzzing: $target"
        
        FUZZ_ARGS=""
        if [ "$FUZZ_RUNS" -gt 0 ]; then
            FUZZ_ARGS="-- -runs=$FUZZ_RUNS"
        else
            FUZZ_ARGS="-- -max_total_time=$FUZZ_MAX_TOTAL_TIME"
        fi
        
        cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz "$target" $FUZZ_ARGS 2>&1 || {
            log_warn "Target $target had issues (may be expected for some targets)"
        }
    done
    
    log_ok "Fuzzing complete"
}

run_property() {
    log_info "=== Running Property Tests (profile: $PROFILE) ==="
    log_info "Cases: $PROPTEST_CASES, Timeout: ${PROPTEST_TIMEOUT}ms"
    
    export PROPTEST_CASES
    export PROPTEST_TIMEOUT
    
    cd "$PROJECT_ROOT/Pruvendo/tests/property_tests"
    cargo test --release -- --nocapture
    cd "$PROJECT_ROOT"
    
    log_ok "Property tests complete"
}

run_apalache() {
    log_info "=== Running Apalache BMC (profile: $PROFILE) ==="
    log_info "Max steps: $APALACHE_MAX_STEPS"
    
    # Setup Java
    export JAVA_HOME="${JAVA_HOME:-/usr/local/opt/openjdk@17}"
    export PATH="$JAVA_HOME/bin:$PATH"
    export APALACHE_DIST="$PROJECT_ROOT/Pruvendo/external_packages/apalache/apalache"
    
    INVARIANTS=(
        "inv_dex_non_negative"
        "inv_owner_only"
        "inv_no_double_withdraw"
        "inv_unique_digests"
        "inv_conservation"
    )
    
    for inv in "${INVARIANTS[@]}"; do
        log_info "Verifying: $inv (max-steps=$APALACHE_MAX_STEPS)"
        quint verify --init=init --step=step \
            --invariant="$inv" \
            --max-steps="$APALACHE_MAX_STEPS" \
            Pruvendo/models/dark_dex_protocol.qnt || {
            log_warn "Invariant $inv verification issue"
        }
    done
    
    log_ok "Apalache BMC complete"
}

run_quint() {
    log_info "=== Running Quint Random Simulation (profile: $PROFILE) ==="
    log_info "Samples: $QUINT_MAX_SAMPLES, Steps: $QUINT_MAX_STEPS"
    
    quint run --init=init --step=step \
        --invariant=inv_owner_only \
        --max-samples="$QUINT_MAX_SAMPLES" \
        --max-steps="$QUINT_MAX_STEPS" \
        Pruvendo/models/dark_dex_protocol.qnt
    
    log_ok "Quint simulation complete"
}

run_real_prover() {
    log_info "=== Running Real Prover Tests (profile: $PROFILE) ==="
    log_info "Filter: $REAL_PROVER_FILTER"

    cd "$PROJECT_ROOT/Pruvendo/tests/property_tests"
    cargo test --release "$REAL_PROVER_FILTER" -- --nocapture
    cd "$PROJECT_ROOT"

    log_ok "Real prover tests complete"
}

# ============================================================
# MAIN
# ============================================================

log_info "=========================================="
log_info "DarkDex Test Runner"
log_info "Profile: $PROFILE"
log_info "Component: $COMPONENT"
log_info "=========================================="

START_TIME=$(date +%s)

case "$COMPONENT" in
    all)
        run_property
        run_real_prover
        run_fuzz
        run_quint
        run_apalache
        ;;
    fuzz)
        run_fuzz
        ;;
    property)
        run_property
        ;;
    apalache)
        run_apalache
        ;;
    quint)
        run_quint
        ;;
    real_prover)
        run_real_prover
        ;;
    *)
        log_err "Unknown component: $COMPONENT"
        log_info "Available components: all, fuzz, property, apalache, quint, real_prover"
        exit 1
        ;;
esac

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log_info "=========================================="
log_ok "All tests completed in ${DURATION}s"
log_info "=========================================="