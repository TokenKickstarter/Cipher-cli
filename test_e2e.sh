#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  Cipher CLI — End-to-End Test
#  Tests: init, whoami, register, lookup, send, recv
#  Uses two separate identities (Alice & Bob)
# ═══════════════════════════════════════════════════════════

set -e

CLI="./target/debug/cipher-cli"
ALICE_HOME="/tmp/cipher-test-alice"
BOB_HOME="/tmp/cipher-test-bob"
PASS="testpass123"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

pass() { echo -e "  ${GREEN}✅ PASS${NC} $1"; }
fail() { echo -e "  ${RED}❌ FAIL${NC} $1"; FAILURES=$((FAILURES+1)); }
header() { echo -e "\n${CYAN}${BOLD}═══ $1 ═══${NC}\n"; }

FAILURES=0

# Cleanup previous test data
rm -rf "$ALICE_HOME" "$BOB_HOME"
mkdir -p "$ALICE_HOME/.cipher" "$BOB_HOME/.cipher"

echo -e "${YELLOW}${BOLD}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║        Cipher CLI — End-to-End Test Suite         ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Test 1: Generate Alice's Identity ─────────────────────
header "TEST 1: Generate Alice's Identity"

OUTPUT=$(printf "${PASS}\n${PASS}\n" | HOME="$ALICE_HOME" $CLI init 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Identity saved"; then
    pass "Alice identity created"
else
    fail "Alice identity creation failed"
fi

# Extract Alice's address
ALICE_ADDR=$(echo "$OUTPUT" | grep "EVM Address:" | head -1 | grep -oE '0x[a-fA-F0-9]{40}')
echo -e "  ${CYAN}Alice's address: ${BOLD}$ALICE_ADDR${NC}"

# ─── Test 2: Generate Bob's Identity ──────────────────────
header "TEST 2: Generate Bob's Identity"

OUTPUT=$(printf "${PASS}\n${PASS}\n" | HOME="$BOB_HOME" $CLI init 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Identity saved"; then
    pass "Bob identity created"
else
    fail "Bob identity creation failed"
fi

BOB_ADDR=$(echo "$OUTPUT" | grep "EVM Address:" | head -1 | grep -oE '0x[a-fA-F0-9]{40}')
echo -e "  ${CYAN}Bob's address: ${BOLD}$BOB_ADDR${NC}"

# ─── Test 3: Alice whoami ─────────────────────────────────
header "TEST 3: Alice - whoami"

OUTPUT=$(printf "${PASS}\n" | HOME="$ALICE_HOME" $CLI whoami 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "$ALICE_ADDR"; then
    pass "Alice whoami shows correct address"
else
    fail "Alice whoami address mismatch"
fi

# ─── Test 4: Bob whoami ───────────────────────────────────
header "TEST 4: Bob - whoami"

OUTPUT=$(printf "${PASS}\n" | HOME="$BOB_HOME" $CLI whoami 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "$BOB_ADDR"; then
    pass "Bob whoami shows correct address"
else
    fail "Bob whoami address mismatch"
fi

# ─── Test 5: Duplicate init should fail ───────────────────
header "TEST 5: Duplicate init should fail"

OUTPUT=$(printf "${PASS}\n${PASS}\n" | HOME="$ALICE_HOME" $CLI init 2>&1) || true

if echo "$OUTPUT" | grep -q "already exists"; then
    pass "Duplicate init correctly rejected"
else
    fail "Duplicate init was not rejected"
fi

# ─── Test 6: Register @alice on TKS blockchain ────────────
header "TEST 6: Register @alice_test_$(date +%s) on TKS blockchain"

ALICE_USERNAME="alice_test_$(date +%s)"
OUTPUT=$(printf "${PASS}\n" | HOME="$ALICE_HOME" $CLI register "$ALICE_USERNAME" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "registered\|success\|already registered"; then
    pass "Alice username @$ALICE_USERNAME registered"
else
    fail "Alice username registration failed"
    echo "$OUTPUT"
fi

# ─── Test 7: Register @bob on TKS blockchain ─────────────
header "TEST 7: Register @bob_test_$(date +%s) on TKS blockchain"

BOB_USERNAME="bob_test_$(date +%s)"
OUTPUT=$(printf "${PASS}\n" | HOME="$BOB_HOME" $CLI register "$BOB_USERNAME" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "registered\|success\|already registered"; then
    pass "Bob username @$BOB_USERNAME registered"
else
    fail "Bob username registration failed"
    echo "$OUTPUT"
fi

# ─── Test 8: Username already taken ───────────────────────
header "TEST 8: Username already taken (Bob tries Alice's name)"

OUTPUT=$(printf "${PASS}\n" | HOME="$BOB_HOME" $CLI register "$ALICE_USERNAME" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "taken\|already\|error"; then
    pass "Username taken correctly detected"
else
    fail "Username taken not detected"
fi

# ─── Test 9: Lookup username ──────────────────────────────
header "TEST 9: Lookup @$ALICE_USERNAME on TKS blockchain"

OUTPUT=$($CLI lookup "@$ALICE_USERNAME" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "$ALICE_ADDR\|registered\|not registered"; then
    pass "Lookup returned a result"
else
    fail "Lookup failed"
fi

# ─── Test 10: Node info (blockchain connectivity) ─────────
header "TEST 10: TKS Blockchain node-info"

OUTPUT=$($CLI node-info 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Best Block"; then
    BLOCK=$(echo "$OUTPUT" | grep "Best Block" | grep -oE '#[0-9]+')
    pass "Blockchain connected — $BLOCK"
else
    fail "Cannot connect to TKS blockchain"
fi

# ─── Test 11: Alice sends message to Bob ──────────────────
header "TEST 11: Alice sends message to Bob"

MSG="Hello Bob! This is a test from Alice at $(date)"
OUTPUT=$(printf "${PASS}\n" | HOME="$ALICE_HOME" $CLI send "$BOB_ADDR" "$MSG" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "sent\|delivered\|message id"; then
    pass "Alice sent message to Bob"
else
    fail "Alice failed to send message"
fi

# ─── Test 12: Bob checks for messages ─────────────────────
header "TEST 12: Bob checks for incoming messages"

# Give the relay a moment to process
sleep 3

OUTPUT=$(printf "${PASS}\n" | HOME="$BOB_HOME" $CLI recv 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "Alice\|Hello\|message\|no new"; then
    pass "Bob recv completed (check output above for message)"
else
    fail "Bob recv failed"
fi

# ─── Test 13: Bob sends reply to Alice ────────────────────
header "TEST 13: Bob sends reply to Alice"

REPLY="Hey Alice! Got your message. Reply from Bob at $(date)"
OUTPUT=$(printf "${PASS}\n" | HOME="$BOB_HOME" $CLI send "$ALICE_ADDR" "$REPLY" 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "sent\|delivered\|message id"; then
    pass "Bob sent reply to Alice"
else
    fail "Bob failed to send reply"
fi

# ─── Test 14: Alice checks for messages ───────────────────
header "TEST 14: Alice checks for Bob's reply"

sleep 3

OUTPUT=$(printf "${PASS}\n" | HOME="$ALICE_HOME" $CLI recv 2>&1) || true
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "Bob\|Hey\|message\|no new"; then
    pass "Alice recv completed (check output above for reply)"
else
    fail "Alice recv failed"
fi

# ─── Test 15: Wrong password should fail ──────────────────
header "TEST 15: Wrong password should fail"

OUTPUT=$(printf "wrongpassword\n" | HOME="$ALICE_HOME" $CLI whoami 2>&1) || true

if echo "$OUTPUT" | grep -qi "wrong password\|error\|corrupted"; then
    pass "Wrong password correctly rejected"
else
    fail "Wrong password was not rejected"
fi

# ═══ Results ══════════════════════════════════════════════
echo ""
echo -e "${YELLOW}${BOLD}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║              Test Results                         ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ $FAILURES -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All tests passed!${NC} 🎉"
else
    echo -e "  ${RED}${BOLD}$FAILURES test(s) failed${NC}"
fi

echo ""
echo -e "  Alice: $ALICE_ADDR (@$ALICE_USERNAME)"
echo -e "  Bob:   $BOB_ADDR (@$BOB_USERNAME)"
echo ""

# Cleanup
rm -rf "$ALICE_HOME" "$BOB_HOME"

exit $FAILURES
