#!/bin/bash

# CryptoShield SDK - Vault KMS Envelope Encryption Test Runner
# This script sets up the environment and runs comprehensive tests

set -e  # Exit on error

echo "🔐 CryptoShield Vault KMS Test Runner"
echo "======================================"

# Configuration
VAULT_ENDPOINT="${VAULT_ENDPOINT:-https://kms.averox.com}"
VAULT_TOKEN="${VAULT_TOKEN:-your_vault_token_here}"
VAULT_TRANSIT_MOUNT="${VAULT_TRANSIT_MOUNT:-transit}"
TEST_TENANT_ID="${TEST_TENANT_ID:-test-tenant-$(date +%s)}"
KEK_NAME="kek-${TEST_TENANT_ID}"

echo ""
echo "📋 Configuration:"
echo "  Vault Endpoint: $VAULT_ENDPOINT"
echo "  Transit Mount: $VAULT_TRANSIT_MOUNT"
echo "  Test Tenant ID: $TEST_TENANT_ID"
echo "  KEK Name: $KEK_NAME"
echo ""

# Function to check Vault connectivity
check_vault_connection() {
  echo "🔍 Checking Vault connectivity..."
  
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ENDPOINT/v1/sys/health")
  
  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "429" ] || [ "$HTTP_CODE" = "472" ] || [ "$HTTP_CODE" = "473" ]; then
    echo "✅ Vault is accessible (HTTP $HTTP_CODE)"
    return 0
  else
    echo "❌ Vault is not accessible (HTTP $HTTP_CODE)"
    return 1
  fi
}

# Function to check if transit engine is mounted
check_transit_mount() {
  echo "🔍 Checking if transit engine is mounted..."
  
  RESPONSE=$(curl -s \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ENDPOINT/v1/sys/mounts")
  
  if echo "$RESPONSE" | grep -q "\"$VAULT_TRANSIT_MOUNT/\""; then
    echo "✅ Transit engine is mounted at /$VAULT_TRANSIT_MOUNT"
    return 0
  else
    echo "⚠️  Transit engine not found at /$VAULT_TRANSIT_MOUNT"
    return 1
  fi
}

# Function to mount transit engine
mount_transit_engine() {
  echo "🔧 Mounting transit engine..."
  
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"transit\",\"description\":\"Transit engine for CryptoShield SDK tests\"}" \
    "$VAULT_ENDPOINT/v1/sys/mounts/$VAULT_TRANSIT_MOUNT")
  
  if [ "$HTTP_CODE" = "204" ]; then
    echo "✅ Transit engine mounted successfully"
    return 0
  else
    echo "❌ Failed to mount transit engine (HTTP $HTTP_CODE)"
    return 1
  fi
}

# Function to create test KEK
create_test_kek() {
  echo "🔑 Creating test KEK: $KEK_NAME..."
  
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "type": "aes256-gcm96",
      "exportable": false,
      "allow_plaintext_backup": false,
      "auto_rotate_period": "30d"
    }' \
    "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME")
  
  if [ "$HTTP_CODE" = "204" ]; then
    echo "✅ Test KEK created successfully"
    return 0
  elif [ "$HTTP_CODE" = "400" ]; then
    echo "ℹ️  KEK already exists, using existing key"
    return 0
  else
    echo "❌ Failed to create KEK (HTTP $HTTP_CODE)"
    return 1
  fi
}

# Function to verify KEK
verify_kek() {
  echo "🔍 Verifying KEK configuration..."
  
  RESPONSE=$(curl -s \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME")
  
  if echo "$RESPONSE" | grep -q "\"type\":\"aes256-gcm96\""; then
    echo "✅ KEK verified successfully"
    echo "$RESPONSE" | jq -r '.data | "   Type: \(.type)\n   Version: \(.latest_version)\n   Created: \(.creation_time)"'
    return 0
  else
    echo "❌ KEK verification failed"
    return 1
  fi
}

# Function to run tests
run_tests() {
  echo ""
  echo "🧪 Running envelope encryption tests..."
  echo ""
  
  # Set environment variables for tests
  export VAULT_ENDPOINT
  export VAULT_TOKEN
  export VAULT_TRANSIT_MOUNT
  export KEK_NAME
  
  # Run Jest with envelope encryption test
  npm test -- test-envelope-encryption.test.ts --verbose
}

# Function to cleanup test KEK
cleanup_test_kek() {
  if [ "$CLEANUP" = "true" ]; then
    echo ""
    echo "🧹 Cleaning up test KEK..."
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE \
      -H "X-Vault-Token: $VAULT_TOKEN" \
      "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME")
    
    if [ "$HTTP_CODE" = "204" ]; then
      echo "✅ Test KEK cleaned up successfully"
    else
      echo "⚠️  Failed to cleanup KEK (HTTP $HTTP_CODE)"
    fi
  fi
}

# Main execution
main() {
  # Check Vault connection
  if ! check_vault_connection; then
    echo "❌ Cannot proceed without Vault connectivity"
    exit 1
  fi
  
  # Check/mount transit engine
  if ! check_transit_mount; then
    if ! mount_transit_engine; then
      echo "❌ Cannot proceed without transit engine"
      exit 1
    fi
  fi
  
  # Create and verify test KEK
  if ! create_test_kek; then
    echo "❌ Cannot proceed without test KEK"
    exit 1
  fi
  
  if ! verify_kek; then
    echo "❌ KEK verification failed"
    exit 1
  fi
  
  # Run tests
  run_tests
  TEST_EXIT_CODE=$?
  
  # Cleanup (optional)
  cleanup_test_kek
  
  echo ""
  if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed successfully!"
  else
    echo "❌ Some tests failed (exit code: $TEST_EXIT_CODE)"
  fi
  
  exit $TEST_EXIT_CODE
}

# Handle script arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --cleanup)
      CLEANUP=true
      shift
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --cleanup    Delete test KEK after tests complete"
      echo "  --help       Show this help message"
      echo ""
      echo "Environment Variables:"
      echo "  VAULT_ENDPOINT         Vault server URL (default: https://kms.averox.com)"
      echo "  VAULT_TOKEN            Vault authentication token"
      echo "  VAULT_TRANSIT_MOUNT    Transit engine mount path (default: transit)"
      echo "  TEST_TENANT_ID         Tenant ID for test (default: auto-generated)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Run main
main

