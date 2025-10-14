# CryptoShield SDK - Vault KMS Envelope Encryption Test Runner (PowerShell)
# This script sets up the environment and runs comprehensive tests

param(
    [switch]$Cleanup = $false,
    [switch]$Help = $false
)

if ($Help) {
    Write-Host @"
CryptoShield Vault KMS Test Runner

Usage: .\run-vault-tests.ps1 [OPTIONS]

Options:
  -Cleanup    Delete test KEK after tests complete
  -Help       Show this help message

Environment Variables:
  VAULT_ENDPOINT         Vault server URL (default: https://kms.averox.com)
  VAULT_TOKEN            Vault authentication token
  VAULT_TRANSIT_MOUNT    Transit engine mount path (default: transit)
  TEST_TENANT_ID         Tenant ID for test (default: auto-generated)
"@
    exit 0
}

$ErrorActionPreference = "Stop"

Write-Host "🔐 CryptoShield Vault KMS Test Runner" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$VAULT_ENDPOINT = if ($env:VAULT_ENDPOINT) { $env:VAULT_ENDPOINT } else { "https://kms.averox.com" }
$VAULT_TOKEN = if ($env:VAULT_TOKEN) { $env:VAULT_TOKEN } else { "your_vault_token_here" }
$VAULT_TRANSIT_MOUNT = if ($env:VAULT_TRANSIT_MOUNT) { $env:VAULT_TRANSIT_MOUNT } else { "transit" }
$TEST_TENANT_ID = if ($env:TEST_TENANT_ID) { $env:TEST_TENANT_ID } else { "test-tenant-$(Get-Date -Format 'yyyyMMddHHmmss')" }
$KEK_NAME = "kek-$TEST_TENANT_ID"

Write-Host "📋 Configuration:" -ForegroundColor Yellow
Write-Host "  Vault Endpoint: $VAULT_ENDPOINT"
Write-Host "  Transit Mount: $VAULT_TRANSIT_MOUNT"
Write-Host "  Test Tenant ID: $TEST_TENANT_ID"
Write-Host "  KEK Name: $KEK_NAME"
Write-Host ""

function Test-VaultConnection {
    Write-Host "🔍 Checking Vault connectivity..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri "$VAULT_ENDPOINT/v1/sys/health" `
            -Headers @{"X-Vault-Token" = $VAULT_TOKEN} `
            -Method GET `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        
        $statusCode = $response.StatusCode
        if ($statusCode -eq 200 -or $statusCode -eq 429 -or $statusCode -eq 472 -or $statusCode -eq 473) {
            Write-Host "✅ Vault is accessible (HTTP $statusCode)" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "❌ Vault is not accessible: $_" -ForegroundColor Red
        return $false
    }
    
    return $false
}

function Test-TransitMount {
    Write-Host "🔍 Checking if transit engine is mounted..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-RestMethod -Uri "$VAULT_ENDPOINT/v1/sys/mounts" `
            -Headers @{"X-Vault-Token" = $VAULT_TOKEN} `
            -Method GET
        
        if ($response."$VAULT_TRANSIT_MOUNT/") {
            Write-Host "✅ Transit engine is mounted at /$VAULT_TRANSIT_MOUNT" -ForegroundColor Green
            return $true
        } else {
            Write-Host "⚠️  Transit engine not found at /$VAULT_TRANSIT_MOUNT" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "❌ Failed to check transit mount: $_" -ForegroundColor Red
        return $false
    }
}

function Mount-TransitEngine {
    Write-Host "🔧 Mounting transit engine..." -ForegroundColor Yellow
    
    try {
        $body = @{
            type = "transit"
            description = "Transit engine for CryptoShield SDK tests"
        } | ConvertTo-Json
        
        $response = Invoke-WebRequest -Uri "$VAULT_ENDPOINT/v1/sys/mounts/$VAULT_TRANSIT_MOUNT" `
            -Headers @{
                "X-Vault-Token" = $VAULT_TOKEN
                "Content-Type" = "application/json"
            } `
            -Method POST `
            -Body $body `
            -UseBasicParsing
        
        if ($response.StatusCode -eq 204) {
            Write-Host "✅ Transit engine mounted successfully" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "❌ Failed to mount transit engine: $_" -ForegroundColor Red
        return $false
    }
    
    return $false
}

function New-TestKEK {
    Write-Host "🔑 Creating test KEK: $KEK_NAME..." -ForegroundColor Yellow
    
    try {
        $body = @{
            type = "aes256-gcm96"
            exportable = $false
            allow_plaintext_backup = $false
            auto_rotate_period = "30d"
        } | ConvertTo-Json
        
        $response = Invoke-WebRequest -Uri "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME" `
            -Headers @{
                "X-Vault-Token" = $VAULT_TOKEN
                "Content-Type" = "application/json"
            } `
            -Method POST `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 204) {
            Write-Host "✅ Test KEK created successfully" -ForegroundColor Green
            return $true
        }
    } catch {
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-Host "ℹ️  KEK already exists, using existing key" -ForegroundColor Cyan
            return $true
        } else {
            Write-Host "❌ Failed to create KEK: $_" -ForegroundColor Red
            return $false
        }
    }
    
    return $false
}

function Test-KEK {
    Write-Host "🔍 Verifying KEK configuration..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-RestMethod -Uri "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME" `
            -Headers @{"X-Vault-Token" = $VAULT_TOKEN} `
            -Method GET
        
        if ($response.data.type -eq "aes256-gcm96") {
            Write-Host "✅ KEK verified successfully" -ForegroundColor Green
            Write-Host "   Type: $($response.data.type)"
            Write-Host "   Version: $($response.data.latest_version)"
            Write-Host "   Created: $($response.data.creation_time)"
            return $true
        }
    } catch {
        Write-Host "❌ KEK verification failed: $_" -ForegroundColor Red
        return $false
    }
    
    return $false
}

function Invoke-Tests {
    Write-Host ""
    Write-Host "🧪 Running envelope encryption tests..." -ForegroundColor Cyan
    Write-Host ""
    
    # Set environment variables for tests
    $env:VAULT_ENDPOINT = $VAULT_ENDPOINT
    $env:VAULT_TOKEN = $VAULT_TOKEN
    $env:VAULT_TRANSIT_MOUNT = $VAULT_TRANSIT_MOUNT
    $env:KEK_NAME = $KEK_NAME
    
    # Run npm test
    try {
        npm test -- test-envelope-encryption.test.ts --verbose
        return $LASTEXITCODE -eq 0
    } catch {
        Write-Host "❌ Tests failed: $_" -ForegroundColor Red
        return $false
    }
}

function Remove-TestKEK {
    if ($Cleanup) {
        Write-Host ""
        Write-Host "🧹 Cleaning up test KEK..." -ForegroundColor Yellow
        
        try {
            $response = Invoke-WebRequest -Uri "$VAULT_ENDPOINT/v1/$VAULT_TRANSIT_MOUNT/keys/$KEK_NAME" `
                -Headers @{"X-Vault-Token" = $VAULT_TOKEN} `
                -Method DELETE `
                -UseBasicParsing
            
            if ($response.StatusCode -eq 204) {
                Write-Host "✅ Test KEK cleaned up successfully" -ForegroundColor Green
            }
        } catch {
            Write-Host "⚠️  Failed to cleanup KEK: $_" -ForegroundColor Yellow
        }
    }
}

# Main execution
try {
    # Check Vault connection
    if (-not (Test-VaultConnection)) {
        Write-Host "❌ Cannot proceed without Vault connectivity" -ForegroundColor Red
        exit 1
    }
    
    # Check/mount transit engine
    if (-not (Test-TransitMount)) {
        if (-not (Mount-TransitEngine)) {
            Write-Host "❌ Cannot proceed without transit engine" -ForegroundColor Red
            exit 1
        }
    }
    
    # Create and verify test KEK
    if (-not (New-TestKEK)) {
        Write-Host "❌ Cannot proceed without test KEK" -ForegroundColor Red
        exit 1
    }
    
    if (-not (Test-KEK)) {
        Write-Host "❌ KEK verification failed" -ForegroundColor Red
        exit 1
    }
    
    # Run tests
    $testsPassed = Invoke-Tests
    
    # Cleanup
    Remove-TestKEK
    
    Write-Host ""
    if ($testsPassed) {
        Write-Host "✅ All tests passed successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "❌ Some tests failed" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Unexpected error: $_" -ForegroundColor Red
    exit 1
}

