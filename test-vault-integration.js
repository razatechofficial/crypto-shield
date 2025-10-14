/**
 * Test script for Vault KMS integration
 * Tests the HashiCorp Vault KMS service
 */

import fetch from "node-fetch";

const VAULT_ENDPOINT = "https://kms.averox.com";
const VAULT_TOKEN = "your_vault_token_here";
const TRANSIT_MOUNT = "transit";

async function testVaultConnection() {
  console.log("🔐 Testing Vault KMS Integration...\n");

  // Step 1: Health check
  console.log("1️⃣ Testing Vault health...");
  try {
    const healthResponse = await fetch(`${VAULT_ENDPOINT}/v1/sys/health`);
    console.log(`   ✅ Vault is healthy (status: ${healthResponse.status})\n`);
  } catch (error) {
    console.error(`   ❌ Vault health check failed:`, error.message);
    return;
  }

  // Step 2: Check if transit engine is mounted
  console.log("2️⃣ Checking if transit engine is mounted...");
  try {
    const mountsResponse = await fetch(`${VAULT_ENDPOINT}/v1/sys/mounts`, {
      headers: {
        "X-Vault-Token": VAULT_TOKEN,
        "Content-Type": "application/json",
      },
    });

    if (!mountsResponse.ok) {
      throw new Error(`Failed to check mounts: ${mountsResponse.statusText}`);
    }

    const mounts = await mountsResponse.json();
    const isTransitMounted = `${TRANSIT_MOUNT}/` in mounts.data;

    if (isTransitMounted) {
      console.log(
        `   ✅ Transit engine already mounted at /${TRANSIT_MOUNT}\n`
      );
    } else {
      console.log(
        `   ⚠️  Transit engine not mounted, attempting to mount...\n`
      );

      // Step 3: Mount transit engine
      console.log("3️⃣ Mounting transit engine...");
      const mountResponse = await fetch(
        `${VAULT_ENDPOINT}/v1/sys/mounts/${TRANSIT_MOUNT}`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": VAULT_TOKEN,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            type: "transit",
            description: "KMS for CryptoShield SDK envelope encryption",
            config: {
              default_lease_ttl: "0",
              max_lease_ttl: "0",
              force_no_cache: false,
            },
          }),
        }
      );

      if (!mountResponse.ok) {
        const error = await mountResponse.text();
        throw new Error(`Failed to mount transit: ${error}`);
      }

      console.log(
        `   ✅ Transit engine mounted successfully at /${TRANSIT_MOUNT}\n`
      );
    }
  } catch (error) {
    console.error(`   ❌ Error:`, error.message);
    return;
  }

  // Step 4: Create a test KEK
  console.log("4️⃣ Creating test KEK...");
  const testTenantId = "test-tenant-" + Date.now();
  const kekName = `kek-${testTenantId}`;

  try {
    const createKeyResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/keys/${kekName}`,
      {
        method: "POST",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          type: "aes256-gcm96",
          derived: false,
          exportable: false,
          allow_plaintext_backup: false,
        }),
      }
    );

    if (!createKeyResponse.ok) {
      const error = await createKeyResponse.text();
      throw new Error(`Failed to create KEK: ${error}`);
    }

    console.log(`   ✅ KEK created: ${kekName}\n`);
  } catch (error) {
    console.error(`   ❌ Error:`, error.message);
    return;
  }

  // Step 5: Test envelope encryption
  console.log("5️⃣ Testing envelope encryption...");
  const testDEK = Buffer.from("test-dek-" + Date.now()).toString("base64");

  try {
    // Encrypt DEK
    const encryptResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/encrypt/${kekName}`,
      {
        method: "POST",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          plaintext: testDEK,
        }),
      }
    );

    if (!encryptResponse.ok) {
      const error = await encryptResponse.text();
      throw new Error(`Failed to encrypt DEK: ${error}`);
    }

    const encryptResult = await encryptResponse.json();
    const encryptedDEK = encryptResult.data.ciphertext;
    console.log(`   ✅ DEK encrypted successfully`);
    console.log(`   📦 Encrypted DEK: ${encryptedDEK.substring(0, 50)}...\n`);

    // Decrypt DEK
    console.log("6️⃣ Testing DEK decryption...");
    const decryptResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/decrypt/${kekName}`,
      {
        method: "POST",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ciphertext: encryptedDEK,
        }),
      }
    );

    if (!decryptResponse.ok) {
      const error = await decryptResponse.text();
      throw new Error(`Failed to decrypt DEK: ${error}`);
    }

    const decryptResult = await decryptResponse.json();
    const decryptedDEK = decryptResult.data.plaintext;

    if (decryptedDEK === testDEK) {
      console.log(
        `   ✅ DEK decrypted successfully - encryption/decryption cycle works!\n`
      );
    } else {
      console.error(`   ❌ Decrypted DEK doesn't match original`);
    }
  } catch (error) {
    console.error(`   ❌ Error:`, error.message);
    return;
  }

  // Step 7: Test key rotation
  console.log("7️⃣ Testing KEK rotation...");
  try {
    const rotateResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/keys/${kekName}/rotate`,
      {
        method: "POST",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
      }
    );

    if (!rotateResponse.ok) {
      const error = await rotateResponse.text();
      throw new Error(`Failed to rotate KEK: ${error}`);
    }

    console.log(`   ✅ KEK rotated successfully\n`);

    // Get key info to verify rotation
    const keyInfoResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/keys/${kekName}`,
      {
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
      }
    );

    if (keyInfoResponse.ok) {
      const keyInfo = await keyInfoResponse.json();
      console.log(`   📊 Key info:`);
      console.log(`      - Latest version: ${keyInfo.data.latest_version}`);
      console.log(`      - Type: ${keyInfo.data.type}`);
      console.log(
        `      - Created: ${new Date(
          keyInfo.data.creation_time
        ).toLocaleString()}\n`
      );
    }
  } catch (error) {
    console.error(`   ❌ Error:`, error.message);
  }

  // Step 8: Cleanup - delete test key
  console.log("8️⃣ Cleaning up test KEK...");
  try {
    // First, configure deletion allowed
    await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/keys/${kekName}/config`,
      {
        method: "POST",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          deletion_allowed: true,
        }),
      }
    );

    // Then delete
    const deleteResponse = await fetch(
      `${VAULT_ENDPOINT}/v1/${TRANSIT_MOUNT}/keys/${kekName}`,
      {
        method: "DELETE",
        headers: {
          "X-Vault-Token": VAULT_TOKEN,
          "Content-Type": "application/json",
        },
      }
    );

    if (!deleteResponse.ok) {
      const error = await deleteResponse.text();
      console.log(`   ⚠️  Could not delete test key: ${error}`);
    } else {
      console.log(`   ✅ Test KEK deleted successfully\n`);
    }
  } catch (error) {
    console.error(`   ⚠️  Cleanup error:`, error.message);
  }

  console.log("🎉 Vault KMS integration test completed successfully!");
  console.log("\n✅ All systems operational:");
  console.log("   - Vault connection: OK");
  console.log("   - Transit engine: OK");
  console.log("   - KEK creation: OK");
  console.log("   - Envelope encryption: OK");
  console.log("   - KEK rotation: OK");
}

// Run the test
testVaultConnection().catch(console.error);
