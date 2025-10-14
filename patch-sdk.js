#!/usr/bin/env node

/**
 * CryptoShield SDK Auto-Patcher
 * Automatically fixes common SDK test failures
 */

const fs = require("fs");
const path = require("path");

console.log("🔧 CryptoShield SDK Auto-Patcher");
console.log("=================================\n");

const SDK_DIR = process.argv[2] || process.cwd();
const INDEX_FILE = path.join(SDK_DIR, "src", "index.ts");

if (!fs.existsSync(INDEX_FILE)) {
  console.error(`❌ Error: Cannot find ${INDEX_FILE}`);
  console.error("Usage: node patch-sdk.js [path-to-sdk-directory]");
  process.exit(1);
}

console.log(`📁 SDK Directory: ${SDK_DIR}`);
console.log(`📄 Patching: ${INDEX_FILE}\n`);

// Backup original file
const backupFile = INDEX_FILE + ".backup";
fs.copyFileSync(INDEX_FILE, backupFile);
console.log(`💾 Backup created: ${backupFile}`);

let content = fs.readFileSync(INDEX_FILE, "utf8");
let patchCount = 0;

// Patch 1: Add zeroize state tracking to AveroxCrypto
if (!content.includes("private _isZeroized")) {
  console.log("\n🔨 Patch 1: Adding zeroize state tracking...");

  content = content.replace(
    /(export class AveroxCrypto \{[\s\S]*?)(private _masterKey: Buffer;)/,
    "$1$2\n  private _isZeroized: boolean = false;"
  );

  patchCount++;
  console.log("✅ Zeroize state tracking added");
}

// Patch 2: Add zeroize check to encrypt method
if (
  !content.includes("if (this._isZeroized)") ||
  content.match(/if \(this\._isZeroized\)/g)?.length < 2
) {
  console.log("\n🔨 Patch 2: Adding zeroize checks to encrypt/decrypt...");

  // Add to encrypt method
  content = content.replace(
    /(encrypt\(plaintext: string \| Buffer, aad: string \| Buffer\): EncryptedEnvelope \{)/,
    `$1\n    if (this._isZeroized) {\n      throw new AveroxCryptoError('ZEROIZED', 'Cannot encrypt: instance has been zeroized');\n    }`
  );

  // Add to decrypt method
  content = content.replace(
    /(decrypt\(envelope: EncryptedEnvelope, aad: string \| Buffer\): string \{)/,
    `$1\n    if (this._isZeroized) {\n      throw new AveroxCryptoError('ZEROIZED', 'Cannot decrypt: instance has been zeroized');\n    }`
  );

  patchCount++;
  console.log("✅ Zeroize checks added to methods");
}

// Patch 3: Fix zeroize method
if (!content.includes("this._isZeroized = true")) {
  console.log("\n🔨 Patch 3: Fixing zeroize method implementation...");

  content = content.replace(
    /(zeroize\(\): void \{[\s\S]*?)(this\._masterKey\.fill\(0\);)([\s\S]*?\})/,
    `$1if (!this._isZeroized) {\n      $2\n      this._isZeroized = true;\n    }$3`
  );

  patchCount++;
  console.log("✅ Zeroize method fixed");
}

// Patch 4: Fix InvalidTagError detection in decrypt
if (!content.includes("Unsupported state or unable to authenticate data")) {
  console.log("\n🔨 Patch 4: Fixing InvalidTagError detection...");

  // Find all decrypt error handlers
  const decryptErrorPattern =
    /(} catch \(error\) \{[\s\S]*?)(if \(error instanceof AveroxCryptoError\) throw error;[\s\S]*?throw new AveroxCryptoError\('DECRYPTION_FAILED')/g;

  content = content.replace(
    decryptErrorPattern,
    `} catch (error) {
      // Detect authentication tag failures
      if (error instanceof Error && (
        error.message.includes('Unsupported state or unable to authenticate data') ||
        error.message.includes('authentication') ||
        error.message.includes('auth tag')
      )) {
        throw new InvalidTagError('Authentication tag verification failed');
      }
      $2`
  );

  patchCount++;
  console.log("✅ InvalidTagError detection added");
}

// Patch 5: Add same fixes to ChaCha20Poly1305
if (content.includes("export class ChaCha20Poly1305")) {
  console.log("\n🔨 Patch 5: Applying same fixes to ChaCha20Poly1305...");

  // Add zeroize state
  if (
    !content.match(
      /export class ChaCha20Poly1305 \{[\s\S]{0,200}private _isZeroized/
    )
  ) {
    content = content.replace(
      /(export class ChaCha20Poly1305 \{[\s\S]*?)(private _key: Buffer;)/,
      "$1$2\n  private _isZeroized: boolean = false;"
    );
  }

  // Add zeroize checks (find ChaCha20 encrypt method)
  const chachaEncryptPattern =
    /(class ChaCha20Poly1305[\s\S]*?encrypt\([^)]*\)[^{]*\{)/;
  if (
    !content.match(
      /class ChaCha20Poly1305[\s\S]{0,500}if \(this\._isZeroized\)/
    )
  ) {
    content = content.replace(
      chachaEncryptPattern,
      `$1\n    if (this._isZeroized) {\n      throw new AveroxCryptoError('ZEROIZED', 'Cannot encrypt: instance has been zeroized');\n    }`
    );
  }

  patchCount++;
  console.log("✅ ChaCha20Poly1305 patched");
}

// Write patched content
fs.writeFileSync(INDEX_FILE, content, "utf8");

console.log(`\n✅ Patching complete! Applied ${patchCount} patches.`);
console.log("\n📋 Summary:");
console.log("  ✓ Zeroize state tracking");
console.log("  ✓ Zeroize checks in encrypt/decrypt");
console.log("  ✓ Proper zeroize implementation");
console.log("  ✓ InvalidTagError detection");
console.log("  ✓ ChaCha20Poly1305 fixes");

console.log("\n🧪 Next steps:");
console.log("  1. Review changes: git diff src/index.ts");
console.log("  2. Run tests: npm test");
console.log("  3. If tests pass, remove backup: rm src/index.ts.backup");
console.log("  4. If tests fail, restore: cp src/index.ts.backup src/index.ts");

console.log("\n💡 To test envelope encryption:");
console.log("  Windows: .\\run-vault-tests.ps1");
console.log("  Linux/Mac: ./run-vault-tests.sh\n");
