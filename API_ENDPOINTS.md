I'll provide you with all the backend routes for testing in Postman, including the JSON data to pass for each endpoint.

[1 tool called]

Let me get the specific Vault API endpoints:

[1 tool called]

Now let me get the KEK rotation endpoints:

[1 tool called]

Let me also check for the specific KEK rotation endpoint:

[1 tool called]

Let me search for the specific KEK rotation endpoint:

[1 tool called]

Perfect! Now I have all the Vault API endpoints. Let me provide you with a comprehensive Postman collection for testing all the Vault API endpoints.

## 🔧 **Postman Collection for Vault API Testing**

### **Base URL**: `http://localhost:3000`

---

## **1. Public Test Endpoints (No Authentication Required)**

### **Test Public API**

```
GET /api/vault/test-public
```

**Headers**: None required
**Response**:

```json
{
  "message": "Vault API is working (public)",
  "timestamp": "2025-10-15T10:30:00.000Z",
  "server": "running",
  "route": "test-public",
  "url": "/api/vault/test-public"
}
```

### **Test Vault Configuration**

```
GET /api/vault/config-test
```

**Headers**: None required
**Response**:

```json
{
  "message": "Vault configuration test",
  "timestamp": "2025-10-15T10:30:00.000Z",
  "healthCheck": true,
  "config": {
    "endpoint": "https://kms. .com",
    "token": "present",
    "transitMount": "transit"
  }
}
```

---

## **2. Cryptographic Operations (No Authentication Required)**

### **Encrypt Data**

```
POST /api/vault/test/encrypt
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "plaintext": "Hello World Test",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "ciphertext": "vault:v4:encrypted_data_here"
}
```

### **Decrypt Data**

```
POST /api/vault/test/decrypt
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "ciphertext": "vault:v4:2O/sKiaQs/Hujv0JPwH+zx7haNrnNW8PVSnY6KceuOwR8gD9926T9LWtyrw=",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "plaintext": "SGVsbG8gV29ybGQgVGVzdA=="
}
```

### **Generate Data Key**

```
POST /api/vault/test/datakey
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "plaintext": "base64-encoded-plaintext-key",
  "ciphertext": "vault:v4:encrypted-data-key"
}
```

### **Rewrap Ciphertext**

```
POST /api/vault/test/rewrap
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "ciphertext": "vault:v4:old-encrypted-data",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "newCiphertext": "vault:v4:new-encrypted-data"
}
```

### **Generate HMAC**

```
POST /api/vault/test/hmac
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "data": "Hello World Test",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "hmac": "vault:v4:odqJV6fQtlyQxzDeRzIAUKR1+QWLZt9dKCNvO48dvLU="
}
```

### **Verify HMAC**

```
POST /api/vault/test/verify
```

**Headers**:

```
Content-Type: application/json
```

**Body**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "data": "Hello World Test",
  "hmac": "vault:v4:odqJV6fQtlyQxzDeRzIAUKR1+QWLZt9dKCNvO48dvLU=",
  "context": "test-context"
}
```

**Response**:

```json
{
  "success": true,
  "valid": true
}
```

---

## **3. Authenticated Endpoints (Require Session Cookie)**

**Note**: For authenticated endpoints, you need to be logged in through the web interface first to get the session cookie.

### **Test Authenticated API**

```
GET /api/vault/test
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
{
  "message": "Vault API is working",
  "timestamp": "2025-10-15T10:30:00.000Z",
  "user": "authenticated"
}
```

### **Create New KEK**

```
POST /api/vault/keys
```

**Headers**:

```
Content-Type: application/json
Cookie: connect.sid=your-session-cookie-here
```

**Body**:

```json
{
  "algorithm": "aes256-gcm96",
  "keyType": "primary"
}
```

**Response**:

```json
{
  "success": true,
  "message": "KEK created successfully in HashiCorp Vault",
  "kekMetadata": {
    "tenantId": "d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
    "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
    "algorithm": "aes256-gcm96",
    "keyVersion": 1,
    "createdAt": "2025-10-15T10:30:00.000Z"
  },
  "tenantId": "d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "createdAt": "2025-10-15T10:30:00.000Z"
}
```

### **Get Primary KEK Info**

```
GET /api/vault/keys
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "algorithm": "aes256-gcm96",
  "keyVersion": 5,
  "minAvailableVersion": 0,
  "minDecryptionVersion": 1,
  "supportsEncryption": true,
  "supportsDecryption": true,
  "supportsSigning": false,
  "supportsDerivation": true,
  "createdAt": 1760510647,
  "tenantId": "d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff"
}
```

### **Get All KEKs for Tenant**

```
GET /api/vault/keys/all
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
[
  {
    "id": "kek-67016887-7471-4ac4-abae-021d05f09e2a",
    "kekName": "kek-67016887-7471-4ac4-abae-021d05f09e2a",
    "algorithm": "aes256-gcm96",
    "keyVersion": 2,
    "capabilities": ["encrypt", "decrypt", "derive"],
    "status": "active",
    "createdAt": "2025-10-15T10:30:00.000Z"
  },
  {
    "id": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
    "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
    "algorithm": "aes256-gcm96",
    "keyVersion": 5,
    "capabilities": ["encrypt", "decrypt", "derive"],
    "status": "active",
    "createdAt": "2025-10-15T10:30:00.000Z"
  }
]
```

### **Debug All Keys in Vault**

```
GET /api/vault/keys/debug
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
{
  "totalKeys": 3,
  "keys": [
    "kek-67016887-7471-4ac4-abae-021d05f09e2a",
    "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
    "test"
  ],
  "message": "All keys in Vault transit engine"
}
```

### **Rotate Specific KEK**

```
POST /api/vault/keys/kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff/rotate
```

**Headers**:

```
Content-Type: application/json
Cookie: connect.sid=your-session-cookie-here
```

**Body**: (Empty body)

```json
{}
```

**Response**:

```json
{
  "success": true,
  "message": "KEK rotated successfully in HashiCorp Vault",
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "newVersion": 6,
  "rotatedAt": "2025-10-15T10:30:00.000Z"
}
```

### **Get Specific KEK Details**

```
GET /api/vault/keys/kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
{
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "algorithm": "aes256-gcm96",
  "keyVersion": 5,
  "minAvailableVersion": 0,
  "minDecryptionVersion": 1,
  "supportsEncryption": true,
  "supportsDecryption": true,
  "supportsSigning": false,
  "supportsDerivation": true,
  "createdAt": 1760510647,
  "tenantId": "d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff"
}
```

### **Delete KEK**

```
DELETE /api/vault/keys/kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff
```

**Headers**:

```
Cookie: connect.sid=your-session-cookie-here
```

**Response**:

```json
{
  "success": true,
  "message": "KEK deleted successfully from HashiCorp Vault",
  "kekName": "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
  "deletedAt": "2025-10-15T10:30:00.000Z"
}
```

---

## **4. How to Get Session Cookie**

1. **Open your browser** and go to `http://localhost:3000`
2. **Log in** to your account
3. **Open Developer Tools** (F12)
4. **Go to Application/Storage tab**
5. **Find Cookies** → `http://localhost:3000`
6. **Copy the value** of `connect.sid`
7. **Use it in Postman** as `Cookie: connect.sid=your-copied-value`

---

## **5. Testing Workflow**

1. **Start with public endpoints** to verify server is running
2. **Test cryptographic operations** with existing KEKs
3. **Create new KEKs** using authenticated endpoints
4. **Test key rotation** and management operations
5. **Verify all operations** work as expected

This collection covers all the Vault API functionality for testing in Postman! 🚀
