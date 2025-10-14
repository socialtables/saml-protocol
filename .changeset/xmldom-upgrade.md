---
"@socialtables/saml-protocol": major
---

## Upgraded Packages

| Package          | From            | To                 | Change               |
| ---------------- | --------------- | ------------------ | -------------------- |
| `@xmldom/xmldom` | 0.7.13 (^0.7.0) | 0.8.10 (^0.8.10)   | Minor upgrade        |
| `xml-crypto`     | 2.1.6 (^2.1.6)  | 6.1.2 (^6.1.2)     | **4 major versions** |
| `xml-encryption` | 2.0.0           | 3.1.0 (^3.1.0)     | 1 major version      |
| `xpath`          | 0.0.23          | 0.0.34 (^0.0.34)   | Patch upgrade        |
| `changesets`     | 2.26.0          | 2.29.27 (^2.29.27) | Patch upgrade        |
| `node-forge`     | 1.3.0           | removed.           | replaced with native crypto        |

## BREAKING CHANGES
Requires Node 20

## Code Changes Made

### 1. Added mimeType Parameter (Required in 0.8+)

Updated all `parseFromString()` calls to include `"text/xml"` mimeType:

```javascript
// Before
new DOMParser().parseFromString(xml);

// After
new DOMParser().parseFromString(xml, "text/xml");
```

**Files affected:**

- `lib/request-handling.js`
- `lib/response-handling.js`
- `lib/metadata.js`
- `lib/response-construction.js`
- `lib/util/encryption.js`
- All test files

### 2. Fixed removeChild() Strictness

Changed from incorrect direct removal to proper parent-based removal:

```javascript
// Before (failed in 0.8+)
doc.removeChild(sigNode);

// After
sigNode.parentNode.removeChild(sigNode);
```

**File:** `lib/response-handling.js`

### 3. Added Namespace Declarations

Added `xmlns:saml` to XML fragments with namespace prefixes:

```javascript
const encAssertString = `<${encTagName} xmlns:saml="${namespaces.saml}">${encryptedData}</${encTagName}>`;
```

**File:** `lib/util/encryption.js`

### 4. Updated xml-crypto API (v2 → v6)

#### Signature Creation

```javascript
// Before (v2.x)
const signer = new SignedXml(null, {
  signatureAlgorithm: algorithm,
});
signer.keyInfoProvider = new CertKeyInfo(cert);
signer.signingKey = privateKey;
signer.addReference(xpath, transforms);

// After (v6.x)
const signer = new SignedXml({
  privateKey: privateKey,
  publicCert: cert,
  signatureAlgorithm: algorithm,
  canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  getKeyInfoContent: SignedXml.getKeyInfoContent,
});
signer.addReference({
  xpath: xpath,
  transforms: transforms,
  digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
});
```

#### Signature Validation

```javascript
// Before (v2.x)
const sigCheck = new SignedXml();
sigCheck.keyInfoProvider = new CertKeyInfo(cert);

// After (v6.x)
const sigCheck = new SignedXml({
  publicCert: cert,
});
```

#### URL Signatures (REDIRECT binding)

```javascript
// Before (v2.x - used xml-crypto internals)
SignedXml.prototype.findSignatureAlgorithm(alg).getSignature(...)

// After (v6.x - use Node.js crypto directly)
const signer = crypto.createSign("RSA-SHA256");
signer.update(payload);
signer.sign(privateKey, "base64");
```

**File:** `lib/util/signing.js`

### 5. Removed Deprecated Code

- Removed `CertKeyInfo` class (replaced by constructor options)
- Removed `xmlbuilder` dependency from signing.js (no longer needed)

### 6. Updated XPath for Signature Removal

Changed to only remove top-level signatures, preserving assertion signatures:

```javascript
// Before
select("//ds:Signature", doc); // Removed ALL signatures

// After
select("/samlp:Response/ds:Signature | /saml2p:Response/ds:Signature", doc); // Only top-level
```

**File:** `lib/response-handling.js`

### 7. Fixed Validation Error Handling

xml-crypto v6 removed `validationErrors` property:

```javascript
// Before (v2.x)
return sigCheck.validationErrors; // Array of error messages

// After (v6.x)
return ["Signature validation failed"]; // Simple error for backward compat
```

**File:** `lib/util/signing.js`

## Breaking Changes Handled

### xml-crypto 2.x → 6.x

- ✅ v3.0.0: Upgraded @xmldom/xmldom from 0.7 to 0.8
- ✅ v4.0.0: Constructor now requires options object (no `null` first parameter)
- ✅ v4.0.0: Renamed `signingKey`/`signingCert` to `privateKey`/`publicCert`
- ✅ v4.0.0: Removed `KeyInfoProvider`, use `getKeyInfoContent` option instead
- ✅ v5.0.0: Removed default algorithms (must explicitly specify)
- ✅ v5.0.0: Removed `validationErrors`, validation now per-reference
- ✅ v6.0.0: Set `getCertFromKeyInfo` to noop by default

### xml-encryption 2.x → 3.x

- ✅ No API changes affecting our usage
- ✅ Added SHA256/512 OAEP digest method support (enhancement)

### @xmldom/xmldom 0.7.x → 0.8.x

- ✅ `parseFromString()` now requires mimeType parameter
- ✅ `removeChild()` enforces strict parent-child relationships
- ✅ XML fragments with namespace prefixes require xmlns declarations
- ✅ Improved XML serialization (minor output differences)
