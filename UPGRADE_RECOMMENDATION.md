# @xmldom/xmldom Upgrade Investigation Results

## Test Results Summary

### Main Branch (0.7.13)
- **All 82 tests passing** ✅

### Upgrade to 0.8.11
- **79/82 tests passing** (96%)
- **3/82 tests failing** (4%)

## Failing Tests

All 3 failures are related to encrypted + signed SAML assertions:

1. `consumes a valid encrypted POST response with a signed assertion`
2. `consumes a valid double-signed, encrypted, POST response`  
3. `consumes a valid REDIRECT response with a query signature, an Assertion signature, and an encrypted Assertion`

## Root Cause

The issue occurs due to version mismatch between our code and transitive dependencies:

- **Our code**: Uses `@xmldom/xmldom@0.8.11`
- **xml-crypto@2.1.6**: Uses `@xmldom/xmldom@0.7.13`
- **xml-encryption@2.0.0**: Uses `@xmldom/xmldom@0.7.13`

When processing encrypted assertions with signatures:
1. The assertion is encrypted with a valid signature
2. We decrypt using `@xmldom/xmldom@0.8.11`
3. We serialize/deserialize the document (line 71-73 in `lib/util/encryption.js`)
4. The XMLSerializer in 0.8.11 outputs slightly different XML than 0.7.13
5. When xml-crypto (using 0.7.13) validates the signature, it fails because the XML has changed

## Attempted Fixes

### ✅ Fixed: Added mimeType parameter
- All `parseFromString()` calls now include `"text/xml"` parameter (required in 0.8+)

### ✅ Fixed: Corrected XPath for signature removal
- Changed from `"//ds:Signature"` (all signatures) to `/samlp:Response/ds:Signature | /saml2p:Response/ds:Signature` (only top-level)
- This prevents accidentally removing valid assertion signatures

### ❌ Did not fix: Removed serialize/deserialize
- Made things worse (5 failures instead of 3)
- The serialize/deserialize is necessary for namespace handling

## Recommendations

### Option 1: Stay on 0.7.x (Recommended for now)
Revert to `@xmldom/xmldom@^0.7.13` until dependencies can be upgraded.

**Pros:**
- All tests pass
- No risk
- Simpler

**Cons:**
- Missing 2+ years of bug fixes and security improvements
- Using older, less maintained version

### Option 2: Upgrade all dependencies together
Upgrade to compatible versions that all use similar xmldom versions:
- `xml-crypto`: 2.1.6 → 6.1.2 (uses `@xmldom/xmldom@^0.8.10`)
- `xml-encryption`: 2.0.0 → 3.1.0 (uses `@xmldom/xmldom@^0.8.5`)
- `@xmldom/xmldom`: 0.7.0 → 0.8.11

**Pros:**
- All packages use compatible versions
- Gets bug fixes and improvements across all libraries
- Likely resolves the failing tests

**Cons:**
- xml-crypto 2.x → 6.x is a major version jump (potential breaking changes)
- xml-encryption 2.x → 3.x is a major version jump (potential breaking changes)
- Requires more testing and potential code changes

### Option 3: Wait for xml-crypto/xml-encryption updates
Wait for these libraries to support `@xmldom/xmldom@0.9.x` 

**Pros:**
- Future-proof
- Gets latest xmldom features

**Cons:**
- May take a long time or never happen
- Not in our control

## Decision

**For this PR: Recommend Option 1 (stay on 0.7.x)**

The 3 failing tests represent a critical feature (encrypted signed assertions), and the root cause is well understood. Rather than ship with failing tests, it's better to:

1. Keep using `@xmldom/xmldom@^0.7.13` for now
2. Create a follow-up issue/PR to upgrade xml-crypto and xml-encryption
3. Then upgrade xmldom to 0.8.x or 0.9.x as part of that effort

This gives us a stable, fully-tested codebase while we plan a more comprehensive upgrade.
