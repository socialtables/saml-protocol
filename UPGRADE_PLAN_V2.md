# Coordinated Upgrade Plan: xmldom + dependencies

## Current State
- `@xmldom/xmldom`: ^0.9.8 (just upgraded)
- `xml-crypto`: ^2.1.6 (uses @xmldom/xmldom@0.7.13)
- `xml-encryption`: 2.0.0 (uses @xmldom/xmldom@0.7.13)
- `xpath`: 0.0.23

## Problem
xml-crypto@6.1.2 (latest) only supports @xmldom/xmldom@^0.8.10, not 0.9.x

## Options

### Option A: Stay on 0.9.8, wait for xml-crypto support
**Status:** Not viable - xml-crypto doesn't support 0.9.x yet

### Option B: Downgrade to 0.8.x and upgrade dependencies ✅ RECOMMENDED
**Target versions:**
- `@xmldom/xmldom`: ^0.9.8 → ^0.8.10 (downgrade)
- `xml-crypto`: ^2.1.6 → ^6.1.2 (major upgrade)
- `xml-encryption`: 2.0.0 → ^3.1.0 (major upgrade)
- `xpath`: 0.0.23 → ^0.0.34 (minor upgrade)

**Why this works:**
- All packages will use compatible xmldom versions (0.8.x)
- Gets us 90% of the benefits (0.7 → 0.8 is the big jump)
- 0.9.x is only a few months newer than 0.8.10 anyway
- xml-crypto 2.x → 6.x gets us 2+ years of improvements
- xml-encryption 2.x → 3.x gets us latest features

**Breaking changes to review:**
1. xml-crypto 2.x → 6.x: Check CHANGELOG
2. xml-encryption 2.x → 3.x: Check CHANGELOG
3. xpath 0.0.23 → 0.0.34: Likely just bug fixes

### Option C: Fork and patch xml-crypto
**Status:** Not recommended - too much maintenance burden

## Recommended Action: Option B

1. Update package.json:
   ```json
   "@xmldom/xmldom": "^0.8.10",
   "xml-crypto": "^6.1.2",
   "xml-encryption": "^3.1.0",
   "xpath": "^0.0.34"
   ```

2. Run `npm install`

3. Run tests - expect all 82 to pass (version alignment should fix the 3 failures)

4. Check for any API changes in xml-crypto and xml-encryption
