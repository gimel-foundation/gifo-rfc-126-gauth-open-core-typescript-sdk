# Gimel Foundation — Additional Terms

**Effective Date:** 2025-01-01
**Applies to:** GAuth Open Core SDK (`@gauth/core`) and all associated packages

## 1. Scope

These Additional Terms supplement the Mozilla Public License 2.0 ("MPL-2.0") under which this software is licensed. In the event of any conflict, the MPL-2.0 prevails except where these terms impose additional restrictions permitted by Section 3.5 of the MPL-2.0.

## 2. Trademark and Branding Exclusions

The following names, logos, and marks are **not** covered by the MPL-2.0 grant:

- **Gimel Foundation** and the Gimel Foundation logo
- **GAuth** and the GAuth protocol mark
- **GiFo-RFC** document identifiers
- The "Gimel ID" identifier and associated branding

You may use these marks solely to identify the origin of the software ("built with GAuth") but may not use them in a way that implies endorsement or affiliation with the Gimel Foundation without prior written consent.

## 3. RFC Reference Integrity

Implementations claiming compliance with GiFo-RFCs (0110, 0111, 0115, 0116, 0117, 0118) must:

1. Implement all MUST-level requirements of the cited RFC version.
2. Not claim compliance with an RFC version that the implementation does not fully satisfy.
3. Clearly state the specific RFC version(s) implemented (e.g., "GiFo-RFC 0116 v2.2").

## 4. Governance Profile Naming

The governance profile names `strict`, `standard`, and `permissive` have defined semantics in the GAuth protocol. Implementations that use these profile names must preserve their intended semantics as defined in GiFo-RFC 0110.

## 5. Connector Slot Model

The seven-slot connector model (PolicyDecision, OAuthEngine, Foundry, Wallet, Governance, Web3Identity, Billing) and their associated tariff codes (O, M, L, and hybrid variants) are part of the GAuth protocol specification. Implementations may extend the slot model but must not redefine the semantics of existing slots or tariff codes.

## 6. No Warranty for Compliance

This SDK provides tooling for implementing governance policies. It does not guarantee regulatory, legal, or contractual compliance. Users are responsible for ensuring their use of GAuth meets applicable requirements.

## 7. Contact

For trademark licensing, RFC compliance questions, or partnership inquiries:

- **Email:** legal@gimelfoundation.com
- **Web:** https://gimelfoundation.com
