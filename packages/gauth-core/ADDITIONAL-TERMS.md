# Gimel Foundation Additional Terms

**Effective:** 2026-04-10
**Applies to:** GAuth Open Core SDK (`@gauth/core`)
**Governing Entity:** Gimel Foundation gGmbH i.G.

---

## Open Core Exclusions

The GAuth Open Core SDK is licensed under the [Mozilla Public License 2.0](LICENSE).
Three capabilities are **excluded** from the open-source license and are subject to
separate, proprietary licensing by Gimel Foundation gGmbH i.G. or Gimel Technologies GmbH.

### 1. AI-Enabled Governance (Slot 5 — `ai_governance`)

Third parties may not create, distribute, or offer competing implementations of
AI-powered governance evaluation for the GAuth adapter slot system without a
separate commercial license from the Gimel Foundation.

This includes but is not limited to: AI-controlled policy evaluation engines,
AI-driven mandate issuance or revocation, AI-based compliance monitoring, and
AI systems that autonomously support, control, or make decisions within the AI
deployment lifecycle.

### 2. Web3 Identity Integration (Slot 6 — `web3_identity`)

Third parties may not create, distribute, or offer competing implementations of
Web3/blockchain-based identity resolution for the GAuth adapter slot system
without a separate commercial license.

This includes: blockchain technology, distributed ledger technology (DLT),
Web3 tokens, smart contracts, decentralized autonomous organizations (DAOs),
or any on-chain credential, authorization, or governance mechanism.

### 3. DNA-Based Identities / Post-Quantum Cryptography (Slot 7 — `dna_identity`)

Third parties may not create, distribute, or offer competing implementations of
DNA-based identity verification or post-quantum cryptographic identity for the
GAuth adapter slot system without a separate commercial license.

This includes: identity systems based on genetic data, biometric DNA profiles,
genomic identifiers, and cryptographic schemes designed to resist quantum
computing attacks (lattice-based, hash-based, code-based, multivariate primitives).

---

## License Boundary

| Component | License | Modifiable | Redistributable |
|-----------|---------|------------|-----------------|
| SDK source code | MPL 2.0 | Yes (file-level copyleft) | Yes |
| Type A/B adapter interfaces | MPL 2.0 | Yes | Yes |
| PEP engine, Management API | MPL 2.0 | Yes | Yes |
| Conformance test suite | MPL 2.0 | Yes | Yes |
| Type C adapter *interfaces* | MPL 2.0 | Yes | Yes |
| Type C adapter *implementations* | Gimel Technologies ToS (proprietary) | No | No |
| Ed25519 manifest verification code | MPL 2.0 | Yes | Yes |

**Important:** The Type C adapter *interfaces* (method signatures) are open-source.
Only the Gimel *implementations* of those interfaces are proprietary. The SDK
includes the interface definitions so that the system can correctly handle the
`null` / `pending` / `active` lifecycle for Type C slots.

---

## Legal Framework

**Gimel Foundation gGmbH i.G.** publishes the GiFo-RFCs and the open-source project.
The Gimel Foundation Legal Terms apply to all use of GAuth.

**Gimel Technologies GmbH** operates proprietary services. When a user opts into
proprietary services (including Excluded Components), a license swap occurs:
the user transitions from MPL 2.0 to the Gimel Technologies Terms of Service.

The Excluded Components are **outside the scope of the MPL 2.0**. The Gimel
Technologies Terms of Service are the sole and independent legal basis for any
use of Excluded Components.

---

## Contact

For proprietary licensing inquiries: info@gimelid.com

Copyright (c) 2026 Gimel Foundation gGmbH i.G.
www.GimelFoundation.com
Operated by Gimel Technologies GmbH
