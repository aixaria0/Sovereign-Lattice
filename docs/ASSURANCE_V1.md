# Repair Evidence-Root Attestation

The v1 assurance module accepts a propagation-envelope digest, Sentinel observation digest, repair problem identity, and native replay eligibility.

If every prerequisite is valid, it creates a domain-separated SHA-256 evidence root under `causal-assurance-repair-attestation/v1`.

If native replay is absent, a digest is malformed, or problem identity is empty, the module fails closed with `UNATTESTED`.

This attestation binds evidence identity only. Sovereign-Lattice PBFT is not treated as equivalent to Casper CBC, and this root is not a protocol-finality certificate.
