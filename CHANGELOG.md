# Changelog

## v1 assurance baseline — 2026-09-28

### Added
- independent repair evidence-root attestation module;
- domain-separated root construction over propagation and Sentinel observation digests;
- native-replay eligibility gate;
- negative controls for malformed digests and missing native replay.

### Boundary
The module attests supplied evidence identity. It is not a Casper consensus implementation and does not prove target-protocol safety or finality.
