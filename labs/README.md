# Research labs

Structural models used by the Sovereign Lattice console. They are not hardware
backends, not gravity duals, and not an execution mode that bypasses policy.

| File | What it does |
| --- | --- |
| `syk.ts` | Two coupled chaotic systems. Entropy, volume, horizon count, connectivity. |
| `codes.ts` | QEC family table, variational vs SVD compression, 15-to-1 distillation scaling, BLS12-381 hash-to-curve steps. |
| `fabric.ts` | Request gate, Tab S9+ / workstation / cluster profiles, bounded selection trace, STRIDE controls. |
| `binding.ts` | Toy integer demo of why MuSig2 / FROST nonce binding exists. |
| `rng.ts` | Seeded Mulberry32 so the labs replay. |

The interactive console is the app that imports these modules. Run `runSyk`, `compressionCurve`, `gateRequest`, and `bindingTrial` from any TypeScript environment that can import them.
