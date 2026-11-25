# Run 2026-11-25: known state → known state on a real Shirudo target

Shirudo test target (swtpm, TCG on Lima arm64, `shirudo@0132734`), one boot. `log.txt` is the full run output.

| Step | Result | Check it |
|---|---|---|
| Start | Quoted register `d80b11ac…`, tree at seq 8 | `node src/cli.ts replay runs/2026-11-25-known-state/KS-start-evidence.json` |
| Instruction bound to a stale tree root | Refused (`shirudo-transition-stale`), nothing appended | `log.txt` |
| Plan 1 (instructed add, seq 9) | `d80b11ac…` → `b8c1d8cc…`, predicted before the sync | `KS-plan-1.json` |
| Key released before the upgrade, sealed to `b8c1d8cc…` | The TPM refused to unseal before the sync (0x126) | `log.txt`, `KS-release-note.json` |
| After the sync | The TPM unsealed and the key opened (sha256 matches). Arrival on plan | `node src/cli.ts arrival runs/2026-11-25-known-state/KS-plan-1.json runs/2026-11-25-known-state/KS-arrived-evidence.json` |
| Plan 2 (instructed delete, seq 10), then a rogue add slipped in at seq 11 and the sync forced | The TPM refused key 2. Arrival off plan: 4 events where 2 were predicted | `node src/cli.ts arrival runs/2026-11-25-known-state/KS-plan-2.json runs/2026-11-25-known-state/KS-offpath-evidence.json` (exit 1) |

`KS-ledger.json` is the node's wallet: hash-chained, EIP-191-signed notes (instructions, the owner's
`transition.approve`, ECDH-wrapped `key.release`, `transition.arrived`). All keys are lab test keys.
