# rootz-shirudo-verify

Check a [Shirudo](https://github.com/shirudo-dev/shirudo) node's TPM register yourself. Plan a kernel-shield change
**from a known state to a known state** before it runs.

Shirudo lets AI agents write small eBPF "upatches" that block an exploit on a running Linux host. Each load, unload and
tree operation is extended into a per-boot TPM NV register, and `shirudo attest` gives you TPM-quoted evidence. This
tool recomputes everything in that evidence from Shirudo's published formats. It never trusts a printout from the tool
it is checking, and it adds one thing:

**The register a sync will produce can be computed before the sync runs.** The register is
`SHA256(register ‖ event)` over the load or unload event, then the `tree_op` event, for every operation applied. So from
a quoted start value and the tree, you know the exact end value in advance. A change can then be treated as a planned
trip between two known values, not as "upgrade, then look at the new quote":

- approve the *transition* before it happens;
- seal a key to the predicted end state (`PolicyNV eq` on Shirudo's NV index), so the machine can open it only by
  arriving there;
- afterwards, check that the machine travelled exactly the planned path, with nothing extra on it.

Zero dependencies. Node 22.18 or later runs the TypeScript directly.

## Quickstart (real data from a Shirudo test target is included)

```sh
git clone https://github.com/rootz-global/rootz-shirudo-verify && cd rootz-shirudo-verify
npm test                                                    # 14 tests, pinned against real Shirudo output

# 1. Replay a node's eventlog to the register its TPM quoted
node src/cli.ts replay examples/after-seq1.evidence.json

# 2. BEFORE the next sync: predict the register it will produce
node src/cli.ts plan examples/after-seq1.evidence.json examples/publication.json --to-seq 2 > plan.json

# 3. AFTER the sync: did the node arrive exactly as planned?
node src/cli.ts arrival plan.json examples/after-seq2.evidence.json        # arrived: true
node src/cli.ts arrival plan.json examples/after-seq1.evidence.json        # arrived: false (exit 1)
```

A full run on a real target, with every verdict re-checkable from its files, is in [`runs/2026-11-25-known-state`](runs/2026-11-25-known-state).

The examples are one boot of a Shirudo test target (swtpm, arm64, `shirudo@0132734`). They hold `attest` evidence after
tree operation 1 and after operation 2, plus the tree publication. The plan predicts `912531b9…`, the value the TPM
certified after operation 2.

On your own node: `shirudo attest --nonce=<n> --output=start.json`, then `shirudo attest verify` on it, then `plan`
against the tree's current publication document, then `bpm tree sync`, then attest and verify again, then `arrival`.

## What it checks, and what it does not

| Command | Checks |
|---|---|
| `replay` | Every eventlog record's digest derives from its own fields, and the fold from the boot's `init` equals the quoted register. |
| `head` | Every operation digest recomputes; the history root over the tree equals Shirudo's `history_root`. |
| `plan` | The start evidence replays. It then predicts each applied operation's events (an add loads its payload; a delete unloads the payload that was **loaded**, not the delete artifact's own) and the end register. |
| `arrival` | The same boot; the start value lies on the replayed path; exactly the predicted events come after it; the quoted end value is the predicted one. |

- **It does not verify the TPM quote's signature.** Run `shirudo attest verify` on the same evidence first. A log that
  agrees with itself proves nothing on its own.
- **It does not predict an operation the node's selector does not match.** We have not observed that outcome on a real
  target, so `plan` refuses rather than guess.
- **Root on the node can still run `bpm tree sync` itself.** Nothing here prevents that. What changes is the consequence:
  the end value moves, `arrival` fails, and a key sealed to the planned end state does not open.

## Signed instructions for every tree operation

This repository is the open verification half. **[Rootz Receipts](https://receipts.rootz.global/use-cases/kernel-shields.html)**
adds the other half:

- a signed instruction for each tree operation, bound to the tree's start and end history roots, with the gate
  refusing a stale one;
- the evidence behind it (advisory, build, canary observation) and the authority of whoever signed it;
- a node-side receiver that holds a sync until every operation has an instruction;
- keys released to the machine only for an approved transition.

It needs no change to Shirudo. Contact: steven@rootz.global.

BSD-2-Clause, like Shirudo. Built by Rootz Corp with Claude (Anthropic). Shirudo is an independent project of its
maintainers; this repository is not affiliated with or endorsed by them, Cisco or OpenAI.
