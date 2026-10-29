// pointer-chain.ts — resolve a multi-level pointer chain.
//
// Classic game-hacking scenario: a static module address leads through a
// chain of pointers to a dynamic value, e.g.
//   "game.exe"+0x1F2A3C -> +0x10 -> +0x28 -> +0x8 -> health (int32)
//
// Run: bun examples/pointer-chain.ts <pid> <baseHex> <off1> [off2 ... offN]
import { Process } from '../src/index.js';

const [pidArg, baseArg, ...offArgs] = process.argv.slice(2);
if (!pidArg || !baseArg || offArgs.length === 0) {
  console.error(
    'usage: bun examples/pointer-chain.ts <pid> <baseHex> <off1> [off2 ...]',
  );
  process.exit(1);
}

const pid = Number(pidArg);
const base = BigInt(baseArg);
const offsets = offArgs.map((o) => Number(BigInt(o))); // accepts 0x… or decimal

using proc = Process.open(pid);

// resolvePointer reads the pointer at `base`, then dereferences through each
// offset except the last, which is added to the final pointer.
const final = proc.resolvePointer(base, offsets);
console.log(
  `chain resolved: 0x${base.toString(16)} -> ${offsets.map((o) => `+0x${o.toString(16)}`).join(' -> ')} -> 0x${final.toString(16)}`,
);

// read the value at the resolved address
console.log(
  `value at final: ${proc.readInt32(final)} (0x${(proc.readInt32(final) >>> 0).toString(16)})`,
);

// Tip: combine with scan() to locate the static base first:
//   const hit = await proc.scanUnique('48 8B 05 ?? ?? ?? ??', { module: 'game.exe' })
//   const gva = proc.resolveRIPRelative(hit)        // global var address
//   const addr = proc.resolvePointer(gva, [0x10, 0x28, 0x8])
