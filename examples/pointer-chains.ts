// pointer-chains.ts — the cheat-dev helper layer:
//   proc.addr()      — one fluent CE-style pointer-chain address
//   proc.pointers()  — a named table of chains, resolved lazily
//   proc.offsets()   — a dumper-generated signature/RVA database
//
// A real table entry is "module + static RVA -> deref chain -> field". This
// demo builds all three forms against the target's own main module so it runs
// against any process (notepad.exe works).
//
// Run: bun examples/pointer-chains.ts [pid-or-name]
// Repo-local import — consumers use `import { Process } from 'memoryprocess'`.
import { Process } from '../src/index.js';

const target = process.argv[2] ?? 'notepad.exe';
using proc = Process.open(/^\d+$/.test(target) ? Number(target) : target);

const main = proc.modules()[0]!;
const modName = main.path.split(/[\\/]/).pop()!;
console.log(`pid=${proc.pid} main=${modName} base=0x${main.base.toString(16)}`);

// ── addr(): three equivalent forms ─────────────────────────────────────────
// Canonical: module name, then RVA added to its base, then the deref chain.
const a1 = proc.addr(modName, 0); // module + rva 0 → the module base itself
// CE paste-friendly "mod+rva" string, and a raw bigint base.
const a2 = proc.addr(`${modName}+0x0`);
const a3 = proc.addr(BigInt(main.base));

// All resolve to the same place; the PE magic ('MZ') proves it.
for (const [tag, a] of [
  ['canonical', a1],
  ['mod+rva', a2],
  ['bigint', a3],
] as const) {
  const at = a.resolve();
  console.log(
    `${tag.padEnd(10)} → 0x${at.toString(16)}  magic=0x${proc.readUInt16(at).toString(16)}`,
  );
}

// Gotcha: in the 'mod+rva'/bigint forms every chain offset DEREFERENCES — the
// rva is already in the base. proc.addr(`${modName}+0x0`, 0x0) would throw
// AMBIGUOUS_ADDRESS_EXPR (doubled-rva bug catcher); pass the numeric base to
// bypass the check when a 0-offset deref is genuinely wanted.

// ── pointers(): a named CE-style address table ─────────────────────────────
// Entries are lazy — nothing reads memory until you touch an Address.
const p = proc.pointers({
  moduleBase: [modName, 0], // canonical entry form [mod, rva, ...chain]
  peMagic: [`${modName}+0x0`], // CE-string base, no chain
});
console.log(`pointers.peMagic  → 0x${p.peMagic.readUInt32().toString(16)}`);
console.log(`pointers.moduleBase → ${p.moduleBase}`);

// ── offsets(): a cs2-dumper / hazedumper style database ────────────────────
// cs2-dumper layout: { "module.dll": { name: rva } } — static RVAs off a base.
// hazedumper layout: { signatures: { name: {module, pattern, offsets, …} } }.
// Both parse through the same API; here we feed a cs2-style map whose rva 0
// resolves to the module base plus a hazedumper-style netvar.
const off = proc.offsets({
  [modName]: { dwMainBase: 0x0 },
  netvars: { m_iHealth: 0x100 }, // netvars are plain field offsets
});
await off.ready(); // resolves + caches every entry once

// After ready(), resolved names are Address properties on `off` —
// combine with netvars to build the classic `<static> + <field>` expression:
const health = await off.addr('dwMainBase');
console.log(
  `dwMainBase=0x${(await off.resolve('dwMainBase')).toString(16)}  ` +
    `+ netvars.m_iHealth=0x${off.netvars.m_iHealth!.toString(16)} ` +
    `→ 0x${health.resolve() + BigInt(off.netvars.m_iHealth!)}`,
);
console.log(`loaded offsets: ${off.keys().join(', ')}`);
