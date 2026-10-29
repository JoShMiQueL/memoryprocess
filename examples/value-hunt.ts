// value-hunt.ts — the classic Cheat Engine flow:
//   1. scanValue  — find every address holding an exact typed value
//   2. nextScan   — refine the hit list after the value changes
//   3. freeze     — lock the found address to a chosen value
//
// To keep the demo self-contained we plant a fake "health" value inside
// the target's memory (a real scenario would be the game's own data);
// the hunt itself uses exactly the same calls you'd make blind.
//
// Run: bun examples/value-hunt.ts <pid-or-name>
// Repo-local import — consumers use `import { Process } from 'memoryprocess'`.
import { Process, Protection } from '../src/index.js';

const target = process.argv[2] ?? 'notepad.exe';
using proc = Process.open(/^\d+$/.test(target) ? Number(target) : target);

// ── setup (simulated game state — you wouldn't do this on a real target) ──
const page = proc.alloc(0x1000, Protection.PAGE_READWRITE);
const HEALTH_OFF = 0x240n;
const healthAddr = page + HEALTH_OFF;
const decoyAddr = page + 0x40n; // second address with the same value — must be filtered out

proc.writeInt32(healthAddr, 5000);
proc.writeInt32(decoyAddr, 5000);

// ── 1. first scan: "exact value" ─────────────────────────────────────────
console.time('scanValue');
let hits = await proc.scanValue(5000, { type: 'int32' });
console.timeEnd('scanValue');
console.log(`scanValue(5000): ${hits.length} hit(s)`);

// ── 2. the "game" changes — health drops, decoy doesn't ──────────────────
proc.writeInt32(healthAddr, 3500); // simulate damage
console.time('nextScan');
hits = await proc.nextScan(hits, 3500, { type: 'int32' });
console.timeEnd('nextScan');
console.log(`nextScan(3500): ${hits.length} hit(s)`);

// another round narrows further — 3500 → 1200
proc.writeInt32(healthAddr, 1200);
hits = await proc.nextScan(hits, 1200, { type: 'int32' });
console.log(
  `nextScan(1200): ${hits.length} hit(s) →`,
  hits.map((h) => '0x' + h.toString(16)),
);

// hits should now contain our planted address (noise hits that happened to
// hold the same values can survive too — that's exactly like real CE use)
if (!hits.includes(healthAddr)) {
  console.error('planted address was filtered out — something is wrong');
  proc.free(page);
  process.exit(1);
}

// ── 3. freeze: lock health at 9999 ───────────────────────────────────────
const unfreeze = proc.freeze(healthAddr, 'int32', 9999, 25 /* ms */);

// the "game" tries to damage us — freeze keeps overwriting it back
proc.writeInt32(healthAddr, 1);
await new Promise((r) => setTimeout(r, 150)); // a few freeze ticks pass
const cur = proc.readInt32(healthAddr);
console.log(
  `after freeze: health=${cur} ${cur === 9999 ? '(locked)' : '(unexpected)'}`,
);

unfreeze();
proc.free(page);
console.log('done — unfroze and released the demo page');
