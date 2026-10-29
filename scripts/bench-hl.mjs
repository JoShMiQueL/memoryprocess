// Perf audit bench — native layer + HL layer (readMany, Entity, resolvePointer,
// watch, modules). Reuses an already-running victim.exe (prints PID + &g_*).
// Run: taskkill /F /IM victim.exe ; start victim.exe ; node scripts/bench-hl.mjs
import { spawn, execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const exe = join(root, 'tests', 'victim.exe');
const outFile = join(process.env.TEMP, 'mp-bench-victim.txt');
try {
  execSync('taskkill /F /IM victim.exe', { stdio: 'ignore' });
} catch {}
const { openSync, closeSync } = await import('node:fs');
const fd = openSync(outFile, 'w');
const child = spawn(exe, [], { stdio: ['ignore', fd, 'inherit'] });
await new Promise((r) => setTimeout(r, 1500));
try {
  closeSync(fd);
} catch {}
const txt = readFileSync(outFile, 'utf8');
const pid = Number(txt.match(/PID=(\d+)/)[1]);
const addr = {};
for (const m of txt.matchAll(/&(g_\w+)=([0-9A-Fa-f]+)/g))
  addr[m[1]] = Number('0x' + m[2]);

const require = createRequire(import.meta.url);
const native = require(join(root, 'dist', 'memoryprocess.node'));
const { Process } = await import(
  pathToFileURL(join(root, 'dist', 'index.js')).href
);

const { handle } = native.openProcess(pid);
const proc = Process.open(pid);

const results = [];
const timed = (label, fn, ms = 2000) => {
  const t0 = performance.now();
  let ops = 0;
  while (performance.now() - t0 < ms) {
    fn();
    ops++;
  }
  const sec = (performance.now() - t0) / 1000;
  results.push([label, `${(ops / sec).toFixed(0)} ops/s`]);
};

// 1. native scalar read (baseline)
timed('native.readValue int32', () =>
  native.readValue(handle, addr.g_i32, 'int32'),
);
// 2. HL readInt32 (TS wrapper)
timed('proc.readInt32', () => proc.readInt32(addr.g_i32));
// 3. native readBuffer 4KB
timed('native.readBuffer 4KB', () =>
  native.readBuffer(handle, addr.g_bigbuf, 4096),
);
// 4. readSafe 4KB (region-walking path)
timed('native.readSafe 4KB', () =>
  native.readSafe(handle, addr.g_bigbuf, 4096),
);
// 5. modules() — Toolhelp snapshot cost
timed('proc.modules() (toolhelp)', () => proc.modules());
// 6. module('victim.exe')
timed("proc.module('victim.exe')", () => proc.module('victim.exe'));
// 7. queryAddress
timed('native.queryAddress', () => native.queryAddress(handle, addr.g_i32));
// 8. regions() full VA walk
timed('proc.regions() full VA walk', () => proc.regions(), 1000);
// 9. resolvePointer 3-chain (3 RPM)
timed('resolvePointer 3-deep', () =>
  proc.resolvePointer(addr.g_ppp, [0, 0, 0]),
);
// 10. readMany — 4 addresses scattered on ONE page (g_i32..g_wstr ~same page)
timed('readMany 4 reqs same page', () =>
  proc.readMany([
    { addr: addr.g_i32, type: 'int32' },
    { addr: addr.g_i64, type: 'int64' },
    { addr: addr.g_f32, type: 'float' },
    { addr: addr.g_str, type: 'pointer' },
  ]),
);
// 11. readMany — 4 reqs on DIFFERENT pages (g_i32, g_bigbuf, g_entity, g_ptr, g_guard_end)
timed('readMany 4 pages', () =>
  proc.readMany([
    { addr: addr.g_i32, type: 'int32' },
    { addr: addr.g_bigbuf, type: 'int32' },
    { addr: addr.g_entity, type: 'int32' },
    { addr: addr.g_ptr, type: 'pointer' },
  ]),
);
// 12. Entity.snapshot — entity schema covering g_entity (packed struct)
const schema = {
  i32: [0, 'int32'],
  f32: [4, 'float'],
  ptr: [8, 'pointer'],
};
const ent = proc.entity(addr.g_entity, schema);
timed('entity.snapshot (3 fields)', () => ent.snapshot());
// 13. Address resolve: 'victim.exe+0x...' — module lookup per construction
const p = proc.pointers({ x: ['victim.exe+0x0', 0] });
timed('Address construction + resolve (module)', () =>
  proc.addr('victim.exe+0x0', 0).resolve(),
);
// 14. writeInt32
timed('proc.writeInt32', () => proc.writeInt32(addr.g_i32, 42));
// 15. scan 'DE AD' in victim.exe module (native async)
{
  const mod = proc.module('victim.exe');
  const t0 = performance.now();
  const hits = await native.scan(pid, 'DE AD', {
    start: mod.base,
    end: mod.base + mod.size,
  });
  const ms = performance.now() - t0;
  results.push([
    `native.scan 2B in ${(mod.size / 1024).toFixed(0)}KiB`,
    `${ms.toFixed(1)}ms ${hits.length} hits`,
  ]);
}
// 16. scanValue int32=42 over a 64MB heap region? skip — victim too small. Instead:
// full writable-region value scan wall time for a unique value.
{
  const t0 = performance.now();
  const needle = Buffer.alloc(4);
  needle.writeInt32LE(0x11223344);
  const hits = await native.scanValue(pid, needle, { onlyWritable: true });
  const ms = performance.now() - t0;
  results.push([
    'native.scanValue 0x11223344 all writable',
    `${ms.toFixed(0)}ms ${hits.length} hits`,
  ]);
}
// 17. listThreads
timed('proc.threads() (toolhelp)', () => proc.threads());

const w = Math.max(...results.map(([k]) => k.length));
console.log(`\nmemoryprocess perf audit (victim.exe pid ${pid})`);
for (const [k, v] of results) console.log(`  ${k.padEnd(w)}  ${v}`);
child.kill();
