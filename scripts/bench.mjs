// Standalone micro-benchmark for memoryprocess (NOT part of `bun test`).
// Run: node scripts/bench.mjs
// Spawns tests/victim.exe, opens it, and measures read + scan throughput.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const exe = join(root, 'tests', 'victim.exe');
if (!existsSync(exe)) {
  console.error(
    'tests/victim.exe not found — run `node scripts/build-victim.mjs` first',
  );
  process.exit(1);
}

const require = createRequire(import.meta.url);
const native = require(join(root, 'dist', 'memoryprocess.node'));

// --- spawn victim and parse its &g_*=addr stdout -------------------------
const child = spawn(exe, [], { stdio: ['ignore', 'pipe', 'inherit'] });
let buf = '';
const ready = new Promise((res, rej) => {
  child.stdout.on('data', (d) => {
    buf += d.toString();
    if (buf.includes('&g_ptr')) res();
  });
  child.on('error', rej);
  setTimeout(() => rej(new Error('victim spawn timeout')), 10_000);
});
await ready;
const pid = Number(buf.match(/PID=(\d+)/)[1]);
const addr = {};
for (const m of buf.matchAll(/&(g_\w+)=([0-9A-Fa-f]+)/g))
  addr[m[1]] = Number('0x' + m[2]);

const cleanup = () => {
  try {
    child.kill();
  } catch {}
};
process.on('exit', cleanup);

// --- open ---------------------------------------------------------------
const { handle } = native.openProcess(pid);
const close = () => {
  try {
    native.closeHandle(handle);
  } catch {}
};

const target = addr.g_i32;
const results = [];

// 1) readInt32 (scalar) ops/sec over ~3s ----------------------------------
{
  const t0 = performance.now();
  let ops = 0;
  while (performance.now() - t0 < 3000) {
    native.readValue(handle, target, 'int32');
    ops++;
  }
  const sec = (performance.now() - t0) / 1000;
  results.push(['readInt32 ops/sec', (ops / sec).toFixed(0)]);
}

// 2) readBuffer(4KB) ops/sec ----------------------------------------------
{
  const base = addr.g_bigbuf;
  const t0 = performance.now();
  let ops = 0;
  while (performance.now() - t0 < 3000) {
    native.readBuffer(handle, base, 4096);
    ops++;
  }
  const sec = (performance.now() - t0) / 1000;
  const mib = ((ops * 4096) / sec / 1024 / 1024).toFixed(1);
  results.push(['readBuffer(4KB) ops/sec', (ops / sec).toFixed(0)]);
  results.push(['readBuffer(4KB) MiB/sec', mib]);
}

// 3) full-module scan wall-time of a 2-byte pattern ------------------------
{
  const mod = native
    .getModules(handle, pid)
    .find((m) => /victim\.exe$/i.test(m.path.replaceAll('/', '\\')));
  const t0 = performance.now();
  const hits = await native.scan(handle, 'DE AD', {
    start: mod.base,
    end: mod.base + mod.size,
  });
  const ms = performance.now() - t0;
  results.push([
    `scan('DE AD') victim.exe (${(mod.size / 1024).toFixed(0)} KiB)`,
    `${ms.toFixed(1)} ms, ${hits.length} hits`,
  ]);
}

// --- report ---------------------------------------------------------------
const w = Math.max(...results.map(([k]) => k.length));
console.log('\nmemoryprocess bench (victim.exe pid ' + pid + ')');
for (const [k, v] of results) console.log(`  ${k.padEnd(w)}  ${v}`);

close();
cleanup();
