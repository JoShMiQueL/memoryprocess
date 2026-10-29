import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, Protection } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

// Regression tests for the round-2 audit (memoryprocess-code-review-r2.md):
//   M1 — hook() must free its RWX stub when patching fails
//   M3 — freeze()/watch() intervals must die with close()
//   M4 — writeProtected restore failure must not mask the write result
//   m10 — disassemble() with an absurd count must not wrap count*16

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('M1 — hook() frees the RWX stub on failure', () => {
  test('hook into unmapped src throws and leaves no new RWX region', () => {
    using proc = Process.open(victim.pid);
    const before = proc
      .regions()
      .filter(
        (r) => (r.protection & Protection.PAGE_EXECUTE_READWRITE) !== 0,
      ).length;
    // disassemble on unmapped memory throws before any stub is allocated
    expect(() => proc.hook(0x1337_0000_0000n, victim.addr.g_counter)).toThrow();
    const mid = proc
      .regions()
      .filter(
        (r) => (r.protection & Protection.PAGE_EXECUTE_READWRITE) !== 0,
      ).length;
    expect(mid).toBe(before);

    // Force failure AFTER #allocNear succeeds: valid src, dst out of rel32 range.
    const src = proc.alloc(0x1000, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(src, Buffer.alloc(16, 0x90));
    expect(() => proc.hook(src, src + 0x8_0000_0000n)).toThrow();
    const after = proc
      .regions()
      .filter(
        (r) => (r.protection & Protection.PAGE_EXECUTE_READWRITE) !== 0,
      ).length;
    // only our own `src` alloc remains — the stub was freed
    expect(after).toBe(mid + 1);
    proc.free(src);
  });
});

describe('M3 — freeze()/watch() timers die with close()', () => {
  test('freeze interval stops writing after close()', async () => {
    const proc = Process.open(victim.pid);
    // g_u32 is never mutated by the victim — safe to assert == while frozen
    proc.freeze(victim.addr.g_u32, 'uint32', 0x5a5a, 20);
    await sleep(80);
    expect(proc.readUInt32(victim.addr.g_u32)).toBe(0x5a5a);
    proc.close();
    await sleep(80);
    // a leftover timer polling handle 0 can't keep re-writing — verify by
    // writing a different value through a fresh handle and observing it stick
    using proc2 = Process.open(victim.pid);
    proc2.writeUInt32(victim.addr.g_u32, 0x4242);
    await sleep(80);
    expect(proc2.readUInt32(victim.addr.g_u32)).toBe(0x4242);
  });

  test('watch interval self-clears after close()', async () => {
    const proc = Process.open(victim.pid);
    let calls = 0;
    proc.watch(
      victim.addr.g_counter,
      () => {
        calls++;
      },
      10,
    );
    // g_counter mutates ~every 50ms; give the watcher generous room to observe a change
    await sleep(200);
    expect(calls).toBeGreaterThan(0);
    proc.close();
    calls = 0;
    await sleep(120);
    expect(calls).toBe(0); // no ticks survive close()
  });
});

describe('M4/m10 — writeProtected restore + disasm count cap', () => {
  test('writeProtected on unmapped addr throws WriteError (not masked by restore)', () => {
    using proc = Process.open(victim.pid);
    expect(() =>
      proc.writeProtected(0x1337_0000_0000n, Buffer.from([0x90])),
    ).toThrow();
  });

  test('disassemble with huge count reads a bounded window, no wrap', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x2000, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(src, Buffer.alloc(0x2000, 0x90));
    const insns = proc.disassemble(src, 1e12);
    expect(insns.length).toBeGreaterThan(0);
    expect(insns.length).toBeLessThanOrEqual(256);
    proc.free(src);
  });
});

describe('M5 — nextScan page-straddle', () => {
  test('value straddling a 4KB boundary is re-checked with alignment:1', async () => {
    using proc = Process.open(victim.pid);
    // place an int64 at page_end - 4 so it straddles two pages
    const base = proc.alloc(0x3000, Protection.PAGE_READWRITE);
    const straddle = base + 0x1000n - 4n;
    proc.writeInt64(straddle, 0x112233445566n);
    const hits = await proc.scanValue(0x112233445566n, {
      type: 'int64',
      alignment: 1,
      start: base,
      end: base + 0x3000n,
    });
    expect(hits.map((h) => h.addr)).toContain(straddle);
    const kept = await proc.nextScan(hits, 0x112233445566n, { type: 'int64' });
    expect(kept.map((h) => h.addr)).toContain(straddle);
    proc.free(base);
  });
});
