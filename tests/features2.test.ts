import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Process, ProcessAccess, WriteError } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

const dir = dirname(fileURLToPath(import.meta.url));
const dllPath = join(dir, 'testdll.dll');

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('readSafe', () => {
  test('reads across a PAGE_GUARD boundary, zero-filling unreadable spans', () => {
    using proc = Process.open(victim.pid);
    const buf = proc.readSafe(victim.addr.g_guard, 0x1800);
    expect(buf.length).toBe(0x1800);
    // first page was memset to 0xC5
    for (let i = 0; i < 0x1000; i++) expect(buf[i]).toBe(0xc5);
    // guard page span is not readable -> zeros (the page content is also zeroed,
    // so this holds even if the implementation's read clears the guard)
    for (let i = 0x1000; i < 0x1800; i++) expect(buf[i]).toBe(0);
  });

  test('fully-unmapped address returns a zero buffer without throwing', () => {
    using proc = Process.open(victim.pid);
    const buf = proc.readSafe(0x100000000000n, 256);
    expect(buf.length).toBe(256);
    expect(buf.every((b) => b === 0)).toBe(true);
  });
});

describe('injectDll / ejectDll', () => {
  test('round-trip: module appears then disappears', async () => {
    using proc = Process.open(victim.pid);
    expect(proc.injectDll(dllPath)).toBe(true);
    // loader needs a moment; poll the module list
    let found = false;
    for (let i = 0; i < 40 && !found; i++) {
      const mods = proc.modules();
      found = mods.some((m) =>
        /testdll\.dll$/i.test(m.path.replaceAll('/', '\\')),
      );
      if (!found) await Bun.sleep(50);
    }
    expect(found).toBe(true);
    expect(proc.module('testdll.dll')).toBeDefined();

    expect(proc.ejectDll('testdll.dll')).toBe(true);
    let gone = false;
    for (let i = 0; i < 40 && !gone; i++) {
      await Bun.sleep(50);
      gone = !proc
        .modules()
        .some((m) => /testdll\.dll$/i.test(m.path.replaceAll('/', '\\')));
    }
    expect(gone).toBe(true);
  });
});

describe('Process.open access flags', () => {
  test('openReadOnly: reads work, writes throw WriteError', () => {
    using proc = Process.openReadOnly(victim.pid);
    expect(typeof proc.readInt32(victim.addr.g_i32)).toBe('number');
    expect(() => proc.writeInt32(victim.addr.g_i32, 1)).toThrow(WriteError);
  });

  test('open with ProcessAccess.ALL still writes fine', () => {
    using proc = Process.open(victim.pid, { access: ProcessAccess.ALL });
    const before = proc.readInt32(victim.addr.g_i32);
    proc.writeInt32(victim.addr.g_i32, before + 7);
    expect(proc.readInt32(victim.addr.g_i32)).toBe(before + 7);
  });
});

describe('scanFirst / scanUnique', () => {
  const UNIQUE = '48 8B 05 AA BB CC 90 90 DE AD BE EF 00 11 22 33';

  test('scanUnique finds g_pattern exactly once in victim.exe', async () => {
    using proc = Process.open(victim.pid);
    const hit = await proc.scanUnique(UNIQUE, { module: 'victim.exe' });
    expect(hit).toBe(victim.addr.g_pattern);
  });

  test('scanUnique throws on multi-hit pattern', async () => {
    using proc = Process.open(victim.pid);
    // "DE AD" appears inside g_pattern and g_pattern2 (twice) -> must reject
    await expect(
      proc.scanUnique('DE AD', { module: 'victim.exe' }),
    ).rejects.toThrow();
  });

  test('scanFirst returns the first hit as bigint', async () => {
    using proc = Process.open(victim.pid);
    const hit = await proc.scanFirst(UNIQUE, { module: 'victim.exe' });
    expect(typeof hit).toBe('bigint');
    expect(hit).toBe(victim.addr.g_pattern);
  });
});

describe('watch', () => {
  test('fires with increasing values and unsubscribes cleanly', async () => {
    using proc = Process.open(victim.pid);
    const values: Array<[number, number]> = [];
    const unwatch = proc.watch(
      victim.addr.g_counter,
      (nv, ov) => values.push([nv, ov]),
      25,
    );
    expect(typeof unwatch).toBe('function');

    await Bun.sleep(400);
    expect(values.length).toBeGreaterThan(0);
    // strictly increasing reads (g_counter increments every 50 ms)
    for (let i = 1; i < values.length; i++) {
      expect(values[i]![0]).toBeGreaterThan(values[i - 1]![0]);
    }
    // callback signature: new value >= old value
    for (const [nv, ov] of values) expect(nv).toBeGreaterThanOrEqual(ov);

    const n = values.length;
    unwatch();
    await Bun.sleep(250);
    expect(values.length).toBeLessThanOrEqual(n + 1); // at most one in-flight tick
  });
});

describe('writeProtected (icache flush)', () => {
  test('writes bytes into the .text region and they stick', () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const addr = BigInt(mod.base) + 0x1200n; // inside .text of the tiny exe
    const original = proc.readBuffer(addr, 8);
    const patch = Buffer.from([0x90, 0x90, 0x90, 0x90, 0xcc, 0xcc, 0xcc, 0xcc]);
    expect(proc.writeProtected(addr, patch)).toBe(true);
    expect([...proc.readBuffer(addr, 8)]).toEqual([...patch]);
    // restore so we don't clobber code another test may run
    proc.writeProtected(addr, original);
    expect([...proc.readBuffer(addr, 8)]).toEqual([...original]);
  });
});
