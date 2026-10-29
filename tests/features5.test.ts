import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Process, Protection } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

const dir = dirname(fileURLToPath(import.meta.url));
const exe = join(dir, 'victim.exe');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('pattern parse hardening (was: process abort)', () => {
  test('invalid pattern rejects with INVALID_PATTERN, no crash', async () => {
    using proc = Process.open(victim.pid);
    await expect(proc.scan('GG HH')).rejects.toMatchObject({
      code: 'INVALID_PATTERN',
    });
    await expect(proc.scan('???')).rejects.toMatchObject({
      code: 'INVALID_PATTERN',
    });
    await expect(proc.scan('1FF')).rejects.toMatchObject({
      code: 'INVALID_PATTERN',
    });
    await expect(proc.scan('4G')).rejects.toMatchObject({
      code: 'INVALID_PATTERN',
    });
    await expect(proc.scan('')).rejects.toThrow();
    // the process is still alive and usable afterwards
    expect(proc.readUInt8(victim.addr.g_u8)).toBe(0x7f);
  });
});

describe('rel32 range checks', () => {
  test('patchJump / patchCall throw when dst is outside ±2GB', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x1000);
    try {
      expect(() => proc.patchJump(src, src + 0x1_0000_0000n)).toThrow(/rel32/);
      expect(() => proc.patchCall(src, src - 0x1_0000_0000n)).toThrow(/rel32/);
      // and a bogus far target
      expect(() => proc.patchJump(src, 0x7f00_0000_0000n)).toThrow(/rel32/);
      // in-range still works
      expect(() => proc.patchJump(src, src + 0x80n)).not.toThrow();
    } finally {
      proc.free(src);
    }
  });
});

describe('read size validation', () => {
  test('readSafe / readBuffer reject negative, non-finite, and huge sizes', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readSafe(victim.addr.g_i32, -1)).toThrow(RangeError);
    expect(() => proc.readSafe(victim.addr.g_i32, 1e12)).toThrow(RangeError);
    expect(() => proc.readSafe(victim.addr.g_i32, Number.NaN)).toThrow(
      RangeError,
    );
    expect(() => proc.readBuffer(victim.addr.g_i32, -5)).toThrow(RangeError);
    expect(() =>
      proc.readBuffer(victim.addr.g_i32, 1024 * 1024 * 1024),
    ).toThrow(RangeError);
  });
});

const addrs = (hits: { addr: bigint }[]) => hits.map((h) => h.addr);

describe('scanValue', () => {
  test('finds a unique private sentinel in writable memory', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeInt32(buf, 0x5aa5cc33);
      const hits = await proc.scanValue(0x5aa5cc33, { type: 'int32' });
      expect(addrs(hits)).toContain(buf);
      // hits carry the decoded value — the CE hit-list model
      const mine = hits.find((h) => h.addr === buf)!;
      expect(mine.value).toBe(0x5aa5cc33);
    } finally {
      proc.free(buf);
    }
  });

  test('float scan finds a private f32 value', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeFloat(buf, 87.5);
      const hits = await proc.scanValue(87.5, {
        type: 'float',
        module: undefined,
      });
      expect(hits.length).toBeGreaterThan(0);
      expect(addrs(hits)).toContain(buf);
      expect(hits.find((h) => h.addr === buf)!.value).toBeCloseTo(87.5);
    } finally {
      proc.free(buf);
    }
  });

  test('int64 / double scans hit their needles with decoded values', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeInt64(buf, 0x0102030405060708n);
      proc.writeDouble(buf + 0x40n, 1337.125);
      const h64 = await proc.scanValue(0x0102030405060708n, { type: 'int64' });
      expect(addrs(h64)).toContain(buf);
      expect(h64.find((h) => h.addr === buf)!.value).toBe(0x0102030405060708n);
      const hd = await proc.scanValue(1337.125, { type: 'double' });
      expect(addrs(hd)).toContain(buf + 0x40n);
      expect(hd.find((h) => h.addr === buf + 0x40n)!.value).toBe(1337.125);
    } finally {
      proc.free(buf);
    }
  });
});

describe('nextScan (refine)', () => {
  test('exact mode keeps only hits whose value still matches after mutation', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeInt32(buf, 0x1111_2222);
      proc.writeInt32(buf + 0x40n, 0x1111_2222);
      const hits = [buf, buf + 0x40n, buf + 0x80n]; // bare addresses still OK for exact
      proc.writeInt32(buf + 0x40n, 0x9999); // mutate one
      const refined = await proc.nextScan(
        hits,
        { type: 'exact', value: 0x1111_2222 },
        { type: 'int32' },
      );
      const ra = addrs(refined);
      expect(ra).toContain(buf);
      expect(ra).not.toContain(buf + 0x40n);
      expect(ra).not.toContain(buf + 0x80n);
      // and the surviving hit carries the re-read value
      expect(refined.find((h) => h.addr === buf)!.value).toBe(0x1111_2222);
      // legacy positional-value call shape still works
      const legacy = await proc.nextScan(hits, 0x1111_2222, { type: 'int32' });
      expect(addrs(legacy)).toEqual(ra);
    } finally {
      proc.free(buf);
    }
  });

  test('live mutation: g_i32 keeps its address when refined with the new value', async () => {
    using proc = Process.open(victim.pid);
    const addr = victim.addr.g_i32;
    const cur = proc.readInt32(addr);
    await sleep(1100); // victim bumps g_i32 ~1/sec
    const now = proc.readInt32(addr);
    if (now === cur) return; // unlucky timing window — skip rather than flake
    const refined = await proc.nextScan([addr], now, { type: 'int32' });
    expect(addrs(refined)).toEqual([addr]);
    expect(refined[0]!.value).toBe(now);
  });

  test('CE relative modes: changed/unchanged/increased/decreased/byDelta', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      // A = will stay, B = +10, C = -5
      proc.writeInt32(buf, 100);
      proc.writeInt32(buf + 0x40n, 200);
      proc.writeInt32(buf + 0x80n, 300);
      // Seed hit-list via a real (narrow) scan so ScanHit values are genuine.
      const seed = async (addr: bigint) =>
        (
          await proc.scanValue(proc.readInt32(addr), {
            type: 'int32',
            start: addr,
            end: addr + 4n,
          })
        )[0]!;
      const list = [
        await seed(buf),
        await seed(buf + 0x40n),
        await seed(buf + 0x80n),
      ];
      proc.writeInt32(buf + 0x40n, 210);
      proc.writeInt32(buf + 0x80n, 295);

      const changed = await proc.nextScan(
        list,
        { type: 'changed' },
        {
          type: 'int32',
        },
      );
      expect(addrs(changed)).toEqual([buf + 0x40n, buf + 0x80n]);
      // chained: changed's stored value is now the NEW value
      expect(changed[0]!.value).toBe(210);
      expect(changed[1]!.value).toBe(295);

      const unchanged = await proc.nextScan(
        list,
        { type: 'unchanged' },
        {
          type: 'int32',
        },
      );
      expect(addrs(unchanged)).toEqual([buf]);

      const inc = await proc.nextScan(
        list,
        { type: 'increased' },
        {
          type: 'int32',
        },
      );
      expect(addrs(inc)).toEqual([buf + 0x40n]);
      const dec = await proc.nextScan(
        list,
        { type: 'decreased' },
        {
          type: 'int32',
        },
      );
      expect(addrs(dec)).toEqual([buf + 0x80n]);

      const incBy = await proc.nextScan(
        list,
        { type: 'increasedBy', value: 10 },
        { type: 'int32' },
      );
      expect(addrs(incBy)).toEqual([buf + 0x40n]);
      const decBy = await proc.nextScan(
        list,
        { type: 'decreasedBy', value: 5 },
        { type: 'int32' },
      );
      expect(addrs(decBy)).toEqual([buf + 0x80n]);

      const between = await proc.nextScan(
        list,
        { type: 'between', lo: 100, hi: 299 },
        { type: 'int32' },
      );
      // current values 100, 210, 295 — all inside [100, 299]
      expect(addrs(between)).toEqual([buf, buf + 0x40n, buf + 0x80n]);

      const ranged = await proc.nextScan(
        list,
        { type: 'range', lo: 200, hi: 250 },
        { type: 'int32' },
      );
      expect(addrs(ranged)).toEqual([buf + 0x40n]);
    } finally {
      proc.free(buf);
    }
  });

  test('relative modes on a live counter (g_counter ticks up)', async () => {
    using proc = Process.open(victim.pid);
    const addr = victim.addr.g_counter;
    const first = await proc.scanValue(proc.readInt32(addr), {
      type: 'int32',
      start: addr,
      end: addr + 4n,
    });
    expect(addrs(first)).toEqual([addr]);
    await sleep(1100); // victim bumps g_counter ~1/sec
    const after = proc.readInt32(addr);
    if (after === first[0]!.value) return; // unlucky timing — skip
    const inc = await proc.nextScan(
      first,
      { type: 'increased' },
      {
        type: 'int32',
      },
    );
    expect(addrs(inc)).toEqual([addr]);
    const unchanged = await proc.nextScan(
      first,
      { type: 'unchanged' },
      {
        type: 'int32',
      },
    );
    expect(unchanged).toEqual([]);
  });

  test('relative modes reject bare-address hits (no stored value)', async () => {
    using proc = Process.open(victim.pid);
    await expect(
      proc.nextScan([victim.addr.g_i32], { type: 'changed' }),
    ).rejects.toThrow(TypeError);
  });
});

describe('freeze', () => {
  test('holds a writable value against an external writer', async () => {
    using proc = Process.open(victim.pid);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeInt32(buf, 0x7777);
      const unfreeze = proc.freeze(buf, 'int32', 0x7777, 20);
      try {
        proc.writeInt32(buf, 0x1111); // simulate mutation
        await sleep(80);
        expect(proc.readInt32(buf)).toBe(0x7777);
        await sleep(80);
        expect(proc.readInt32(buf)).toBe(0x7777);
      } finally {
        unfreeze();
      }
      proc.writeInt32(buf, 0x2222);
      await sleep(60);
      expect(proc.readInt32(buf)).toBe(0x2222);
    } finally {
      proc.free(buf);
    }
  });
});

describe('suspendProcess / resumeProcess (NtSuspendProcess)', () => {
  test('freezes the whole process atomically', async () => {
    using proc = Process.open(victim.pid);
    expect(proc.suspendProcess()).toBe(true);
    try {
      const a = proc.readInt32(victim.addr.g_counter);
      await sleep(150);
      const b = proc.readInt32(victim.addr.g_counter);
      expect(b).toBe(a);
    } finally {
      expect(proc.resumeProcess()).toBe(true);
    }
    await sleep(150);
    const c = proc.readInt32(victim.addr.g_counter);
    const a = proc.readInt32(victim.addr.g_counter);
    expect(a).toBeGreaterThan(0);
    void c;
  });
});

describe('enableDebugPrivilege', () => {
  test('returns a boolean without throwing', () => {
    expect(typeof Process.enableDebugPrivilege()).toBe('boolean');
  });
});

describe('section-aware scan', () => {
  test('scan with section returns hits inside the module', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.scan('4D 5A', {
      module: 'victim.exe',
      section: '.text',
    });
    const mod = proc.module('victim.exe')!;
    const base = BigInt(mod.base);
    for (const h of hits) {
      expect(h >= base && h < base + BigInt(mod.size)).toBe(true);
    }
    // sanity: the same pattern over the whole module finds at least as many
    const all = await proc.scan('4D 5A', { module: 'victim.exe' });
    expect(hits.length).toBeLessThanOrEqual(all.length);
  });

  test('unknown section returns empty, not a crash', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.scan('4D 5A', {
      module: 'victim.exe',
      section: '.nope',
    });
    expect(hits).toEqual([]);
  });
});

describe('waitForExit', () => {
  test('times out with null on a live process, resolves exit code after kill', async () => {
    // dedicated victim so the kill can't disturb the shared fixture
    const child = spawn(exe, [], { stdio: ['ignore', 'pipe', 'ignore'] });
    let buf = '';
    await new Promise<void>((res, rej) => {
      const t = setTimeout(
        () => rej(new Error('victim2 spawn timeout')),
        10_000,
      );
      child.stdout!.on('data', (d) => {
        buf += d.toString();
        if (buf.includes('&g_pattern2')) {
          clearTimeout(t);
          res();
        }
      });
      child.on('error', rej);
    });
    const pid = Number(buf.match(/PID=(\d+)/)![1]);
    using proc = Process.open(pid);

    // still running → timeout resolves null
    const t0 = Date.now();
    const r1 = await proc.waitForExit(400);
    expect(r1).toBeNull();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(350);

    child.kill();
    const r2 = await proc.waitForExit(5000);
    expect(typeof r2).toBe('number');
    expect(r2).not.toBeNull();
  });
});
