import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  Process,
  ProcessAccess,
  Protection,
  ReadError,
  WriteError,
} from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

// abuse2 — wide fuzz/abuse suite. Every case must produce a graceful
// throw / benign return — NEVER a crash or a hang. A crash here is a
// library bug (mark it // CRASH:).

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Race an async call against a timeout so a hang fails instead of
// blocking the suite forever.
async function withTimeout<T>(
  p: Promise<T>,
  ms = 30_000,
): Promise<{ ok: boolean; value?: T; error?: unknown }> {
  try {
    const value = await Promise.race([
      p,
      new Promise<never>((_, rej) =>
        setTimeout(() => rej(new Error('TIMEOUT — possible hang')), ms),
      ),
    ]);
    return { ok: true, value };
  } catch (error) {
    return { ok: false, error };
  }
}

// A call is acceptable if it throws any Error OR returns without crashing.
function benignOrThrow(fn: () => unknown): {
  threw: boolean;
  value: unknown;
  error: unknown;
} {
  try {
    return { threw: false, value: fn(), error: undefined };
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    return { threw: true, value: undefined, error };
  }
}

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

// ---------------------------------------------------------------- precision
describe('precision / out-of-range addresses', () => {
  test('readInt32(2^53+1) → ReadError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readInt32(2n ** 53n + 1n)).toThrow(ReadError);
  });
  test('readBuffer(0x8000000000000, 8) → ReadError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readBuffer(0x8000000000000n, 8)).toThrow(ReadError);
  });
  test('readSafe(0xFFFFFFFFFFFFFF00, 16) → 16-byte buffer', () => {
    using proc = Process.open(victim.pid);
    const buf = proc.readSafe(0xffffffffffffff00n, 16);
    expect(buf.length).toBe(16);
  });
  test('readPointer(u64 max) → ReadError, no wraparound read', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readPointer(0xffffffffffffffffn)).toThrow(ReadError);
  });
  test('writeInt32(2^53+1) → WriteError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.writeInt32(2n ** 53n + 1n, 0)).toThrow(WriteError);
  });
});

describe('size abuse (-1/0/2^32/1e18/NaN/Infinity)', () => {
  const badSizes = [-1, 2 ** 32, 1e18, NaN, Infinity, -Infinity];
  for (const s of badSizes) {
    test(`readSafe size ${s} → RangeError`, () => {
      using proc = Process.open(victim.pid);
      expect(() => proc.readSafe(victim.addr.g_i32, s)).toThrow(RangeError);
    });
    test(`readBuffer size ${s} → RangeError`, () => {
      using proc = Process.open(victim.pid);
      expect(() => proc.readBuffer(victim.addr.g_i32, s)).toThrow(RangeError);
    });
    test(`alloc size ${s} → throw or benign`, () => {
      using proc = Process.open(victim.pid);
      const r = benignOrThrow(() => proc.alloc(s, Protection.PAGE_READWRITE));
      if (!r.threw && typeof r.value === 'bigint' && r.value !== 0n)
        proc.free(r.value as bigint);
    });
  }
  test('readSafe size 0 → benign (0-byte buffer or throw)', () => {
    using proc = Process.open(victim.pid);
    const r = benignOrThrow(() => proc.readSafe(victim.addr.g_i32, 0));
    if (!r.threw) expect((r.value as Buffer).length).toBe(0);
  });
  test('alloc size 0 → benign', () => {
    using proc = Process.open(victim.pid);
    const r = benignOrThrow(() => proc.alloc(0, Protection.PAGE_READWRITE));
    if (!r.threw && r.value) proc.free(r.value as bigint);
  });
});

// ------------------------------------------------------------ type confusion
describe('type confusion — wrong arg types must not cross N-API', () => {
  test("readInt32('x') → TypeError", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readInt32('x' as any)).toThrow(TypeError);
  });
  test("writeBuffer(addr, 'str') — currently accepts string, must not crash", () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.writeBuffer(victim.addr.g_bigbuf, 'str' as any));
  });
  test('writeBuffer(addr, 123) → TypeError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.writeBuffer(victim.addr.g_bigbuf, 123 as any)).toThrow(
      TypeError,
    );
  });
  test('scan(123) → TypeError', async () => {
    using proc = Process.open(victim.pid);
    await expect(proc.scan(123 as any)).rejects.toThrow(TypeError);
  });
  test("protect(addr, sz, 'x') → TypeError", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.protect(victim.addr.g_i32, 4, 'x' as any)).toThrow(
      TypeError,
    );
  });
  test("hook(src, 'notnum') → TypeError", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.hook(victim.addr.g_i32, 'notnum' as any)).toThrow(
      TypeError,
    );
  });
  test("disassemble(addr, 'x') → TypeError", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.disassemble(victim.addr.g_i32, 'x' as any)).toThrow(
      TypeError,
    );
  });
  test("freeze(addr, 'nope', 1) → TypeError", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.freeze(victim.addr.g_u32, 'nope' as any, 1)).toThrow(
      TypeError,
    );
  });
  test('writeInt32(addr, {}) — value confusion benign or throw', () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.writeInt32(victim.addr.g_bigbuf, {} as any));
  });
});

// --------------------------------------------------------------- after-close
describe('after-close — every method throws /closed|open/i', () => {
  test('table-driven: ~40 method calls on a closed handle', async () => {
    const proc = Process.open(victim.pid);
    proc.close();
    const a = victim.addr.g_i32;
    const stub = victim.addr.g_pattern;
    const rows: [string, () => unknown][] = [
      ['readInt32', () => proc.readInt32(a)],
      ['readBuffer', () => proc.readBuffer(a, 8)],
      ['readSafe', () => proc.readSafe(a, 8)],
      ['readString', () => proc.readString(a)],
      ['readWideString', () => proc.readWideString(a)],
      ['readPointer', () => proc.readPointer(a)],
      ['readArray', () => proc.readArray(a, 'int32', 2)],
      ['readStruct', () => proc.readStruct(a, { x: [0, 'int32'] })],
      ['readRegion', () => proc.readRegion(a, 16)],
      ['resolvePointer', () => proc.resolvePointer(a, [0])],
      ['writeInt32', () => proc.writeInt32(a, 1)],
      ['writeBuffer', () => proc.writeBuffer(a, Buffer.from([1]))],
      ['writeProtected', () => proc.writeProtected(a, Buffer.from([0x90]))],
      ['nop', () => proc.nop(a, 1)],
      ['patchJump', () => proc.patchJump(a, stub)],
      ['patchCall', () => proc.patchCall(a, stub)],
      ['alloc', () => proc.alloc(0x1000)],
      ['free', () => proc.free(a)],
      ['protect', () => proc.protect(a, 4, Protection.PAGE_READWRITE)],
      ['queryAddress', () => proc.queryAddress(a)],
      [
        'scan',
        () => proc.scan('AA', { start: Number(a), end: Number(a) + 0x100 }),
      ],
      [
        'scanValue',
        () => proc.scanValue(1, { start: Number(a), end: Number(a) + 0x100 }),
      ],
      ['nextScan', () => proc.nextScan([a], 1)],
      ['injectDll', () => proc.injectDll('C:\\x.dll')],
      ['ejectDll', () => proc.ejectDll('zzz-not-loaded')],
      ['hook', () => proc.hook(stub, a)],
      ['disassemble', () => proc.disassemble(a, 4)],
      ['callRemote', () => proc.callRemote(a, 0, 10)],
      ['getThreadContext', () => proc.getThreadContext(0)],
      ['setThreadContext', () => proc.setThreadContext(0, {})],
      ['hwBreakpoint', () => proc.hwBreakpoint(0, a, 0)],
      ['threads', () => proc.threads()],
      ['module', () => proc.module('victim.exe')],
      ['modules', () => proc.modules()],
      ['regions', () => proc.regions()],
      ['findCodeCave', () => proc.findCodeCave(8)],
      ['resolveExport', () => proc.resolveExport('victim.exe', 'g_i32')],
      ['dumpModule', () => proc.dumpModule('victim.exe', 'nul')],
      ['execShellcode', () => proc.execShellcode(Buffer.from([0xc3]))],
      ['freeze', () => proc.freeze(a, 'int32', 0)],
      ['watch', () => proc.watch(a, () => {})],
      ['suspendProcess', () => proc.suspendProcess()],
      ['waitForExit', () => proc.waitForExit(1)],
      ['isWow64', () => proc.isWow64],
      ['mainThread', () => proc.mainThread],
    ];
    expect(rows.length).toBeGreaterThanOrEqual(40);
    for (const [name, fn] of rows) {
      try {
        const r = fn();
        if (r instanceof Promise) {
          await expect(r, name).rejects.toThrow(/closed|open/i);
        } else {
          throw new Error(`${name} returned without throwing: ${String(r)}`);
        }
      } catch (e: any) {
        expect(String(e?.message ?? e), name).toMatch(/closed|open/i);
      }
    }
  });
});

// ------------------------------------------------------------------ scan abuse
describe('scan abuse', () => {
  test("single-byte 'AA' module-bounded scan returns hits, no OOM", async () => {
    using proc = Process.open(victim.pid);
    const r = await withTimeout(proc.scan('AA', { module: 'victim.exe' }));
    expect(r.ok).toBe(true);
    expect(Array.isArray(r.value)).toBe(true);
  });
  test("match-everything '?? ?? ?? ??' bounded window → hits, no crash", async () => {
    using proc = Process.open(victim.pid);
    const start = Number(victim.addr.g_bigbuf);
    const r = await withTimeout(
      proc.scan('?? ?? ?? ??', { start, end: start + 0x400 }),
    );
    expect(r.ok).toBe(true);
    expect((r.value as bigint[]).length).toBeGreaterThan(0);
  });
  test('pattern longer than the scanned region → 0 hits', async () => {
    using proc = Process.open(victim.pid);
    const start = Number(victim.addr.g_i32);
    const hits = await proc.scan(
      'DE AD BE EF 00 11 22 33 44 55 66 77 88 99 AA BB',
      { start, end: start + 4 },
    );
    expect(hits.length).toBe(0);
  });
  test("scanValue({type:'pointer'}) → TypeError (write-only type)", async () => {
    using proc = Process.open(victim.pid);
    // 'pointer' is a write-type; scanning for it is rejected by contract.
    await expect(
      proc.scanValue(0x1234n, { type: 'pointer' as any }),
    ).rejects.toThrow(TypeError);
  });
  test("nextScan({type:'pointer'}) → TypeError", async () => {
    using proc = Process.open(victim.pid);
    await expect(
      proc.nextScan([victim.addr.g_i32], 0, { type: 'pointer' as any }),
    ).rejects.toThrow(TypeError);
  });
  test("scanValue({type:'bogus'}) → throws TypeError", async () => {
    using proc = Process.open(victim.pid);
    await expect(proc.scanValue(1, { type: 'bogus' as any })).rejects.toThrow(
      TypeError,
    );
  });
  test('nextScan([], v) → []', async () => {
    using proc = Process.open(victim.pid);
    expect(await proc.nextScan([], 0)).toEqual([]);
  });
  test('nextScan on hits inside a freed region → benign, drops dead hits', async () => {
    using proc = Process.open(victim.pid);
    const base = proc.alloc(0x2000, Protection.PAGE_READWRITE);
    proc.writeInt64(base, 0x41414141n);
    const hits = await proc.scanValue(0x41414141n, {
      type: 'int64',
      start: base,
      end: base + 0x2000n,
    });
    expect(hits.map((h) => h.addr)).toContain(base);
    proc.free(base);
    const kept = await proc.nextScan(hits, 0x41414141n, { type: 'int64' });
    expect(kept.map((h) => h.addr)).not.toContain(base);
  });
  test('scan with start > end → benign (empty or throw)', async () => {
    using proc = Process.open(victim.pid);
    const r = await withTimeout(
      proc.scan('AA', { start: 0x7fff0000, end: 0x1000 }),
      10_000,
    );
    expect(r.ok || r.error instanceof Error).toBe(true);
  });
});

// ------------------------------------------------------------------ hook abuse
describe('hook / disasm abuse', () => {
  test('hook(0x100000000000) → throws', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.hook(0x100000000000n, victim.addr.g_counter)).toThrow();
  });
  test('hook dst 3GB away → throws /rel32|range/i', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x1000, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(src, Buffer.alloc(32, 0x90));
    expect(() => proc.hook(src, src + 0xc0000000n)).toThrow(/rel32|range/i);
    proc.free(src);
  });
  test('unhook(forged handle) → false or throw, no crash', () => {
    using proc = Process.open(victim.pid);
    const forged = {
      src: 0x13370000n,
      dst: 0n,
      stub: 0x42000n,
      stolen: Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90]),
    };
    benignOrThrow(() => proc.unhook(forged));
  });
  test('disassemble(unmapped) → throws or []', () => {
    using proc = Process.open(victim.pid);
    const r = benignOrThrow(() => proc.disassemble(0x1337_0000_0000n, 8));
    if (!r.threw) expect(r.value).toEqual([]);
  });
  test('disassemble(addr, -1) → clamped or throw, no crash', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x1000, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(src, Buffer.alloc(0x1000, 0x90));
    const r = benignOrThrow(() => proc.disassemble(src, -1));
    if (!r.threw)
      expect((r.value as unknown[]).length).toBeLessThanOrEqual(512);
    proc.free(src);
  });
  test('disassemble(addr, 1e6) → bounded result', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x1000, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(src, Buffer.alloc(0x1000, 0x90));
    const insns = proc.disassemble(src, 1e6);
    expect(insns.length).toBeLessThanOrEqual(4096);
    proc.free(src);
  });
});

// --------------------------------------------------------- threads / context
describe('thread/context abuse', () => {
  test('setThreadContext(999999, {}) → false or throw', () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.setThreadContext(999999, {}));
  });
  test('hwBreakpoint slot 4/-1/99 → RangeError', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    for (const slot of [4, -1, 99] as any[])
      expect(() => proc.hwBreakpoint(tid, victim.addr.g_i32, slot)).toThrow(
        RangeError,
      );
  });
  test('hwBreakpoint bad size → RangeError', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    expect(() =>
      proc.hwBreakpoint(tid, victim.addr.g_i32, 0, 3 as any),
    ).toThrow(RangeError);
  });
  test('getThreadContext(0) → throws FOREIGN_TID (was: null)', () => {
    using proc = Process.open(victim.pid);
    // H5 fix: tid 0 doesn't belong to the target — rejected, not null-queried.
    expect(() => proc.getThreadContext(0)).toThrow(
      /FOREIGN_TID|does not belong/,
    );
  });
  test('suspendThread(0x7fffffff) → false or throw', () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.suspendThread(0x7fffffff));
  });
});

// ------------------------------------------------------------------ injection
describe('injection abuse', () => {
  test("injectDll('C:\\\\nonexistent.dll') → InjectError or false", () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.injectDll('C:\\nonexistent.dll'));
  });
  test("injectDll('C:\\\\') → throws", () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.injectDll('C:\\')).toThrow();
  });
  test("ejectDll('notloaded') → InjectError or false", () => {
    using proc = Process.open(victim.pid);
    benignOrThrow(() => proc.ejectDll('notloaded'));
  });
});

// ------------------------------------------------------------------ exhaustion
describe('exhaustion', () => {
  test('20 parallel bounded scans complete without crash', async () => {
    using proc = Process.open(victim.pid);
    const start = Number(victim.addr.g_bigbuf);
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        proc.scan('AB AB AB AB', { start, end: start + 0x1000 }),
      ),
    );
    for (const r of results) expect(Array.isArray(r)).toBe(true);
  });
  test('30 freeze+unfreeze cycles leave no live writers', async () => {
    using proc = Process.open(victim.pid);
    for (let i = 0; i < 30; i++) {
      const unfreeze = proc.freeze(victim.addr.g_u32, 'uint32', i, 5);
      unfreeze();
    }
    await sleep(100);
    // no surviving timer may rewrite g_u32 — write a sentinel and confirm it sticks
    proc.writeUInt32(victim.addr.g_u32, 0xc0ffee);
    await sleep(60);
    expect(proc.readUInt32(victim.addr.g_u32)).toBe(0xc0ffee);
  });
  test('open/close victim 150x — no handle leak crash', () => {
    for (let i = 0; i < 150; i++) {
      const p = Process.open(victim.pid);
      p.readInt32(victim.addr.g_i32);
      p.close();
    }
  });
});

// ------------------------------------------------------------------- pid abuse
describe('pid abuse', () => {
  test('open(4) — System process → throws or succeeds (elevated)', () => {
    benignOrThrow(() => {
      const p = Process.open(4);
      p.close();
    });
  });
  test('open(own pid) works', () => {
    const p = Process.open(process.pid);
    expect(p.pid).toBe(process.pid);
    p.close();
  });
  test('open(nonexistent name) → ProcessNotFoundError', () => {
    expect(() => Process.open('definitely-not-a-process-zzz.exe')).toThrow(
      /not found/i,
    );
  });
  test('open(0x7fffffff) → throws', () => {
    expect(() => Process.open(0x7fffffff)).toThrow();
  });
  test('killed victim: every method throws or is benign', async () => {
    const v2 = await spawnVictim();
    const proc = Process.open(v2.pid);
    proc.readInt32(v2.addr.g_i32); // sanity
    v2.kill();
    await sleep(400); // let the process fully exit
    const a = v2.addr.g_i32;
    benignOrThrow(() => proc.readInt32(a));
    benignOrThrow(() => proc.readBuffer(a, 8));
    benignOrThrow(() => proc.readSafe(a, 8));
    benignOrThrow(() => proc.writeInt32(a, 1));
    benignOrThrow(() => proc.modules());
    benignOrThrow(() => proc.regions());
    benignOrThrow(() => proc.threads());
    benignOrThrow(() => proc.alloc(0x100));
    benignOrThrow(() => proc.queryAddress(a));
    // async: OpenProcess inside the worker must reject or yield []
    const s = await withTimeout(
      proc.scan('AA', { start: Number(a), end: Number(a) + 0x100 }),
    );
    if (s.ok) expect(s.value).toEqual([]);
    const sv = await withTimeout(
      proc.scanValue(1, { start: Number(a), end: Number(a) + 0x100 }),
    );
    if (sv.ok) expect(sv.value).toEqual([]);
    const w = await withTimeout(proc.waitForExit(2000));
    if (w.ok)
      expect(w.value === null || typeof w.value === 'number').toBe(true);
    proc.close();
  });
});
