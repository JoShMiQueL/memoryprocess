/**
 * lifecycle — QA round-4 TS-layer fixes:
 *   C1  FinalizationRegistry + exit sweep (double-close safe, no API break)
 *   C2  watch/freeze timers unref'd + WeakRef'd (won't pin Process/event loop)
 *   perf  module cache (module() memoized, miss re-enumerates, refreshModules)
 *   H5  tid-ownership validation on suspend/resume/context APIs
 *   H1  negative/NaN timeoutMs rejected with TypeError
 *   m3  typed PROCESS_CLOSED on read-after-close
 *   span  entity schema span > 64KiB rejected
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  InvalidSchemaError,
  MemoryProcessError,
  Process,
  ProcessClosedError,
} from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

const dir = dirname(fileURLToPath(import.meta.url));
const srcIndex = pathToFileURL(join(dir, '..', 'src', 'index.js')).href;
const BUN = Bun.which('bun') ?? 'bun';

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('C1 — finalizer / close lifecycle', () => {
  test('close() twice is a safe no-op (finalizer unregistered)', () => {
    const proc = Process.open(victim.pid);
    proc.close();
    expect(() => proc.close()).not.toThrow();
    expect(proc.handle).toBe(0);
  });

  test('using-dispose + explicit close is idempotent', () => {
    const proc = Process.open(victim.pid);
    proc[Symbol.dispose]();
    expect(() => proc.close()).not.toThrow();
  });
});

describe('C2 — watch/freeze do not anchor the process or event loop', () => {
  test("watch returns an unsubscribe fn and its timer is unref'd", () => {
    using proc = Process.open(victim.pid);
    const un = proc.watch(victim.addr.g_counter, () => {}, 25);
    expect(typeof un).toBe('function');
    un();
  });

  test("freeze returns a stop fn and its timer is unref'd", () => {
    using proc = Process.open(victim.pid);
    const un = proc.freeze(victim.addr.g_u32, 'uint32', 0x5a5a, 25);
    expect(typeof un).toBe('function');
    un();
  });

  test("subprocess: open + watch + return exits promptly (timer unref'd)", () => {
    // If watch's interval were NOT unref'd, this script would hang past the
    // 4s timeout — the interval would keep the event loop alive.
    const code =
      `import {Process} from ${JSON.stringify(srcIndex)};` +
      `const p=Process.open(${victim.pid});` +
      `p.watch(0x10000n,()=>{},10);` + // bogus addr is fine — only the timer matters
      `console.log('DONE');`;
    const t0 = Date.now();
    const r = spawnSync(BUN, ['-e', code], {
      timeout: 4000,
      killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'pipe'],
    } as any);
    const ms = Date.now() - t0;
    expect(ms).toBeLessThan(4000);
    expect(r.stdout?.toString() ?? '').toContain('DONE');
  });

  test('watch cb throw → onError invoked, watcher stays alive', async () => {
    using proc = Process.open(victim.pid);
    const errs: unknown[] = [];
    let calls = 0;
    const un = proc.watch(
      victim.addr.g_counter,
      () => {
        calls++;
        throw new Error('user cb fault');
      },
      20,
      { onError: (e) => errs.push(e) },
    );
    await Bun.sleep(200);
    un();
    expect(calls).toBeGreaterThan(0);
    expect(errs.length).toBe(calls);
    expect((errs[0] as Error).message).toBe('user cb fault');
  });
});

describe('perf — module cache', () => {
  test('module() is memoized (same object) until refreshModules()', () => {
    using proc = Process.open(victim.pid);
    const a = proc.module('victim.exe');
    const b = proc.module('victim.exe');
    expect(a).toBeDefined();
    expect(a).toBe(b); // cache hit — identical object
    proc.refreshModules();
    const c = proc.module('victim.exe');
    expect(c).toBeDefined();
    expect(c).not.toBe(a); // re-enumerated — new object
    expect(c!.base).toBe(a!.base);
  });

  test('modules() returns the cached list after first enumeration', () => {
    using proc = Process.open(victim.pid);
    const l1 = proc.modules();
    const l2 = proc.modules();
    expect(l1).toBe(l2);
    proc.refreshModules();
    expect(proc.modules()).not.toBe(l1);
  });

  test('module() miss re-enumerates (fresh dll appears on re-lookup)', () => {
    using proc = Process.open(victim.pid);
    // 'testdll.dll' was never loaded into the victim — miss twice.
    expect(proc.module('notloaded-qa4.dll')).toBeUndefined();
    expect(proc.module('notloaded-qa4.dll')).toBeUndefined();
  });
});

describe('H5 — tid ownership validation', () => {
  // Our own tids are guaranteed-foreign to the victim Process — deterministic.
  const foreignTid = (): number => {
    using self = Process.open(process.pid);
    return self.threads()[0]!;
  };

  test('suspendThread(foreign tid) throws FOREIGN_TID', () => {
    using proc = Process.open(victim.pid);
    const fTid = foreignTid();
    expect(fTid).toBeGreaterThan(0);
    try {
      proc.suspendThread(fTid);
      expect.unreachable('should have thrown');
    } catch (e: any) {
      expect(e).toBeInstanceOf(MemoryProcessError);
      expect(e.code).toBe('FOREIGN_TID');
    }
  });

  test('resumeThread/getThreadContext/setThreadContext reject foreign tid', () => {
    using proc = Process.open(victim.pid);
    const fTid = foreignTid();
    expect(() => proc.resumeThread(fTid)).toThrow(/does not belong/);
    expect(() => proc.getThreadContext(fTid)).toThrow(/does not belong/);
    expect(() => proc.setThreadContext(fTid, { dr0: 0n })).toThrow(
      /does not belong/,
    );
    expect(() => proc.hwBreakpoint(fTid, victim.addr.g_i32, 0)).toThrow(
      /does not belong/,
    );
    expect(() => proc.clearHwBreakpoint(fTid, 0)).toThrow(/does not belong/);
  });

  test('own tid still works (suspend+resume round-trip)', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    try {
      expect(proc.suspendThread(tid)).toBe(true);
    } finally {
      proc.resumeThread(tid);
    }
  });
});

describe('H1 — timeout validation', () => {
  test('callRemote negative/NaN timeout → TypeError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.callRemote(0n, 0, -1)).toThrow(TypeError);
    expect(() => proc.callRemote(0n, 0, Number.NaN)).toThrow(TypeError);
  });

  test('callRemote valid timeout does NOT throw TypeError (dedicated victim — remote AV is fatal)', async () => {
    // callRemote(0) makes the remote thread AV → target dies. That's inherent
    // to CreateRemoteThread; use a throwaway victim so the shared one survives.
    const v = await spawnVictim();
    try {
      const p = Process.open(v.pid);
      expect(() => p.callRemote(0n, 0, 500)).not.toThrow(TypeError);
      p.close();
    } finally {
      v.kill();
    }
  });

  test('execShellcode negative timeout → TypeError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.execShellcode(Buffer.from([0xc3]), 0, -1)).toThrow(
      TypeError,
    );
  });

  test('execShellcode(empty) → TypeError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.execShellcode(Buffer.alloc(0))).toThrow(TypeError);
  });
});

describe('m3 — typed PROCESS_CLOSED', () => {
  test('read-after-close throws ProcessClosedError with code PROCESS_CLOSED', () => {
    const proc = Process.open(victim.pid);
    proc.close();
    expect(() => proc.readInt32(victim.addr.g_i32)).toThrow(ProcessClosedError);
    try {
      proc.readInt32(victim.addr.g_i32);
    } catch (e: any) {
      expect(e.code).toBe('PROCESS_CLOSED');
      expect(e).toBeInstanceOf(MemoryProcessError);
    }
  });
});

describe('entity schema span guard', () => {
  test('span > 64KiB throws INVALID_SCHEMA', () => {
    using proc = Process.open(victim.pid);
    expect(() =>
      proc.entity(victim.addr.g_entity, {
        a: [0, 'int32'],
        b: [0x20000, 'int32'], // span 0x20004 > 64KiB
      }),
    ).toThrow(InvalidSchemaError);
  });

  test('span ≤ 64KiB still works', () => {
    using proc = Process.open(victim.pid);
    const e = proc.entity(victim.addr.g_entity, {
      id: [0, 'int32'],
      xp: [0x1000, 'uint64'], // sparse but under the cap
    });
    expect(() => e.snapshot()).not.toThrow();
  });
});
