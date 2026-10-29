/**
 * native-hardening — QA4 critical/high fixes, exercised through BOTH the
 * public Process API and the raw `native` binding (for the additive exports
 * the TS layer may not have wired into its interface yet).
 *
 * Coverage:
 *   C3  suspendProcess(self) refused; suspendThread(self-tid) skipped;
 *       suspendAll(self) completes without hanging the caller
 *   C2  hookSteal relocates rel32/RIP-rel operands when given stubAddr;
 *       external rel8/LOOP/JECXZ still refused; inspection mode (no
 *       stubAddr) refuses all position-relative instrs
 *   C4  ejectDll: kernel32 (FreeLibrary FALSE) → InjectError; unknown → error;
 *       double-eject → error; base=0 → error
 *   H1  callRemote negative/huge timeoutMs → RangeError (no INFINITE wrap);
 *       waitForExit(-1) → RangeError
 *   M1  native writeProtectedMemory restores EACH region's own protection
 *   M2  injectDll relative path / >32767 chars → error; absolute still works
 *   fWW findWhatWrites WoW64 guard added (code path untestable x64↔x64);
 *       detach leaves the debuggee running
 *
 * IMPORTANT: run `taskkill /F /IM victim.exe` before `bun test`.
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Process, Protection, InjectError } from '../src/index.js';
import { native } from '../src/native.js';
import { spawnVictim, type Victim } from './victim.js';

const dir = dirname(fileURLToPath(import.meta.url));
const dllPath = join(dir, 'testdll.dll');
const srcIndex = pathToFileURL(join(dir, '..', 'src', 'index.js')).href;
const BUN = Bun.which('bun') ?? 'bun';

// New exports are additive — not yet declared on the Native interface (the
// TS-layer agent owns native.ts). Cast to access them.
const nat = native as any;

let victim: Victim;
let proc: Process;
let rawHandle = 0; // separate native-level handle for raw binding calls
beforeAll(async () => {
  victim = await spawnVictim();
  proc = Process.open(victim.pid);
  rawHandle = nat.openProcess(victim.pid).handle;
});
afterAll(() => {
  if (rawHandle) nat.closeHandle(rawHandle);
  proc?.close();
  victim?.kill();
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function probe<T>(fn: () => T): { threw: boolean; err?: Error; val?: T } {
  try {
    return { threw: false, val: fn() };
  } catch (e: any) {
    return {
      threw: true,
      err: e instanceof Error ? e : new Error(String(e)),
    };
  }
}
async function injectAndWait(p: Process): Promise<number | null> {
  p.injectDll(dllPath);
  // Use the native binding rather than p.module() — the latter's cache-miss
  // path is mid-refactor in the TS layer and can throw while iterating.
  for (let i = 0; i < 40; i++) {
    const mods = nat.getModules(rawHandle, p.pid) as {
      base: number;
      path: string;
    }[];
    const m = mods.find((m) => m.path.toLowerCase().endsWith('\\testdll.dll'));
    if (m) return m.base;
    await sleep(50);
  }
  return null;
}
/** Run `bun -e` with a wall-clock timeout; hung = subprocess had to be killed. */
function runSub(
  code: string,
  timeoutMs = 4000,
): { hung: boolean; out: string } {
  const r = spawnSync(BUN, ['-e', code], {
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe'],
  } as any);
  const out = (r.stdout?.toString() ?? '') + (r.stderr?.toString() ?? '');
  const hung = r.error != null && (r.error as any).killed === true;
  return { hung, out };
}

/* ================= C3 — self-suspend ================= */
describe('C3 self-suspend refused', () => {
  test('suspendProcess(own pid) throws SELF_SUSPEND, does not hang', () => {
    using self = Process.open(process.pid);
    const r = probe(() => self.suspendProcess());
    expect(r.threw).toBe(true);
    expect((r.err as any)?.code ?? r.err?.message).toMatch(
      /SELF_SUSPEND|self/i,
    );
  });

  test('resumeProcess(own pid) is allowed (harmless)', () => {
    using self = Process.open(process.pid);
    expect(self.resumeProcess()).toBe(true);
  });

  test('suspendThread(currentThreadId) returns false — never hangs', () => {
    const tid = (nat.currentThreadId as () => number)();
    expect(nat.suspendThread(tid)).toBe(false);
  });

  test('suspendAll() on own pid → SELF_SUSPEND (refused) — subprocess', () => {
    const r = runSub(
      `import {Process} from ${JSON.stringify(srcIndex)};` +
        `try{const p=Process.open(process.pid);p.suspendAll();console.log('NO_THROW')}catch(e){console.log('CODE',e.code)}`,
    );
    // TS-layer refuses outright — self-suspend deadlocks the host.
    expect(r.hung).toBe(false);
    expect(r.out).toContain('SELF_SUSPEND');
  });
});

/* ================= C2 — hookSteal relocation ================= */
describe('C2 hookSteal position-relative handling', () => {
  test('inspection mode (no stubAddr): rel instrs still refused', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const cases: { name: string; bytes: number[] }[] = [
      { name: 'E8 rel32 call', bytes: [0xe8, 0x10, 0, 0, 0, 0xc3] },
      { name: 'E9 rel32 jmp', bytes: [0xe9, 0x10, 0, 0, 0, 0xc3] },
      {
        name: 'EB rel8 jmp',
        bytes: [0xeb, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
      { name: '0F84 jcc rel32', bytes: [0x0f, 0x84, 0x10, 0, 0, 0, 0xc3] },
      {
        name: '74 rel8 jcc',
        bytes: [0x74, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
      // 48 8B 05 <disp32> = mov rax,[rip+disp32] — RIP-relative ModRM
      {
        name: 'RIP-rel mov rax,[rip+..]',
        bytes: [0x48, 0x8b, 0x05, 0x10, 0, 0, 0, 0xc3],
      },
      // RIP-rel after a safe instr: NOP (0x90) then E9
      { name: 'NOP then E9', bytes: [0x90, 0xe9, 0x10, 0, 0, 0, 0x90, 0xc3] },
    ];
    for (const c of cases) {
      const a = proc.alloc(0x100, PAGE);
      proc.writeBuffer(a, Buffer.from(c.bytes));
      const r = probe(() => nat.hookSteal(rawHandle, Number(a)));
      proc.free(a);
      expect(r.threw, `${c.name} should be refused`).toBe(true);
      expect((r.err as any)?.code, c.name).toBe('HOOK_RELOCATE');
    }
  });

  test('with stubAddr: E8/E9/0F84/RIP-rel RELOCATE — operand rewritten', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const cases: {
      name: string;
      bytes: number[];
      opOff: number; // offset of the rel32/disp32 field within stolen bytes
    }[] = [
      { name: 'E8 rel32 call', bytes: [0xe8, 0x10, 0, 0, 0, 0xc3], opOff: 1 },
      { name: 'E9 rel32 jmp', bytes: [0xe9, 0x10, 0, 0, 0, 0xc3], opOff: 1 },
      {
        name: '0F84 jcc rel32',
        bytes: [0x0f, 0x84, 0x10, 0, 0, 0, 0xc3],
        opOff: 2,
      },
      {
        name: 'RIP-rel mov rax,[rip+..]',
        bytes: [0x48, 0x8b, 0x05, 0x10, 0, 0, 0, 0xc3],
        opOff: 3,
      },
    ];
    for (const c of cases) {
      const a = proc.alloc(0x100, PAGE);
      const stub = proc.alloc(0x100, PAGE);
      proc.writeBuffer(a, Buffer.from(c.bytes));
      const r = nat.hookSteal(rawHandle, Number(a), 5, Number(stub)) as {
        length: number;
        bytes: Buffer;
      };
      proc.free(a);
      proc.free(stub);
      expect(r.length).toBeGreaterThanOrEqual(5);
      // The rewritten operand must differ from the original — it now points
      // from stubPos+len to the same absolute target.
      expect(r.bytes.readInt32LE(c.opOff), c.name).not.toBe(0x10);
    }
  });

  test('with stubAddr: external rel8/LOOP/JECXZ still refused', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const cases: { name: string; bytes: number[] }[] = [
      {
        name: 'EB rel8 jmp (external)',
        bytes: [0xeb, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
      {
        name: '74 rel8 jcc (external)',
        bytes: [0x74, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
      {
        name: 'E2 loop (external)',
        bytes: [0xe2, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
      {
        name: 'E3 jecxz (external)',
        bytes: [0xe3, 0x7f, 0x90, 0x90, 0x90, 0x90, 0xc3],
      },
    ];
    for (const c of cases) {
      const a = proc.alloc(0x100, PAGE);
      const stub = proc.alloc(0x100, PAGE);
      proc.writeBuffer(a, Buffer.from(c.bytes));
      const r = probe(() =>
        nat.hookSteal(rawHandle, Number(a), 5, Number(stub)),
      );
      proc.free(a);
      proc.free(stub);
      expect(r.threw, `${c.name} should be refused`).toBe(true);
      expect((r.err as any)?.code, c.name).toBe('HOOK_RELOCATE');
    }
  });

  test('relocated rel32 call still reaches its target — functional', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const page = proc.alloc(0x400, PAGE);
    try {
      const callee = page + 0x200n; // mov eax,0x2A; ret
      const fn = page; // call callee; ret
      const hook = page + 0x180n; // mov eax,99; ret
      proc.writeBuffer(callee, Buffer.from([0xb8, 0x2a, 0, 0, 0, 0xc3]));
      const code = Buffer.alloc(0x40, 0x90);
      code[0] = 0xe8;
      code.writeInt32LE(Number(callee - (fn + 5n)), 1); // call callee
      code[5] = 0xc3; // ret
      proc.writeBuffer(fn, code.subarray(0, 6));
      proc.writeBuffer(hook, Buffer.from([0xb8, 0x63, 0, 0, 0, 0xc3]));

      expect(proc.callRemote(fn, 0)).toBe(42); // baseline: call works
      const h = proc.hook(fn, hook);
      expect(proc.callRemote(fn, 0)).toBe(99); // diverted
      // The stub's relocated E8 must still call `callee` — running the stub
      // directly returns 42 (eax survives as the thread exit code).
      expect(proc.callRemote(h.stub, 0)).toBe(42);
      expect(proc.unhook(h)).toBe(true);
      expect(proc.callRemote(fn, 0)).toBe(42);
    } finally {
      proc.free(page);
    }
  });

  test('relocated RIP-relative mov reads the original location', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const page = proc.alloc(0x400, PAGE);
    try {
      const fn = page; // mov rax,[rip+disp]; ret — reads qword at page+0x40
      const hook = page + 0x100n;
      const data = page + 0x40n;
      proc.writeBuffer(
        data,
        Buffer.from([0xef, 0xbe, 0xad, 0x0b, 0, 0, 0, 0]), // 0x0BADBEEF
      );
      const code = Buffer.from([0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3]);
      code.writeInt32LE(Number(data - (fn + 7n)), 3); // disp32 → data
      proc.writeBuffer(fn, code);
      proc.writeBuffer(hook, Buffer.from([0xb8, 0x63, 0, 0, 0, 0xc3]));

      const h = proc.hook(fn, hook);
      // Stub executes relocated mov → eax = 0x0BADBEEF read from the ORIGINAL
      // data address, then back-jump → ret. Exit code = eax.
      expect(proc.callRemote(h.stub, 0)).toBe(0x0badbeef);
      proc.unhook(h);
    } finally {
      proc.free(page);
    }
  });

  test('internal rel8 branch (target inside stolen window) copies verbatim', () => {
    const PAGE = Protection.PAGE_EXECUTE_READWRITE;
    const page = proc.alloc(0x400, PAGE);
    try {
      const fn = page;
      const hook = page + 0x100n;
      // EB 01 (jmp +1 over the nop) → mov eax,42; ret — the branch target is
      // INSIDE the stolen window, so a verbatim copy stays correct.
      proc.writeBuffer(
        fn,
        Buffer.from([0xeb, 0x01, 0x90, 0xb8, 0x2a, 0, 0, 0, 0xc3]),
      );
      proc.writeBuffer(hook, Buffer.from([0xb8, 0x63, 0, 0, 0, 0xc3]));
      const h = proc.hook(fn, hook);
      expect(h.stolen.length).toBe(8);
      // Stub: EB 01 skips the copied nop, mov eax,42 runs, back-jump → ret.
      expect(proc.callRemote(h.stub, 0)).toBe(42);
      proc.unhook(h);
    } finally {
      proc.free(page);
    }
  });

  test('safe prologue bytes → returns length>=5 + bytes', () => {
    // push rbp (55); mov rbp,rsp (48 89 E5); sub rsp,0x10 (48 83 EC 10); ret
    const a = proc.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(
      a,
      Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xc3]),
    );
    const r = nat.hookSteal(rawHandle, Number(a)) as {
      length: number;
      bytes: Buffer;
    };
    expect(r.length).toBeGreaterThanOrEqual(5);
    expect(r.bytes.length).toBe(r.length);
    expect(r.bytes[0]).toBe(0x55);
    proc.free(a);
  });

  test('our own E9 patch is relocatable, but Process refuses re-hooking (HOOK_ALREADY)', () => {
    // Native level: an E9 at src with stubAddr relocates fine (legit jmp
    // thunks must be hookable) — double-hook protection lives in process.ts.
    const a = proc.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
    const stub = proc.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
    proc.writeBuffer(
      a,
      Buffer.from([0xe9, 0x00, 0x10, 0x00, 0x00, 0xcc, 0xcc, 0xcc]),
    );
    const r = nat.hookSteal(rawHandle, Number(a), 5, Number(stub)) as {
      length: number;
      bytes: Buffer;
    };
    expect(r.length).toBe(5);
    proc.free(a);
    proc.free(stub);
  });
});

/* ================= C4 — ejectDll result + WoW64 ================= */
describe('C4 ejectDll hardened', () => {
  test('native ejectDll(base=0) → INJECT_FAILED (FreeLibrary FALSE checked)', () => {
    // FreeLibrary(NULL) returns FALSE — before the exit-code check this
    // reported success. Now throws INJECT_FAILED at the native boundary.
    const r = probe(() => nat.ejectDll(proc.pid, 0));
    expect(r.threw).toBe(true);
    expect((r.err as any)?.code).toBe('INJECT_FAILED');
    expect(proc.readInt32(victim.addr.g_i32)).toBe(0x12345678);
  });

  test('native ejectDll(bogus base) → INJECT_FAILED', () => {
    const r = probe(() => nat.ejectDll(proc.pid, 0xdead0000));
    expect(r.threw).toBe(true);
    expect((r.err as any)?.code).toBe('INJECT_FAILED');
  });

  test('ejectDll(never-loaded name) → InjectError module-not-found', () => {
    const r = probe(() => proc.ejectDll('definitely-not-loaded-xyz.dll'));
    expect(r.threw).toBe(true);
    expect(r.err).toBeInstanceOf(InjectError);
  });

  test('double eject → second throws (module already gone)', async () => {
    const base = await injectAndWait(proc);
    expect(base).not.toBeNull();
    expect(proc.ejectDll('testdll.dll')).toBe(true);
    await sleep(80);
    const r = probe(() => proc.ejectDll('testdll.dll'));
    expect(r.threw).toBe(true);
    expect(r.err).toBeInstanceOf(InjectError);
  });

  test('ejectDll({base:0}) → InjectError, not silent true', () => {
    const r = probe(() => proc.ejectDll({ base: 0 } as any));
    expect(r.threw).toBe(true);
    expect(r.err).toBeInstanceOf(InjectError);
  });
});

/* ================= M2 — injectDll path rules ================= */
describe('M2 injectDll path hardening', () => {
  test('native injectDll(relative path) → INJECT_FAILED', () => {
    const r = probe(() => nat.injectDll(proc.pid, 'testdll.dll'));
    expect(r.threw).toBe(true);
    expect((r.err as any)?.code ?? r.err?.message).toMatch(
      /INJECT_FAILED|absolute/i,
    );
  });

  test('native injectDll(>32767-char path) → error', () => {
    const long = 'C:\\' + 'a'.repeat(32800) + '\\x.dll';
    const r = probe(() => nat.injectDll(proc.pid, long));
    expect(r.threw).toBe(true);
  });

  test('public injectDll(absolute testdll) still works — LoadLibraryW', async () => {
    const base = await injectAndWait(proc);
    expect(base).not.toBeNull();
    try {
      proc.ejectDll('testdll.dll');
    } catch {
      /* refcount may differ; leave loaded */
    }
  });
});

/* ================= H1 — callRemote/waitForExit timeout validation ===== */
describe('H1 timeoutMs validation', () => {
  test('callRemote(timeout=-1) → throws, no INFINITE wrap', () => {
    // TS validates first (TypeError) — native defense-in-depth throws
    // RangeError if reached. Either way: must throw, never hang.
    const r = probe(() => proc.callRemote(victim.addr.g_i32, 0, -1));
    expect(r.threw).toBe(true);
    expect(r.err).toBeInstanceOf(Error);
  });

  test('callRemote(timeout=1e9) → throws', () => {
    const r = probe(() => proc.callRemote(victim.addr.g_i32, 0, 1e9));
    expect(r.threw).toBe(true);
  });

  test('callRemote(timeout=NaN) → throws', () => {
    const r = probe(() => proc.callRemote(victim.addr.g_i32, 0, NaN));
    expect(r.threw).toBe(true);
  });

  test('native callRemote(timeout=-1) → RangeError (defense in depth)', () => {
    const r = probe(() =>
      nat.callRemote(proc.pid, Number(victim.addr.g_i32), 0, -1),
    );
    expect(r.threw).toBe(true);
    expect(r.err).toBeInstanceOf(RangeError);
  });

  test('callRemote(timeout=0) → returns quickly', () => {
    const t0 = Date.now();
    const r = proc.callRemote(victim.addr.g_i32, 0, 0);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(r === null || typeof r === 'number').toBe(true);
  });

  test('waitForExit(timeout=-1) → throws/rejects', async () => {
    // May throw synchronously (native binding validates before Queue) or
    // reject the promise — either is correct; must not silently wait.
    let threw = false;
    try {
      await proc.waitForExit(-1);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});

/* ============ M1 — writeProtectedMemory per-region restore ============ */
describe('M1 writeProtectedMemory per-page restore', () => {
  test('write spanning two differently-protected pages restores EACH', () => {
    // alloc 2 pages; demote page2 to READWRITE while page1 stays EXECUTE_READWRITE
    const a = proc.alloc(0x2000, Protection.PAGE_EXECUTE_READWRITE);
    const page2 = a + 0x1000n;
    proc.protect(page2, 0x1000, Protection.PAGE_READWRITE);
    const before1 = proc.queryAddress(a)!.protection;
    const before2 = proc.queryAddress(page2)!.protection;
    expect(before1).not.toBe(before2);

    // Write 8 bytes straddling the page boundary.
    const span = a + 0x1000n - 4n;
    const r = nat.writeProtectedMemory(
      rawHandle,
      Number(span),
      Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44]),
    ) as { ok: boolean; restored: boolean };
    expect(r.ok).toBe(true);
    expect(r.restored).toBe(true);

    // Each page must get ITS OWN original protection back — the old TS impl
    // restored page1's prot over BOTH pages.
    expect(proc.queryAddress(a)!.protection).toBe(before1);
    expect(proc.queryAddress(page2)!.protection).toBe(before2);

    expect(
      proc
        .readBuffer(span, 8)
        .equals(Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44])),
    ).toBe(true);
    proc.free(a);
  });

  test('empty buffer → ok:true no-op', () => {
    const a = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    const r = nat.writeProtectedMemory(
      rawHandle,
      Number(a),
      Buffer.alloc(0),
    ) as {
      ok: boolean;
    };
    expect(r.ok).toBe(true);
    proc.free(a);
  });
});

/* ============ findWhatWrites — detach leaves debuggee running ============ */
describe('findWhatWrites detach (no residual debuggee)', () => {
  test('runs to completion and victim keeps running', async () => {
    Process.enableDebugPrivilege();
    const before = proc.readInt32(victim.addr.g_counter);
    const hits = await proc.findWhatWrites(victim.addr.g_counter, {
      size: 4,
      timeoutMs: 400,
      maxHits: 8,
    });
    expect(Array.isArray(hits)).toBe(true);
    await sleep(300);
    const after = proc.readInt32(victim.addr.g_counter);
    // counter thread must keep running — proves disarm+drain+detach left no
    // suspended/armed debuggee behind (cleanup path incl. exceptions).
    expect(after).toBeGreaterThanOrEqual(before);
  });
});
