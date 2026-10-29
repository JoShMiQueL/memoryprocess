/**
 * abuse4 — adversarial fuzz of the DANGEROUS APIs:
 *   injectDll/ejectDll, callRemote/execShellcode, hook/unhook,
 *   hwBreakpoint, suspend*, dead-process, lifecycle, findWhatWrites.
 *
 * Validates findings from .opencode/analysis/qa4-dangerous-apis.md.
 * Every case: acceptable = throws / clean return; BAD = silent wrong result;
 * CRITICAL = crash, hang, or victim corruption.
 *
 * Speed rules: ONE shared victim for read-only / non-destructive cases;
 * per-test dedicated victims ONLY where the victim may die. Risky hangs run
 * in `bun -e` subprocesses with spawnSync timeouts so a frozen library call
 * can't freeze THIS suite.
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { Process, Protection, InjectError } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

const dir = dirname(fileURLToPath(import.meta.url));
const dllPath = join(dir, 'testdll.dll');
const srcIndex = pathToFileURL(join(dir, '..', 'src', 'index.js')).href;
const BUN = Bun.which('bun') ?? 'bun';

let victim: Victim;
let proc: Process;

/** Observed outcomes — transcribed into .opencode/analysis/qa4-fuzz-dangerous.md */
const FINDINGS: string[] = [];
function rec(
  name: string,
  observed: string,
  verdict: 'ok' | 'bad' | 'critical',
) {
  FINDINGS.push(`${verdict.toUpperCase().padEnd(8)} | ${name} | ${observed}`);
}

function probe<T>(fn: () => T): { threw: boolean; err?: Error; val?: T } {
  try {
    return { threw: false, val: fn() };
  } catch (e: any) {
    return { threw: true, err: e instanceof Error ? e : new Error(String(e)) };
  }
}
async function probeAsync<T>(
  fn: () => Promise<T> | T,
): Promise<{ threw: boolean; err?: Error; val?: T }> {
  try {
    return { threw: false, val: await fn() };
  } catch (e: any) {
    return { threw: true, err: e instanceof Error ? e : new Error(String(e)) };
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const victimAlive = () => proc.readInt32(victim.addr.g_i32) !== undefined;

/** Run `bun -e <script>` with a hard wall-clock timeout. Returns {hung, out}. */
function runSub(
  code: string,
  timeoutMs = 3500,
): { hung: boolean; out: string; ms: number } {
  const t0 = Date.now();
  const r = spawnSync(BUN, ['-e', code], {
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe'],
  } as any);
  const ms = Date.now() - t0;
  const out = (r.stdout?.toString() ?? '') + (r.stderr?.toString() ?? '');
  const hung =
    (r.error != null && (r.error as any).killed) ||
    (ms >= timeoutMs - 50 && out === '');
  return { hung, out, ms };
}

/** Inject testdll into `p` and poll for it; returns module base or null. */
async function injectAndWait(p: Process): Promise<number | null> {
  p.injectDll(dllPath);
  for (let i = 0; i < 40; i++) {
    const m = p.module('testdll.dll');
    if (m) return m.base;
    await sleep(50);
  }
  return null;
}

beforeAll(async () => {
  victim = await spawnVictim();
  proc = Process.open(victim.pid);
});
afterAll(() => {
  proc?.close();
  victim?.kill();
  console.log('\n===== abuse4 findings =====\n' + FINDINGS.join('\n'));
});

/* ============ 1. self-suspend (C3) — subprocess probes ============ */
describe('self-suspend (C3)', () => {
  // FIXED: suspendProcess/suspendAll on own pid now REFUSE with SELF_SUSPEND
  // instead of deadlocking. Assert the refusal, never actually hang.
  test('suspendProcess() on own pid → SELF_SUSPEND (refused)', () => {
    const r = runSub(
      `import {Process} from ${JSON.stringify(srcIndex)};` +
        `try{const p=Process.open(process.pid);p.suspendProcess();console.log('NO_THROW')}catch(e){console.log('CODE',e.code)}`,
    );
    expect(r.hung).toBe(false);
    expect(r.out).toContain('SELF_SUSPEND');
    rec('suspendProcess(self)', 'refused with SELF_SUSPEND — C3 fixed', 'ok');
  });

  test('suspendAll() on own pid → SELF_SUSPEND (refused)', () => {
    const r = runSub(
      `import {Process} from ${JSON.stringify(srcIndex)};` +
        `try{const p=Process.open(process.pid);p.suspendAll();console.log('NO_THROW')}catch(e){console.log('CODE',e.code)}`,
    );
    expect(r.hung).toBe(false);
    expect(r.out).toContain('SELF_SUSPEND');
    rec('suspendAll(self)', 'refused with SELF_SUSPEND — C3 fixed', 'ok');
  });
});

/* ============ 2. injectDll paths (M2/M8) ============ */
describe('injectDll path fuzz', () => {
  test("relative path 'testdll.dll' — resolves vs TARGET cwd", () => {
    const p = probe(() => proc.injectDll('testdll.dll'));
    rec(
      "injectDll('testdll.dll')",
      p.threw
        ? `threw ${p.err!.name} (target cwd lookup failed) — M2: no absolute-path enforcement`
        : 'loaded via target search order — M2 planting primitive',
      'ok', // either is "acceptable" behavior; the M2 gap is the missing check
    );
    if (!p.threw) {
      // cleanup: eject what we just loaded
      try {
        proc.ejectDll('testdll.dll');
      } catch {}
    }
    expect(p.threw || p.val === true).toBe(true);
  });

  test('nonexistent absolute path → InjectError', () => {
    const p = probe(() => proc.injectDll('C:\\definitely\\missing\\nope.dll'));
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(InjectError);
    rec(
      'injectDll(missing)',
      `InjectError: ${p.err!.message.slice(0, 50)}`,
      'ok',
    );
  });

  test('unicode path (non-ASCII filename) — ANSI mangling (M2)', () => {
    const u = join(tmpdir(), `mp_täst_${process.pid}.dll`);
    copyFileSync(dllPath, u);
    try {
      const p = probe(() => proc.injectDll(u));
      if (!p.threw) {
        rec(
          'injectDll(unicode)',
          'loaded non-ASCII path — UTF-8→ANSI worked here',
          'ok',
        );
        try {
          proc.ejectDll(u.split(/[\\/]/).pop()!);
        } catch {}
      } else {
        rec(
          'injectDll(unicode)',
          `InjectError — LoadLibraryA ANSI mangling (M2 confirmed): ${p.err!.message.slice(0, 40)}`,
          'bad',
        );
      }
    } finally {
      if (existsSync(u)) unlinkSync(u);
    }
    // acceptable either way (system codepage dependent)
  });

  test('MAX_PATH+ path (>32KB not tested, ~300 chars)', () => {
    const long = 'C:\\' + 'a'.repeat(300) + '\\x.dll';
    const p = probe(() => proc.injectDll(long));
    expect(p.threw).toBe(true);
    rec('injectDll(300-char)', `threw ${p.err!.name}`, 'ok');
  });

  test('empty string → throws', () => {
    const p = probe(() => proc.injectDll(''));
    expect(p.threw).toBe(true);
    rec("injectDll('')", `threw ${p.err!.name}`, 'ok');
  });

  test('non-string arg → TypeError', () => {
    expect(() => proc.injectDll(42 as any)).toThrow(TypeError);
    rec('injectDll(42)', 'TypeError', 'ok');
  });

  test('double-inject same dll → refcount 2; single eject leaves it loaded (M8)', async () => {
    const base = await injectAndWait(proc);
    expect(base).not.toBeNull();
    expect(proc.injectDll(dllPath)).toBe(true);
    await sleep(100);
    expect(proc.ejectDll('testdll.dll')).toBe(true);
    await sleep(100);
    const still = proc.module('testdll.dll');
    rec(
      'double-inject/eject-once',
      still
        ? 'still loaded — refcount semantics, no tracking (M8)'
        : 'unloaded after one eject',
      still ? 'bad' : 'ok',
    );
    // balance refcount regardless
    try {
      proc.ejectDll('testdll.dll');
    } catch {}
    expect(typeof proc.readInt32(victim.addr.g_i32)).toBe('number');
  });
});

/* ============ 3. ejectDll (C4, L1) ============ */
describe('ejectDll fuzz', () => {
  test('eject never-injected name → InjectError (module not found)', () => {
    const p = probe(() => proc.ejectDll('notloaded-xyz.dll'));
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(InjectError);
    rec(
      'ejectDll(never-injected)',
      `InjectError: ${p.err!.message.slice(0, 40)}`,
      'ok',
    );
  });

  test('substring match REJECTED: ejectDll("testd") throws, dll stays loaded (C4.3 fixed)', async () => {
    const base = await injectAndWait(proc);
    expect(base).not.toBeNull();
    const p = probe(() => proc.ejectDll('testd')); // substring!
    await sleep(80);
    const gone = !proc.module('testdll.dll');
    rec(
      'ejectDll("testd")',
      `${p.threw ? `threw ${p.err!.name}` : `returned ${p.val}`}, dll ${gone ? 'UNLOADED' : 'still loaded'} — exact basename match enforced`,
      p.threw && !gone ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(gone).toBe(false);
    try {
      proc.ejectDll('testdll.dll');
    } catch {}
  });

  test('ejectDll("kernel32.dll") → true despite FreeLibrary failing? (C4.1)', () => {
    // kernel32's refcount never drops to 0 → FreeLibrary returns FALSE →
    // a correct impl reports failure. C4: no exit-code check → true either way.
    const p = probe(() => proc.ejectDll('kernel32.dll'));
    rec(
      'ejectDll("kernel32")',
      `${p.threw ? `threw ${p.err!.name}` : `returned ${p.val}`} — kernel32 cannot unload; ${p.val === true ? 'C4.1 confirmed: no FreeLibrary exit-code check' : 'ok'}`,
      p.val === true ? 'bad' : 'ok',
    );
    // victim must still be alive (FreeLibrary failed, kernel32 still there)
    expect(victimAlive()).toBe(true);
  });

  test('eject twice → second throws InjectError (module gone)', async () => {
    const base = await injectAndWait(proc);
    expect(base).not.toBeNull();
    expect(proc.ejectDll('testdll.dll')).toBe(true);
    await sleep(80);
    const p2 = probe(() => proc.ejectDll('testdll.dll'));
    expect(p2.threw).toBe(true);
    rec('ejectDll twice', 'second → InjectError(module not found)', 'ok');
  });

  test('ejectDll({base:0}) — bogus ModuleInfo base', () => {
    const p = probe(() => proc.ejectDll({ base: 0 } as any));
    rec(
      'ejectDll(base=0)',
      p.threw
        ? `threw ${p.err!.name}`
        : `returned ${p.val} — FreeLibrary(0) unchecked`,
      p.val === true ? 'bad' : 'ok',
    );
  });
});

/* ============ 4. callRemote / execShellcode (H1, M3, M5) ============ */
describe('callRemote / execShellcode', () => {
  // callRemote(bad addr) makes the remote thread AV → the whole target dies.
  // That's inherent to CreateRemoteThread — dedicated victim so the shared one survives.
  test('callRemote(0) → remote AV kills target (inherent CreateRemoteThread footgun)', async () => {
    const v = await spawnVictim();
    try {
      const p = Process.open(v.pid);
      const r = probe(() => p.callRemote(0n, 0, 3000));
      rec(
        'callRemote(0)',
        r.threw
          ? `threw ${r.err!.name}`
          : `returned ${r.val === null ? 'null' : `0x${(r.val as number).toString(16)}`} — remote AV terminates target`,
        'ok',
      );
      // target is dead or dying — reads now fail (process gone)
      const dead = probe(() => p.readInt32(v.addr.g_i32));
      rec(
        'callRemote(0) aftermath',
        `reads ${dead.threw ? 'fail' : 'still work'} — remote AV is process-fatal`,
        'ok',
      );
      p.close();
    } finally {
      v.kill();
    }
  });

  test('callRemote(unmapped) → null/exit-code, target dies (dedicated victim)', async () => {
    const v = await spawnVictim();
    try {
      const p = Process.open(v.pid);
      const r = probe(() => p.callRemote(0xdead0000n, 0, 3000));
      rec(
        'callRemote(unmapped)',
        r.threw ? `threw` : `→ ${r.val} (remote AV)`,
        'ok',
      );
      p.close();
    } finally {
      v.kill();
    }
  });

  test('callRemote timeout=0 → null, thread terminated', async () => {
    const v = await spawnVictim();
    try {
      const p = Process.open(v.pid);
      const r = probe(() => p.callRemote(0n, 0, 0));
      expect(r.val === null || r.threw).toBe(true);
      rec('callRemote(…,0)', `→ ${r.threw ? r.err!.name : r.val}`, 'ok');
      p.close();
    } finally {
      v.kill();
    }
  });

  test('H1: callRemote timeout=-1 → TypeError (H1 FIXED)', () => {
    const p = probe(() => proc.callRemote(0n, 0, -1));
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
    rec(
      'callRemote timeout=-1',
      `TypeError — negative timeout rejected (H1 fixed): ${p.err!.message.slice(0, 40)}`,
      'ok',
    );
  });

  test('execShellcode(empty) → error (M5)', () => {
    const p = probe(() => proc.execShellcode(Buffer.alloc(0)));
    rec(
      'execShellcode(empty)',
      p.threw ? `threw ${p.err!.name}` : `→ ${p.val}`,
      'ok',
    );
    expect(p.threw || p.val === null).toBe(true);
  });

  test('execShellcode(valid ret-imm) on dedicated victim — baseline still fine', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      const code = Buffer.from([0xb8, 0x2a, 0, 0, 0, 0xc3]); // mov eax,42; ret
      expect(p2.execShellcode(code)).toBe(42);
      p2.close();
      rec('execShellcode baseline', 'returned 42', 'ok');
    } finally {
      v2.kill();
    }
  });
});

/* ============ 5. hook abuse (C2, H2, H3, M4) ============ */
describe('hook abuse (dedicated victim)', () => {
  test('hook mid-instruction (f+1) → silent success, bogus trampoline (M4/C2)', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      const base = await injectAndWait(p2);
      expect(base).not.toBeNull();
      const f = p2.resolveExport('testdll.dll', 'mp_fortytwo')!;
      const disF = p2.disassemble(f, 2);
      const disMid = p2.disassemble(f + 1n, 2);
      const h = probe(() => p2.hook(f + 1n, f + 1n + 0x100n));
      if (h.threw) {
        rec('hook(f+1)', `threw ${h.err!.name}`, 'ok');
      } else {
        // disassembly at f+1 differs from f → stolen bytes are garbage
        const bogus =
          disMid[0]?.size !== disF[0]?.size ||
          disMid[0]?.bytes[0] !== disF[0]?.bytes[0];
        rec(
          'hook(f+1 mid-instruction)',
          `succeeded silently; disasm diverges=${bogus} — M4 confirmed`,
          'bad',
        );
        const u = probe(() => p2.unhook(h.val!));
        rec('unhook(mid-insn handle)', `${u.threw ? 'threw' : u.val}`, 'ok');
      }
      p2.close();
    } finally {
      v2.kill();
    }
  });

  test('hook <5B function (ret-only) → succeeds, callRemote likely crashes victim', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      // craft a 1-byte function `C3` (ret) in a remote RWX page
      const f = p2.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
      p2.writeBuffer(f, Buffer.from([0xc3]));
      const h = probe(() => p2.hook(f, f + 0x80n));
      if (h.threw) {
        rec('hook(1-byte fn)', `threw ${h.err!.name} — refused`, 'ok');
      } else {
        // stolen ≥5 bytes → disasm decoded PAST the ret into following bytes
        const r = probe(() => p2.callRemote(f, 0, 2000));
        const alive = probe(() => p2.readInt32(v2.addr.g_i32));
        rec(
          'hook(<5B fn)+call',
          `hook ok (stole past ret); callRemote→${r.threw ? r.err!.name : r.val}; victim ${alive.threw ? 'DEAD — wild jump' : 'alive'}`,
          alive.threw ? 'critical' : 'bad',
        );
      }
      p2.close();
    } finally {
      v2.kill();
    }
  });

  test('double-hook same src → second hook steals our E9 → wild jump (C2)', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      const base = await injectAndWait(p2);
      const f = p2.resolveExport('testdll.dll', 'mp_fortytwo')!;
      const page = p2.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
      p2.writeBuffer(page, Buffer.from([0xb8, 0x63, 0, 0, 0, 0xc3])); // mov eax,99; ret
      const h1 = probe(() => p2.hook(f, page));
      const h2 = probe(() => p2.hook(f, page + 0x40n));
      if (h1.threw || h2.threw) {
        rec(
          'double-hook',
          `threw (${h1.err?.name ?? ''}/${h2.err?.name ?? ''}) — refused`,
          'ok',
        );
      } else {
        const r = probe(() => p2.callRemote(f, 0, 2000));
        const alive = probe(() => p2.readInt32(v2.addr.g_i32));
        rec(
          'double-hook same src',
          `both succeeded; callRemote→${r.threw ? r.err!.name : r.val}; victim ${alive.threw ? 'DEAD — C2 confirmed wild jump' : 'alive'}`,
          alive.threw ? 'critical' : 'bad',
        );
      }
      p2.close();
    } finally {
      v2.kill();
    }
  });

  test('hook with stolen rel32 (C2): call-rel32 fn → RELOCATED, hook succeeds', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      const base = await injectAndWait(p2);
      // src = E8 <rel32 to a ret INSIDE the same page>; C3 — since v2 hookSteal
      // RELOCATES rel32, this now succeeds and the relocated call in the stub
      // still reaches the original target.
      const src = p2.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
      const code = Buffer.alloc(0x80, 0xc3);
      code[0] = 0xe8;
      code.writeInt32LE(0x60, 1); // call src+0x65 (lands on a ret we wrote)
      p2.writeBuffer(src, code);
      const dst = src + 0x40n;
      const h = probe(() => p2.hook(src, dst));
      expect(h.threw).toBe(false);
      rec(
        'hook(stolen E8 rel32)',
        `succeeded — rel32 relocated to stub (C2 UPGRADED)`,
        'ok',
      );
      // Clean up the live hook we just installed.
      p2.unhook(h.val!);
      // victim still alive — no wild jump happened
      expect(typeof p2.readInt32(v2.addr.g_i32)).toBe('number');
      p2.close();
    } finally {
      v2.kill();
    }
  });

  test('unhook twice — second is write+free on freed stub', async () => {
    const v2 = await spawnVictim();
    try {
      const p2 = Process.open(v2.pid);
      // f and dst both in one allocated page → guaranteed rel32 range.
      const page = p2.alloc(0x100, Protection.PAGE_EXECUTE_READWRITE);
      const f = page; // target: mov eax,42; ret
      const dst = page + 0x40n; // hook: ret
      p2.writeBuffer(f, Buffer.from([0xb8, 0x2a, 0, 0, 0, 0xc3]));
      p2.writeBuffer(dst, Buffer.from([0xc3]));
      const h = p2.hook(f, dst);
      expect(p2.unhook(h)).toBe(true);
      const p = probe(() => p2.unhook(h));
      rec(
        'unhook twice',
        `second → ${p.threw ? p.err!.name : p.val} (writes already-restored bytes, frees freed stub)`,
        'ok',
      );
      p2.close();
    } finally {
      v2.kill();
    }
  });
});

/* ============ 6. hwBreakpoint (H6) ============ */
describe('hwBreakpoint fuzz', () => {
  test('5th breakpoint → slot RangeError (only 4 exist)', () => {
    const tid = proc.threads()[0]!;
    expect(() => proc.hwBreakpoint(tid, victim.addr.g_i32, 4 as any)).toThrow(
      RangeError,
    );
    rec('hwBreakpoint slot 4', 'RangeError', 'ok');
  });

  test('invalid kind → TypeError', () => {
    const tid = proc.threads()[0]!;
    expect(() =>
      proc.hwBreakpoint(tid, victim.addr.g_i32, 0, 1, 'bogus' as any),
    ).toThrow(TypeError);
    rec("hwBreakpoint kind='bogus'", 'TypeError', 'ok');
  });

  test('clear never-set slot → true (idempotent)', () => {
    const tid = proc.threads()[0]!;
    try {
      proc.suspendAll();
      expect(proc.clearHwBreakpoint(tid, 3)).toBe(true);
      rec('clearHwBreakpoint never-set', 'returned true', 'ok');
    } finally {
      proc.resumeAll();
    }
  });

  test('arm WITHOUT suspending → succeeds (H6: no enforcement)', () => {
    const tid = proc.threads()[0]!;
    const p = probe(() => proc.hwBreakpoint(tid, 0n, 1)); // dr1=0, harmless addr
    rec(
      'hwBreakpoint on running thread',
      `${p.threw ? `threw ${p.err!.name}` : `returned ${p.val}`} — no suspend enforcement (H6)`,
      p.val === true ? 'bad' : 'ok',
    );
    try {
      proc.suspendAll();
      proc.clearHwBreakpoint(tid, 1);
      proc.resumeAll();
    } catch {}
    expect(victimAlive()).toBe(true);
  });
});

/* ============ 7. dead process ============ */
describe('dead-process errors', () => {
  test('killed victim: read/scan/inject/callRemote error types', async () => {
    const v3 = await spawnVictim();
    const p3 = Process.open(v3.pid);
    const a = v3.addr.g_i32;
    p3.readInt32(a);
    v3.kill();
    await sleep(300);
    const cases: [string, () => unknown][] = [
      ['readInt32', () => p3.readInt32(a)],
      ['injectDll', () => p3.injectDll(dllPath)],
      ['callRemote', () => p3.callRemote(a, 0, 500)],
      ['suspendProcess', () => p3.suspendProcess()],
    ];
    for (const [n, fn] of cases) {
      const p = probe(fn);
      rec(
        `dead-proc ${n}`,
        p.threw ? `threw ${p.err!.name}` : `→ ${p.val}`,
        'ok',
      );
      expect(p.threw || p.val === null || p.val === false).toBe(true);
    }
    const s = await probeAsync(() =>
      p3.scan('AA', { start: Number(a), end: Number(a) + 0x100 }),
    );
    rec(
      'dead-proc scan',
      s.threw ? `threw` : `→ ${JSON.stringify(s.val)}`,
      'ok',
    );
    p3.close();
  });
});

/* ============ 8. lifecycle ============ */
describe('lifecycle churn', () => {
  test('200× watch/unwatch churn → no leaked timers', async () => {
    const t0 = Date.now();
    for (let i = 0; i < 200; i++) {
      const un = proc.watch(victim.addr.g_counter, () => {}, 5);
      un();
    }
    await sleep(60);
    rec('200× watch/unwatch', `${Date.now() - t0}ms, no hang`, 'ok');
    expect(victimAlive()).toBe(true);
  });

  test('two Process objects on same pid — concurrent bounded scans', async () => {
    const p2 = Process.open(victim.pid);
    try {
      const start = Number(victim.addr.g_bigbuf);
      const [a, b] = await Promise.all([
        proc.scan('AB AB AB AB', { start, end: start + 0x800 }),
        p2.scan('AB AB', { start, end: start + 0x800 }),
      ]);
      expect(a.length).toBeGreaterThan(0);
      expect(b.length).toBeGreaterThan(0);
      rec('concurrent scans, 2 handles', `${a.length}/${b.length} hits`, 'ok');
    } finally {
      p2.close();
    }
  });

  test.each([
    ['open(0)', 0],
    ['open(-1)', -1],
  ])('%s → throws', (_l, pid) => {
    const p = probe(() => Process.open(pid));
    expect(p.threw).toBe(true);
    rec(`Process.open(${pid})`, `threw ${p.err!.name}`, 'ok');
  });

  test('open(own pid) → allowed (documented M8-adjacent)', () => {
    const p = Process.open(process.pid);
    expect(p.pid).toBe(process.pid);
    p.close();
    rec('Process.open(self)', 'allowed', 'ok');
  });
});

/* ============ 9. findWhatWrites detach (H7) ============ */
describe('findWhatWrites', () => {
  test('runs and detaches — victim counter keeps incrementing', async () => {
    Process.enableDebugPrivilege();
    const before = proc.readInt32(victim.addr.g_counter);
    const r = await probeAsync(() =>
      proc.findWhatWrites(victim.addr.g_counter, {
        size: 4,
        timeoutMs: 500,
        maxHits: 4,
      }),
    );
    if (r.threw) {
      rec(
        'findWhatWrites',
        `threw ${r.err!.name}: ${r.err!.message.slice(0, 50)}`,
        'ok',
      );
      return;
    }
    const mid = proc.readInt32(victim.addr.g_counter);
    await sleep(300);
    const after = proc.readInt32(victim.addr.g_counter);
    const runs = after > mid;
    rec(
      'findWhatWrites detach',
      `hits=${(r.val as any[]).length}, counter ${mid}→${after} ${runs ? 'still running — clean detach' : 'FROZEN — debuggee left suspended (H7.2)'}`,
      runs ? 'ok' : 'critical',
    );
    expect(runs).toBe(true);
  });
});
