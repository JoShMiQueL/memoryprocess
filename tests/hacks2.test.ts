import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;
beforeAll(async () => {
  // DebugActiveProcess on even our own spawned child needs SeDebugPrivilege
  // in the token on many systems (else win32 5). Best-effort grant.
  Process.enableDebugPrivilege();
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('findWhatWrites', () => {
  test('captures at least one write hit on g_counter with non-zero rip', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.findWhatWrites(victim.addr.g_counter, {
      timeoutMs: 500,
      size: 4,
    });
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const hit = hits[0]!;
    expect(hit.rip).toBeGreaterThan(0n);
    expect(typeof hit.tid).toBe('number');
    expect(victim.pid).toBeGreaterThan(0);
    // threadContext is a full snapshot incl. dr6 with the armed slot bit set
    expect(hit.threadContext.rip).toBeGreaterThan(0n);
    expect(hit.threadContext.dr6 & 0xfn).not.toBe(0n);
  });

  test('rip falls inside a victim module (victim.exe)', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.findWhatWrites(victim.addr.g_counter, {
      timeoutMs: 400,
    });
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const mod = proc.module('victim.exe')!;
    const base = BigInt(mod.base);
    const end = base + BigInt(mod.size);
    // g_counter is written by the main loop inside victim.exe
    expect(hits.some((h) => h.rip >= base && h.rip < end)).toBe(true);
  });

  test('maxHits=1 stops after a single hit', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.findWhatWrites(victim.addr.g_counter, {
      timeoutMs: 2000,
      maxHits: 1,
    });
    expect(hits.length).toBe(1);
  });

  test('address never written returns an empty array', async () => {
    using proc = Process.open(victim.pid);
    // g_bigbuf is written once at startup then never touched again
    const hits = await proc.findWhatWrites(victim.addr.g_bigbuf, {
      timeoutMs: 300,
      size: 8,
    });
    expect(hits).toEqual([]);
  });

  test('victim is still running and not debug-attached afterwards', async () => {
    using proc = Process.open(victim.pid);
    const before = proc.readInt32(victim.addr.g_counter);
    await Bun.sleep(150);
    const after = proc.readInt32(victim.addr.g_counter);
    expect(after).toBeGreaterThan(before); // counter still increments
    // A second attach proves the first detached cleanly (a process can only
    // have ONE debugger — if still attached this would fail or return []).
    const hits = await proc.findWhatWrites(victim.addr.g_counter, {
      timeoutMs: 300,
    });
    expect(hits.length).toBeGreaterThanOrEqual(1);
    // and its threads were fully resumed (no leftover suspend counts)
    const tids = proc.threads();
    expect(tids.length).toBeGreaterThanOrEqual(1);
    for (const tid of tids) {
      const ctx = proc.getThreadContext(tid);
      // all Dr7 local/global enable bits (bits 0..7) must be clear — our
      // write breakpoint was disarmed and originals restored
      expect(ctx!.dr7 & 0xffn).toBe(0n);
    }
  });

  test('hwBreakpoint kind=write sets RW=01 in dr7', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    try {
      proc.suspendAll();
      expect(proc.hwBreakpoint(tid, victim.addr.g_counter, 1, 4, 'write')).toBe(
        true,
      );
      const ctx = proc.getThreadContext(tid);
      expect(ctx!.dr1).toBe(BigInt(victim.addr.g_counter));
      // slot 1: bits 20..23 = RW(01)<<0 | LEN(11)<<2 => 0b1101 = 0xD
      expect((ctx!.dr7 >> 20n) & 0xfn).toBe(0xdn);
      // local enable L1 = bit 2
      expect(ctx!.dr7 & (1n << 2n)).not.toBe(0n);
      expect(proc.clearHwBreakpoint(tid, 1)).toBe(true);
      const ctx2 = proc.getThreadContext(tid);
      expect(ctx2!.dr1).toBe(0n);
    } finally {
      proc.resumeAll();
    }
  });
});
