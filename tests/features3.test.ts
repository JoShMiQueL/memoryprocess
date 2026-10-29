import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, unlinkSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Process, Protection, ProcessAccess } from '../src/index.js';
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

describe('queryAddress', () => {
  test('committed global: base <= addr < base+size, MEM_COMMIT', () => {
    using proc = Process.open(victim.pid);
    const info = proc.queryAddress(victim.addr.g_i32);
    expect(info).not.toBeNull();
    const base = BigInt(info!.baseAddress);
    const size = BigInt(info!.size);
    const addr = BigInt(victim.addr.g_i32);
    expect(addr).toBeGreaterThanOrEqual(base);
    expect(addr).toBeLessThan(base + size);
    expect(info!.state).toBe(0x1000); // MEM_COMMIT
  });

  test('unmapped address returns null', () => {
    using proc = Process.open(victim.pid);
    expect(proc.queryAddress(0x100000000000n)).toBeNull();
  });
});

describe('getThreadContext / setThreadContext', () => {
  test('suspended thread yields non-zero rip/rsp; setThreadContext writes back', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    try {
      expect(proc.suspendThread(tid)).toBe(true);
      const ctx = proc.getThreadContext(tid);
      expect(ctx).not.toBeNull();
      expect(typeof ctx!.rip).toBe('bigint');
      expect(typeof ctx!.rsp).toBe('bigint');
      expect(ctx!.rip).not.toBe(0n);
      expect(ctx!.rsp).not.toBe(0n);
      expect(proc.setThreadContext(tid, { dr0: 0n })).toBe(true);
    } finally {
      proc.resumeThread(tid);
    }
  });

  test('getThreadContext on foreign tid throws FOREIGN_TID (was: returns null)', () => {
    using proc = Process.open(victim.pid);
    // H5 fix: cross-process tids are rejected, not silently queried.
    expect(() => proc.getThreadContext(0x7ffffffe)).toThrow(
      /FOREIGN_TID|does not belong/,
    );
  });
});

describe('hwBreakpoint / clearHwBreakpoint', () => {
  test('dr0 is set to the target address and cleared back to 0', () => {
    using proc = Process.open(victim.pid);
    const tid = proc.threads()[0]!;
    try {
      proc.suspendAll();
      expect(proc.hwBreakpoint(tid, victim.addr.g_i32, 0)).toBe(true);
      const ctx = proc.getThreadContext(tid);
      expect(ctx!.dr0).toBe(BigInt(victim.addr.g_i32));
      expect(proc.clearHwBreakpoint(tid, 0)).toBe(true);
      const ctx2 = proc.getThreadContext(tid);
      expect(ctx2!.dr0).toBe(0n);
    } finally {
      proc.resumeAll();
    }
  });
});

describe('callRemote / resolveExport', () => {
  test('mp_fortytwo returns 42, mp_echo round-trips its parameter', async () => {
    using proc = Process.open(victim.pid);
    expect(proc.injectDll(dllPath)).toBe(true);
    try {
      // wait for the loader
      let mod: { base: number; size: number; path: string } | undefined;
      for (let i = 0; i < 40 && !mod; i++) {
        mod = proc.module('testdll.dll');
        if (!mod) await Bun.sleep(50);
      }
      expect(mod).toBeDefined();

      const fortytwo = proc.resolveExport('testdll.dll', 'mp_fortytwo');
      expect(fortytwo).not.toBeNull();
      expect(proc.callRemote(fortytwo!, 0)).toBe(42);

      const echo = proc.resolveExport('testdll.dll', 'mp_echo');
      expect(echo).not.toBeNull();
      expect(proc.callRemote(echo!, 0x1234)).toBe(0x1234);
    } finally {
      try {
        proc.ejectDll('testdll.dll');
      } catch {
        /* best effort */
      }
    }
  });

  test('kernel32!LoadLibraryA resolves inside kernel32 module range', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.resolveExport('kernel32.dll', 'LoadLibraryA');
    expect(addr).not.toBeNull();
    const k32 = proc.module('kernel32.dll')!;
    const base = BigInt(k32.base);
    expect(addr! >= base && addr! < base + BigInt(k32.size)).toBe(true);
  });

  test('victim.exe exports resolve to their printed addresses', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.resolveExport('victim.exe', 'g_i32');
    expect(addr).not.toBeNull();
    expect(addr).toBe(BigInt(victim.addr.g_i32));
  });
});

describe('findCodeCave', () => {
  test('returns null or a run of 0x00/0xCC bytes', () => {
    using proc = Process.open(victim.pid);
    const cave = proc.findCodeCave(64);
    if (cave === null) return; // acceptable: no cave found
    expect(typeof cave).toBe('bigint');
    const buf = proc.readBuffer(cave, 64);
    for (const b of buf) expect(b === 0x00 || b === 0xcc).toBe(true);
  });

  test('scoped to victim.exe module', () => {
    using proc = Process.open(victim.pid);
    const cave = proc.findCodeCave(32, { module: 'victim.exe' });
    if (cave === null) return;
    const mod = proc.module('victim.exe')!;
    const base = BigInt(mod.base);
    expect(cave >= base && cave < base + BigInt(mod.size)).toBe(true);
  });
});

describe('writeString / writeWideString / readArray', () => {
  test('writeString round-trips through g_str', () => {
    using proc = Process.open(victim.pid);
    const addr = victim.addr.g_str;
    const original = proc.readString(addr, 64);
    try {
      proc.writeString(addr, 'mp_v2_string_test');
      expect(proc.readString(addr, 64)).toBe('mp_v2_string_test');
    } finally {
      proc.writeString(addr, original);
    }
  });

  test('writeWideString round-trips through g_wstr', () => {
    using proc = Process.open(victim.pid);
    const addr = victim.addr.g_wstr;
    const original = proc.readWideString(addr, 32);
    try {
      proc.writeWideString(addr, 'wide_mp_v2');
      expect(proc.readWideString(addr, 32)).toBe('wide_mp_v2');
    } finally {
      proc.writeWideString(addr, original);
    }
  });

  test('readArray reads g_array[64] int32s (i*100)', () => {
    using proc = Process.open(victim.pid);
    const arr = proc.readArray(victim.addr.g_array, 'int32', 64);
    expect(arr.length).toBe(64);
    expect(arr[10]).toBe(1000);
    expect(arr[63]).toBe(6300);
  });
});

describe('moduleFromAddress / mainThread / dumpModule', () => {
  test('moduleFromAddress maps a global to victim.exe', () => {
    using proc = Process.open(victim.pid);
    const m = proc.moduleFromAddress(victim.addr.g_i32);
    expect(m).not.toBeNull();
    expect(m!.path).toMatch(/victim\.exe$/i);
    expect(proc.moduleFromAddress(0x100000000000n)).toBeNull();
  });

  test('mainThread is a positive tid present in threads()', () => {
    using proc = Process.open(victim.pid);
    const main = proc.mainThread;
    expect(typeof main).toBe('number');
    expect(main).toBeGreaterThan(0);
    expect(proc.threads()).toContain(main);
  });

  test('dumpModule writes an MZ file of roughly module size', () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const out = join(tmpdir(), `mp_dump_${process.pid}_${Date.now()}.bin`);
    try {
      const ret = proc.dumpModule('victim.exe', out);
      expect(existsSync(out)).toBe(true);
      expect(ret).toBe(out);
      const size = statSync(out).size;
      expect(size).toBeGreaterThanOrEqual(Math.floor(mod.size * 0.9));
      const head = readFileSync(out).subarray(0, 2);
      expect(head[0]).toBe(0x4d); // 'M'
      expect(head[1]).toBe(0x5a); // 'Z'
    } finally {
      if (existsSync(out)) unlinkSync(out);
    }
  });
});
