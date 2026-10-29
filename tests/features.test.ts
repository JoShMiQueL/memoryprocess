import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, Protection } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('memory management', () => {
  test('alloc + write + read + free round-trip', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000);
    expect(addr).toBeGreaterThan(0n);
    proc.writeBuffer(addr, Buffer.from('allocated_mem_test'));
    expect(proc.readString(addr)).toBe('allocated_mem_test');
    expect(proc.free(addr)).toBe(true);
  });

  test('protect changes and restores protection', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    const old = proc.protect(addr, 0x1000, Protection.PAGE_READONLY);
    expect(old).toBe(Protection.PAGE_READWRITE);
    // writing to READONLY should fail
    let failed = false;
    try {
      proc.writeInt32(addr, 1);
    } catch {
      failed = true;
    }
    expect(failed).toBe(true);
    const restored = proc.protect(addr, 0x1000, Protection.PAGE_READWRITE);
    expect(restored).toBe(Protection.PAGE_READONLY);
    proc.writeInt32(addr, 0xabcd);
    expect(proc.readInt32(addr)).toBe(0xabcd);
    proc.free(addr);
  });
});

describe('writeProtected / nop / patchJump', () => {
  test('writeProtected writes into executable region', () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const code = Buffer.from([0xcc, 0xcc, 0xcc]);
    const addr = BigInt(mod.base) + 0x1000n;
    expect(proc.writeProtected(addr, code)).toBe(true);
    const back = proc.readBuffer(addr, 3);
    expect([...back]).toEqual([0xcc, 0xcc, 0xcc]);
  });

  test('nop fills with 0x90', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000);
    proc.writeBuffer(addr, Buffer.from([1, 2, 3, 4, 5]));
    proc.nop(addr, 5);
    expect([...proc.readBuffer(addr, 5)]).toEqual([
      0x90, 0x90, 0x90, 0x90, 0x90,
    ]);
    proc.free(addr);
  });

  test('patchJump emits E9 rel32', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000);
    const target = addr + 0x100n;
    proc.patchJump(addr, target);
    const bytes = proc.readBuffer(addr, 5);
    expect(bytes[0]).toBe(0xe9);
    const rel = bytes.readInt32LE(1);
    expect(BigInt(rel)).toBe(target - (addr + 5n));
    proc.free(addr);
  });
});

describe('wow64 / threads / info', () => {
  test('isWow64 / pointerSize', () => {
    using proc = Process.open(victim.pid);
    expect(typeof proc.isWow64).toBe('boolean');
    expect(proc.pointerSize).toBe(proc.isWow64 ? 4 : 8);
  });

  test('threads() lists own threads', () => {
    using proc = Process.open(victim.pid);
    const t = proc.threads();
    expect(t.length).toBeGreaterThan(0);
  });

  test('suspendAll/resumeAll freeze the process', () => {
    using proc = Process.open(victim.pid);
    const before = proc.readInt32(victim.addr.g_counter);
    const tids = proc.suspendAll();
    expect(tids.length).toBeGreaterThan(0);
    // give it a moment to confirm counter is frozen
    const frozen1 = proc.readInt32(victim.addr.g_counter);
    Bun.sleepSync(80);
    const frozen2 = proc.readInt32(victim.addr.g_counter);
    expect(frozen2).toBe(frozen1);
    proc.resumeAll();
    Bun.sleepSync(120);
    const after = proc.readInt32(victim.addr.g_counter);
    expect(after).toBeGreaterThan(frozen2);
  });
});

describe('rip-relative + readRegion', () => {
  test('resolveRIPRelative computes absolute addr', () => {
    using proc = Process.open(victim.pid);
    // craft in victim: we can't inject instructions easily; verify math on a fake.
    // place a fake "48 8B 05 <rel32>" in alloc'd mem: 48 8B 05 + rel32 -> target
    const buf = proc.alloc(0x1000);
    const target = buf + 0x500n;
    const insn = buf + 0x10n;
    const rel = Number(target - (insn + 7n)); // rip = insn+7 (3-byte opcode + 4-byte rel)
    const code = Buffer.alloc(7);
    code[0] = 0x48;
    code[1] = 0x8b;
    code[2] = 0x05;
    code.writeInt32LE(rel, 3);
    proc.writeBuffer(insn, code);
    const resolved = proc.resolveRIPRelative(insn, 3);
    expect(resolved).toBe(target);
    proc.free(buf);
  });

  test('readRegion gives index-local access', () => {
    using proc = Process.open(victim.pid);
    const view = proc.readRegion(victim.addr.g_i32, 64);
    // g_i32..g_i64..g_u32..g_f32 are laid out contiguously-ish; just verify accessors
    expect(view.size).toBe(64);
    expect(typeof view.int32At(0)).toBe('number');
    expect(typeof view.floatAt(16)).toBe('number');
  });
});
