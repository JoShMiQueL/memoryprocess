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

// x64 byte streams used throughout
const MOV_RAX_RIP = [0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44]; // mov rax,[rip+disp] — 7B
const RET_42 = [0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]; // mov eax,42; ret
const RET_0x1234 = [0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3]; // mov eax,0x1234; ret
const RET_99 = [0xb8, 0x63, 0x00, 0x00, 0x00, 0xc3]; // mov eax,99; ret

describe('disassemble', () => {
  test('decodes instruction lengths for a known byte stream', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const bytes = Buffer.from([
        ...MOV_RAX_RIP, // 7B
        0x90, // nop — 1B
        0x55, // push rbp — 1B
        0x48,
        0x83,
        0xec,
        0x28, // sub rsp,0x28 — 4B
        0xc3, // ret — 1B
      ]);
      proc.writeBuffer(addr, bytes);

      const ins = proc.disassemble(addr, 5);
      expect(ins.length).toBe(5);
      expect(ins.map((i) => i.size)).toEqual([7, 1, 1, 4, 1]);
      expect(BigInt(ins[0]!.address)).toBe(addr);
      expect(BigInt(ins[1]!.address)).toBe(addr + 7n);
      expect(BigInt(ins[2]!.address)).toBe(addr + 8n);
      expect(BigInt(ins[3]!.address)).toBe(addr + 9n);
      expect(BigInt(ins[4]!.address)).toBe(addr + 13n);
      expect(ins[0]!.bytes.length).toBe(7);
      expect(ins[0]!.bytes[0]).toBe(0x48);
    } finally {
      proc.free(addr);
    }
  });
});

describe('patchCall', () => {
  test('writes E8 rel32 with correct displacement', () => {
    using proc = Process.open(victim.pid);
    const src = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const dst = src + 0x80n;
      expect(proc.patchCall(src, dst)).toBe(true);
      const buf = proc.readBuffer(src, 5);
      expect(buf[0]).toBe(0xe8);
      const rel = buf.readInt32LE(1);
      expect(BigInt(src + 5n) + BigInt(rel)).toBe(dst);
    } finally {
      proc.free(src);
    }
  });
});

describe('execShellcode', () => {
  test('mov eax,42; ret → exit code 42', () => {
    using proc = Process.open(victim.pid);
    expect(proc.execShellcode(Buffer.from(RET_42))).toBe(42);
  });

  test('mov eax,0x1234; ret → exit code 0x1234', () => {
    using proc = Process.open(victim.pid);
    expect(proc.execShellcode(Buffer.from(RET_0x1234))).toBe(0x1234);
  });
});

describe('hook / unhook', () => {
  test('round-trip: callRemote runs target → hook diverts → unhook restores', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const f = addr; // "target function": returns 42
      const g = addr + 0x100n; // "hook function": returns 99
      proc.writeBuffer(f, Buffer.from(RET_42));
      proc.writeBuffer(g, Buffer.from(RET_99));

      // baseline
      expect(proc.callRemote(f, 0)).toBe(42);

      const h = proc.hook(f, g);
      expect(h.stolen.length).toBe(5); // first instr is exactly 5B
      expect(BigInt(h.src)).toBe(f);
      expect(BigInt(h.dst)).toBe(g);
      expect(BigInt(h.stub)).not.toBe(0n);

      // diverted
      expect(proc.callRemote(f, 0)).toBe(99);

      expect(proc.unhook(h)).toBe(true);
      // restored
      expect(proc.callRemote(f, 0)).toBe(42);
    } finally {
      proc.free(addr);
    }
  });

  test('steals whole instructions — 10-byte lead instr is not split', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const h2 = addr;
      const g = addr + 0x100n;
      // first instruction is 10 bytes (mov rax,imm64); hook must steal >=10,
      // never 5. (A RIP-relative mov is also fine here — hookSteal now
      // RELOCATES those: see 'relocates RIP-relative' test.)
      const MOV_RAX_IMM64 = [
        0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      ];
      proc.writeBuffer(h2, Buffer.from([...MOV_RAX_IMM64, 0xc3]));
      proc.writeBuffer(g, Buffer.from(RET_99));

      const h = proc.hook(h2, g);
      expect(h.stolen.length).toBe(10);
      expect(proc.unhook(h)).toBe(true);
    } finally {
      proc.free(addr);
    }
  });

  test('rel8 external branch in stolen set → HOOK_RELOCATE (cannot widen)', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const g = addr + 0x100n;
      // EB <rel8> jmp to OUTSIDE the page then ret — rel8 can't be widened to
      // a same-length rewrite from a far stub → still refused (MinHook-level
      // limitation; rel32 + RIP-rel DO relocate now).
      const code = Buffer.from([0xeb, 0x7e, 0x90, 0x90, 0x90, 0x90, 0xc3]);
      proc.writeBuffer(addr, code);
      proc.writeBuffer(g, Buffer.from(RET_99));
      expect(() => proc.hook(addr, g)).toThrow(
        /relocat|position-relative|HOOK/i,
      );
    } finally {
      proc.free(addr);
    }
  });

  test('double-hook refused — same src is tracked per-Process (HOOK_ALREADY)', () => {
    using proc = Process.open(victim.pid);
    const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
    try {
      const f = addr;
      const g = addr + 0x100n;
      proc.writeBuffer(f, Buffer.from(RET_42));
      proc.writeBuffer(g, Buffer.from(RET_99));
      const h = proc.hook(f, g);
      // Second hook on the same src: relocation could steal our own E9
      // correctly, but the unhook ordering is unfixable (restoring h1 would
      // orphan h2's stub) — the Process registry refuses it up front.
      expect(() => proc.hook(f, g)).toThrow(/relocat|position-relative|HOOK/i);
      proc.unhook(h);
      // Re-hooking after unhook is fine again.
      const h2 = proc.hook(f, g);
      proc.unhook(h2);
    } finally {
      proc.free(addr);
    }
  });
});
