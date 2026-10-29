import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, ProcessNotFoundError, ReadError } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;

beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('Process', () => {
  test('list() returns processes including the victim', () => {
    const list = Process.list();
    expect(list.length).toBeGreaterThan(0);
    expect(list.some((p) => p.pid === victim.pid)).toBe(true);
  });

  test('find() locates a process by name', () => {
    const found = Process.find('victim');
    expect(found).toBeDefined();
    expect(found!.pid).toBe(victim.pid);
  });

  test('open() by pid returns a working handle', () => {
    using proc = Process.open(victim.pid);
    expect(proc.pid).toBe(victim.pid);
    expect(proc.handle).toBeGreaterThan(0);
  });

  test('open() missing process throws ProcessNotFoundError', () => {
    expect(() => Process.open('definitely-not-a-real-process-xyz.exe')).toThrow(
      ProcessNotFoundError,
    );
  });

  test('readInt32 / readUInt32 / readInt64', () => {
    using proc = Process.open(victim.pid);
    expect(proc.readInt32(victim.addr.g_i32)).toBe(0x12345678);
    expect(proc.readUInt32(victim.addr.g_u32)).toBe(0xdeadbeef);
    expect(proc.readInt64(victim.addr.g_i64)).toBe(0x1122334455667788n);
  });

  test('readFloat / readDouble', () => {
    using proc = Process.open(victim.pid);
    expect(Math.abs(proc.readFloat(victim.addr.g_f32) - Math.PI)).toBeLessThan(
      0.0001,
    );
    expect(Math.abs(proc.readDouble(victim.addr.g_f64) - Math.E)).toBeLessThan(
      0.0000001,
    );
  });

  test('readString', () => {
    using proc = Process.open(victim.pid);
    expect(proc.readString(victim.addr.g_str)).toBe('memoryprocess_v2_victim');
  });

  test('readPointer chains to target', () => {
    using proc = Process.open(victim.pid);
    expect(proc.readPointer(victim.addr.g_ptr)).toBe(victim.addr.g_i32);
  });

  test('readBuffer reads raw bytes', () => {
    using proc = Process.open(victim.pid);
    const buf = proc.readBuffer(victim.addr.g_pattern, 16);
    expect([...buf.slice(0, 4)]).toEqual([0x48, 0x8b, 0x05, 0xaa]);
    expect(buf.length).toBe(16);
  });

  test('write + readback round-trips', () => {
    using proc = Process.open(victim.pid);
    proc.writeInt32(victim.addr.g_i32, 0xcafebabe | 0);
    expect(proc.readInt32(victim.addr.g_i32)).toBe(0xcafebabe | 0);
    proc.writeFloat(victim.addr.g_f32, 1.5);
    expect(Math.abs(proc.readFloat(victim.addr.g_f32) - 1.5)).toBeLessThan(
      0.001,
    );
    proc.writeInt64(victim.addr.g_i64, 0x4142434445464748n);
    expect(proc.readInt64(victim.addr.g_i64)).toBe(0x4142434445464748n);
  });

  test('modules() / module(name)', () => {
    using proc = Process.open(victim.pid);
    const mods = proc.modules();
    expect(mods.length).toBeGreaterThan(0);
    const victimMod = proc.module('victim.exe');
    expect(victimMod).toBeDefined();
    expect(victimMod!.path.toLowerCase()).toContain('victim.exe');
  });

  test('regions() returns committed regions covering known addr', () => {
    using proc = Process.open(victim.pid);
    const regs = proc.regions();
    expect(regs.length).toBeGreaterThan(0);
    expect(
      regs.some(
        (r) =>
          victim.addr.g_i32 >= BigInt(r.baseAddress) &&
          victim.addr.g_i32 < BigInt(r.baseAddress) + BigInt(r.size),
      ),
    ).toBe(true);
  });

  test('scan() finds pattern with wildcards (async)', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.scan('48 8B 05 AA BB CC', {});
    expect(hits.some((h) => h === victim.addr.g_pattern)).toBe(true);
    const wild = await proc.scan('DE AD ?? EF', {});
    expect(wild.some((h) => h === victim.addr.g_pattern + 8n)).toBe(true);
  });

  test('scan() module-scoped', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.scan('4D 5A', { module: 'victim.exe' });
    expect(hits.length).toBeGreaterThan(0);
  });

  test('invalid address read throws ReadError', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.readInt32(0x1)).toThrow(ReadError);
  });

  test('close() makes further reads throw', () => {
    const proc = Process.open(victim.pid);
    proc.close();
    expect(() => proc.readInt32(victim.addr.g_i32)).toThrow();
  });
});
