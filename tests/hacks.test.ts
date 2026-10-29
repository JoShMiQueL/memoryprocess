import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, Offsets } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('proc.addr — CE-style mod+rva + chain', () => {
  test('"module+rva" resolves to the right address', () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const rva = Number(victim.addr.g_i32) - mod.base;
    const a = proc.addr(`victim.exe+0x${rva.toString(16)}`);
    expect(a.resolve()).toBe(victim.addr.g_i32);
    expect(a.readInt32()).toBe(proc.readInt32(victim.addr.g_i32));
  });

  test('variadic chain walks like resolvePointer', () => {
    using proc = Process.open(victim.pid);
    // g_ppp -> g_pp -> g_ptr -> g_i32 ; offsets [0,0,0]
    const direct = proc.resolvePointer(victim.addr.g_ppp, [0, 0, 0]);
    const a = proc.addr(victim.addr.g_ppp, 0, 0, 0);
    expect(a.resolve()).toBe(direct);
    expect(a.resolve()).toBe(victim.addr.g_i32);
  });

  test('.add() appends to the chain immutably', () => {
    using proc = Process.open(victim.pid);
    const a0 = proc.addr(victim.addr.g_ppp);
    const a1 = a0.add(0).add(0).add(0);
    expect(a0.chain.length).toBe(0);
    expect(a1.resolve()).toBe(victim.addr.g_i32);
  });

  test('module string for a missing module throws', () => {
    using proc = Process.open(victim.pid);
    expect(() => proc.addr('nosuch.dll+0x10')).toThrow();
  });

  test('proc.pointers — named chain table, lazy + reusable', () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const p = proc.pointers({
      i32: [
        `victim.exe+0x${(Number(victim.addr.g_i32) - mod.base).toString(16)}`,
      ],
      counter: [victim.addr.g_counter],
      viaChain: [victim.addr.g_ppp, 0, 0, 0],
    });
    expect(p.i32.readInt32()).toBe(0x12345678);
    expect(p.counter.readInt32()).toBeGreaterThan(0);
    expect(p.viaChain.resolve()).toBe(victim.addr.g_i32);
    // reusable — same chain read twice hits live memory again
    p.counter.writeInt32(777);
    expect(p.counter.readInt32()).toBe(777);
  });
});

describe('Offsets — cs2-dumper + hazedumper + property access', () => {
  test('cs2-dumper module-keyed rva map → property Address', async () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const rva = Number(victim.addr.g_i32) - mod.base;
    const off = proc.offsets({
      'victim.exe': {
        g_i32: rva,
        g_counter: Number(victim.addr.g_counter) - mod.base,
      },
    });
    await off.ready();
    // @ts-expect-error proxy-populated property
    const a = off.g_i32;
    expect(a.readInt32()).toBe(proc.readInt32(victim.addr.g_i32));
    // @ts-expect-error proxy-populated
    expect(off.g_counter.readInt32()).toBeGreaterThan(0);
  });

  test('hazedumper signatures (AOB) resolve to the pattern addr', async () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const rva = Number(victim.addr.g_pattern) - mod.base;
    const off = proc.offsets({
      signatures: {
        g_pattern: {
          module: 'victim.exe',
          pattern: '48 8B 05 AA BB CC 90 90 DE AD BE EF 00 11 22 33',
          rva: 0,
        },
      },
    });
    const addr = await off.resolve('g_pattern');
    expect(addr).toBe(victim.addr.g_pattern);
  });

  test('Offsets.of binds in one call; netvars expose field offsets', async () => {
    using proc = Process.open(victim.pid);
    const off = Offsets.of(proc, {
      'victim.exe': {
        g_i32: Number(victim.addr.g_i32) - proc.module('victim.exe')!.base,
      },
      netvars: { m_iHealth: 0x24 },
    });
    await off.ready();
    expect(off.netvars.m_iHealth).toBe(0x24);
    // @ts-expect-error proxy
    expect(off.g_i32).toBeDefined();
  });
});

describe('proc.entity / entityList', () => {
  test('entity.snapshot decodes the packed struct', () => {
    using proc = Process.open(victim.pid);
    const e = proc.entity(victim.addr.g_entity, {
      id: [0, 'int32'],
      health: [4, 'float'],
      mana: [8, 'double'],
      name: [16, 'string:32'],
    });
    const s = e.snapshot<{
      id: number;
      health: number;
      mana: number;
      name: string;
    }>();
    expect(s.id).toBe(1337);
    expect(Math.abs(s.health - 87.5)).toBeLessThan(0.01);
    expect(Math.abs(s.mana - 4200.75)).toBeLessThan(0.01);
    expect(s.name).toBe('TestEntity');
  });

  test('entity.read/write a single field', () => {
    using proc = Process.open(victim.pid);
    const e = proc.entity(victim.addr.g_entity, { id: [0, 'int32'] });
    e.write('id', 0xbeef);
    expect(e.read('id')).toBe(0xbeef);
    e.write('id', 1337); // restore
  });

  test('entityList array-stride over g_array yields all 64', () => {
    using proc = Process.open(victim.pid);
    const list = proc.entityList({
      first: victim.addr.g_array,
      stride: 4,
      schema: { v: [0, 'int32'] },
      max: 64,
    });
    const ents = list.toArray();
    expect(ents.length).toBe(64);
    const tenth = ents[10] as any;
    expect(tenth.snapshot().v).toBe(1000);
  });
});

describe('proc.readMany / findPointersTo', () => {
  test('readMany batches scalars correctly', () => {
    using proc = Process.open(victim.pid);
    const [i32, u32, f32] = proc.readMany([
      { addr: victim.addr.g_i32, type: 'int32' },
      { addr: victim.addr.g_u32, type: 'uint32' },
      { addr: victim.addr.g_f32, type: 'float' },
    ]);
    expect(i32).toBe(0x12345678);
    expect(u32).toBe(0xdeadbeef);
    expect(Math.abs((f32 as number) - 3.14159265)).toBeLessThan(0.001);
  });

  test('findPointersTo(g_i32) finds the g_ptr slot', async () => {
    using proc = Process.open(victim.pid);
    const hits = await proc.findPointersTo(victim.addr.g_i32, {
      module: 'victim.exe',
    });
    expect(hits).toContain(victim.addr.g_ptr);
  });
});
