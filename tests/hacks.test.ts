import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Hacks, Process, Protection } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;
beforeAll(async () => {
  victim = await spawnVictim();
});
afterAll(() => {
  victim?.kill();
});

describe('Address (fluent chain)', () => {
  test('resolve() with no chain returns base verbatim', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    expect(h.addr(victim.addr.g_i32).resolve()).toBe(victim.addr.g_i32);
  });

  test('g_ppp → g_i32 chain matches proc.resolvePointer', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    // resolvePointer(base,[0x0]) reads *base then +0 → lands on g_pp.
    // g_ppp → *→ g_pp → *→ g_ptr → *→ g_i32: three derefs = chain [0,0,0].
    const expected = proc.resolvePointer(victim.addr.g_ppp, [0, 0, 0]);
    const a = h.addr(victim.addr.g_ppp).add(0).deref().add(0).deref().add(0);
    expect(a.resolve()).toBe(expected);
    expect(a.resolve()).toBe(victim.addr.g_i32);
  });

  test('readInt32() at resolved chain == live value', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const a = h.addr(victim.addr.g_ppp).add(0).deref().add(0).deref().add(0);
    expect(a.readInt32()).toBe(proc.readInt32(victim.addr.g_i32));
  });

  test('readInt32 on a plain addr reads at base, not through it', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    expect(h.addr(victim.addr.g_u32).readUInt32()).toBe(0xdeadbeef);
  });

  test('add() is immutable — original chain untouched', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const a = h.addr(0x1000n);
    const b = a.add(0x10);
    expect(a).not.toBe(b);
    expect(a.chain).toEqual([]);
    expect(b.chain).toEqual([0x10]);
    expect(a.resolve()).toBe(0x1000n);
  });
});

describe('OffsetsDb', () => {
  const json = {
    signatures: {
      g_pattern: {
        module: 'victim.exe',
        // exact bytes of g_pattern[16]
        pattern: '48 8B 05 AA BB CC 90 90 DE AD BE EF 00 11 22 33',
      },
    },
    netvars: {
      static_rva: {
        module: 'victim.exe',
        rva: 0,
      },
    },
  };

  test('load → resolve(name) scans module and returns hit', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const db = h.loadOffsets(JSON.stringify(json));
    const a = await db.resolve('g_pattern');
    expect(a).toBe(victim.addr.g_pattern);
  });

  test('rva-only entry resolves to module base', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const db = h.loadOffsets(json);
    const mod = proc.module('victim.exe')!;
    expect(await db.resolve('static_rva')).toBe(BigInt(mod.base));
  });

  test('resolve caches — second call same result, no rescan', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const db = h.loadOffsets(json);
    const a = await db.resolve('g_pattern');
    const b = await db.resolve('g_pattern');
    expect(b).toBe(a);
  });

  test('resolveAll returns every key', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const db = h.loadOffsets(json);
    const all = await db.resolveAll();
    expect(all.g_pattern).toBe(victim.addr.g_pattern);
    expect(all.static_rva).toBe(BigInt(proc.module('victim.exe')!.base));
  });

  test('offsets() throws before loadOffsets', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    expect(() => h.offsets()).toThrow(/loadOffsets/);
  });
});

describe('Entity', () => {
  const schema = {
    id: [0, 'int32'],
    health: [4, 'float'],
    mana: [8, 'double'],
    name: [16, 'string:32'],
  } as const;

  test('snapshot() decodes every field in one read', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const e = h.entity(victim.addr.g_entity, schema);
    const s = e.snapshot<{
      id: number;
      health: number;
      mana: number;
      name: string;
    }>();
    expect(s.id).toBe(1337);
    expect(s.health).toBeCloseTo(87.5, 5);
    expect(s.mana).toBeCloseTo(4200.75, 6);
    expect(s.name).toBe('TestEntity');
  });

  test('read(field) / write(field) hit live memory', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const e = h.entity(victim.addr.g_entity, schema);
    expect(e.read('id')).toBe(1337);
    const orig = proc.readInt32(victim.addr.g_entity);
    e.write('id', 4242);
    expect(proc.readInt32(victim.addr.g_entity)).toBe(4242);
    e.write('id', orig);
    expect(e.read('name')).toBe('TestEntity');
  });
});

describe('EntityList', () => {
  test('array-stride over g_array yields 64 int32s', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const list = h.entityList({
      first: victim.addr.g_array,
      stride: 4,
      max: 64,
    });
    const addrs = [...list] as bigint[];
    expect(addrs.length).toBe(64);
    for (let i = 0; i < 64; i++)
      expect(proc.readInt32(addrs[i]!)).toBe(i * 100);
  });

  test('linked-list walks g_ppp chain until null', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    // g_ppp is itself the head pointer; next-offset 0 yields *cur each hop.
    // The chain tail (g_i32) is data, not a node — the walk yields one extra
    // hop reading g_i32's value as a pointer, then stops on the ReadError.
    const list = h.entityList({ first: victim.addr.g_ppp, next: 0, max: 8 });
    const addrs = [...list] as bigint[];
    expect(addrs.slice(0, 3)).toEqual([
      victim.addr.g_pp,
      victim.addr.g_ptr,
      victim.addr.g_i32,
    ]);
    expect(addrs.length).toBeGreaterThanOrEqual(3);
    expect(addrs.length).toBeLessThanOrEqual(8);
  });

  test('schema mode yields Entity views', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const schema = { v: [0, 'int32'] } as const;
    const list = h.entityList({
      first: victim.addr.g_array,
      stride: 4,
      max: 3,
      schema,
    });
    const ents = [...list];
    expect((ents[0] as any).read('v')).toBe(0);
    expect((ents[2] as any).read('v')).toBe(200);
  });
});

describe('readMany', () => {
  test('batch-reads i32/u32/f32 across one call', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const [i32, u32, f32] = h.readMany([
      { addr: victim.addr.g_i32, type: 'int32' },
      { addr: victim.addr.g_u32, type: 'uint32' },
      { addr: victim.addr.g_f32, type: 'float' },
    ]);
    expect(u32).toBe(0xdeadbeef);
    expect(f32).toBeCloseTo(3.14159265, 5);
    // g_i32 is mutated by the victim — compare to a direct read, not a literal.
    expect(i32).toBe(proc.readInt32(victim.addr.g_i32));
  });

  test('unreadable addr → null, others still decode', () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const [bad, good] = h.readMany([
      { addr: 0x1n, type: 'int32' },
      { addr: victim.addr.g_u32, type: 'uint32' },
    ]);
    expect(bad).toBeNull();
    expect(good).toBe(0xdeadbeef);
  });
});

describe('findPointersTo', () => {
  test('finds the real g_ptr → g_i32 link', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const hits = await h.findPointersTo(victim.addr.g_i32);
    expect(hits).toContain(victim.addr.g_ptr);
  });

  test('module-scoped pointer scan stays inside victim.exe', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const mod = proc.module('victim.exe')!;
    const hits = await h.findPointersTo(victim.addr.g_i32, {
      module: 'victim.exe',
    });
    expect(hits).toContain(victim.addr.g_ptr);
    for (const p of hits)
      expect(p >= BigInt(mod.base) && p < BigInt(mod.base + mod.size)).toBe(
        true,
      );
  });
});

describe('passthroughs', () => {
  test('scanValue/nextScan/freeze/watch delegate', async () => {
    using proc = Process.open(victim.pid);
    const h = new Hacks(proc);
    const buf = proc.alloc(0x1000, Protection.PAGE_READWRITE);
    try {
      proc.writeInt32(buf, 0x5151_aaaa);
      const hits = await h.scanValue(0x5151_aaaa, { type: 'int32' });
      expect(hits).toContain(buf);
      proc.writeInt32(buf, 0x5151_bbbb);
      const refined = await h.nextScan(hits, 0x5151_bbbb, { type: 'int32' });
      expect(refined).toContain(buf);
      const un = h.freeze(buf, 'int32', 0x9999, 20);
      un();
      const unwatch = h.watch(buf, () => {}, 20);
      unwatch();
    } finally {
      proc.free(buf);
    }
  });
});
