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

  test("bare module name: addr('victim.exe', rva, ...chain)", () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const rva = Number(victim.addr.g_ppp) - mod.base;
    // 'mod', rva, chain — equivalent to 'mod+rva' + chain
    const a = proc.addr('victim.exe', rva, 0, 0, 0);
    expect(a.resolve()).toBe(victim.addr.g_i32);
    // and the pointers() def form
    const p = proc.pointers({
      i32: ['victim.exe', Number(victim.addr.g_i32) - mod.base],
      chained: ['victim.exe', rva, 0, 0, 0],
    });
    expect(p.i32.readInt32()).toBe(0x12345678);
    expect(p.chained.resolve()).toBe(victim.addr.g_i32);
  });

  describe('addr() validation — descriptive errors, no silent garbage', () => {
    test.each([
      ['victim.exe+', 'empty rva'],
      ['victim.exe+0x', 'empty hex'],
      ['victim.exe+GG', 'bad hex'],
      ['victim.exe+-5', 'signed rva'],
      ['victim.exe+0x10+0x20', 'double +'],
      ['+0x10', 'missing module'],
      ['victim.exe-0x10', 'minus form'],
      ['nosuch.dll+0x10', 'module missing'],
      ['nosuch.dll', 'bare missing module'],
      ['', 'empty string'],
    ])('proc.addr(%j) throws descriptive error (%s)', (expr, _why) => {
      using proc = Process.open(victim.pid);
      try {
        proc.addr(expr);
        expect.unreachable('should have thrown');
      } catch (e: any) {
        expect(e).toBeInstanceOf(Error);
        expect(['INVALID_ADDRESS_EXPR', 'MODULE_NOT_FOUND']).toContain(e.code);
        expect(e.message.length).toBeGreaterThan(10);
      }
    });

    test('bare module + negative rva arg throws', () => {
      using proc = Process.open(victim.pid);
      expect(() => proc.addr('victim.exe', -1)).toThrow(/invalid rva/);
    });

    test("hex-string base still works ('0x...' isn't a module)", () => {
      using proc = Process.open(victim.pid);
      const a = proc.addr(`0x${victim.addr.g_i32.toString(16)}`);
      expect(a.readInt32()).toBe(0x12345678);
    });

    test("'mod+rva' + chain[0] is a DEREF offset, not double-rva (documented)", () => {
      using proc = Process.open(victim.pid);
      const mod = proc.module('victim.exe')!;
      // 'victim.exe+rva(g_ppp)' + [0,0,0] walks g_ppp→g_i32 — the chain
      // offsets are deref hops, they are NOT added to the base again.
      const rva = Number(victim.addr.g_ppp) - mod.base;
      const a = proc.addr(`victim.exe+0x${rva.toString(16)}`, 0, 0, 0);
      expect(a.resolve()).toBe(victim.addr.g_i32);
    });

    describe('ambiguity heuristic — rva repeated as chain[0]', () => {
      test("'mod+rva' + chain[0]==rva throws AMBIGUOUS_ADDRESS_EXPR", () => {
        using proc = Process.open(victim.pid);
        const mod = proc.module('victim.exe')!;
        const rva = Number(victim.addr.g_i32) - mod.base;
        try {
          proc.addr(`victim.exe+0x${rva.toString(16)}`, rva, 0x10);
          expect.unreachable('should throw');
        } catch (e: any) {
          expect(e.code).toBe('AMBIGUOUS_ADDRESS_EXPR');
          expect(e.message).toContain('dereference');
        }
      });

      test('rva==0 does NOT trigger (chain[0]=0 is a normal deref)', () => {
        using proc = Process.open(victim.pid);
        // 'mod+0' embeds rva 0 → heuristic skips; chain[0]=0 derefs base.
        // victim base itself isn't a pointer target we control, so just
        // assert construction doesn't throw (resolve may fail on read).
        expect(() => proc.addr('victim.exe+0', 0)).not.toThrow();
      });

      test('different chain[0] value does NOT trigger', () => {
        using proc = Process.open(victim.pid);
        const mod = proc.module('victim.exe')!;
        const rva = Number(victim.addr.g_ppp) - mod.base;
        // chain[0]=0 ≠ rva → clean construction, correct resolve
        const a = proc.addr(`victim.exe+0x${rva.toString(16)}`, 0, 0, 0);
        expect(a.resolve()).toBe(victim.addr.g_i32);
      });

      test('numeric base bypasses the heuristic entirely', () => {
        using proc = Process.open(victim.pid);
        const mod = proc.module('victim.exe')!;
        const rva = Number(victim.addr.g_ppp) - mod.base;
        // numeric base + chain[0]==rva → legal, no heuristic
        const a = proc.addr(BigInt(mod.base) + BigInt(rva), 0, 0, 0);
        expect(a.resolve()).toBe(victim.addr.g_i32);
      });

      test('pointers() defs get the same validation', () => {
        using proc = Process.open(victim.pid);
        const mod = proc.module('victim.exe')!;
        const rva = Number(victim.addr.g_i32) - mod.base;
        expect(() =>
          proc.pointers({
            bad: [`victim.exe+0x${rva.toString(16)}`, rva],
          }),
        ).toThrow(/AMBIGUOUS|appears twice/);
      });
    });

    describe('canonical form is unambiguous', () => {
      test("['mod', rva, ...chain] ≡ ['mod+rva', ...chain]", () => {
        using proc = Process.open(victim.pid);
        const mod = proc.module('victim.exe')!;
        const rva = Number(victim.addr.g_ppp) - mod.base;
        const canonical = proc.addr('victim.exe', rva, 0, 0, 0).resolve();
        const ceForm = proc
          .addr(`victim.exe+0x${rva.toString(16)}`, 0, 0, 0)
          .resolve();
        const rawForm = proc
          .addr(BigInt(mod.base) + BigInt(rva), 0, 0, 0)
          .resolve();
        expect(canonical).toBe(ceForm);
        expect(canonical).toBe(rawForm);
        expect(canonical).toBe(victim.addr.g_i32);
      });
    });
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

  test('ready() before bind() throws "not bound"', async () => {
    const off = Offsets.load({ 'victim.exe': { x: 0x10 } });
    await expect(off.ready()).rejects.toThrow('not bound');
  });

  test('flat {module, rva} SigEntry resolves', async () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const off = proc.offsets({
      g_i32: {
        module: 'victim.exe',
        rva: Number(victim.addr.g_i32) - mod.base,
      },
    });
    expect(await off.resolve('g_i32')).toBe(victim.addr.g_i32);
  });

  test('flat "mod+rva" string entry resolves', async () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const rva = (Number(victim.addr.g_i32) - mod.base).toString(16);
    const off = proc.offsets({ g_i32: `victim.exe+0x${rva}` });
    expect(await off.resolve('g_i32')).toBe(victim.addr.g_i32);
  });

  test.each([
    ['mod-0x10', 'minus form'],
    ['a+0x1+0x2', 'double +'],
    ['mod+xyz', 'bad rva'],
    ['mod+', 'empty rva'],
  ])('Offsets.load string %j → INVALID_OFFSET_ENTRY (%s)', (s, _w) => {
    try {
      Offsets.load({ x: s });
      expect.unreachable('should throw');
    } catch (e: any) {
      expect(e.code).toBe('INVALID_OFFSET_ENTRY');
      expect(e.message).toContain('x');
    }
  });

  test('reserved-name collision throws at ready(), keeps API intact', async () => {
    using proc = Process.open(victim.pid);
    for (const name of ['resolve', 'proc', 'entries', 'ready', 'netvars']) {
      const off = proc.offsets({
        signatures: { [name]: { module: 'victim.exe', rva: 0x10 } },
      });
      try {
        await off.ready();
        expect.unreachable(`ready() should throw for "${name}"`);
      } catch (e: any) {
        expect(e.code).toBe('RESERVED_OFFSET_NAME');
      }
      expect(typeof off.resolve).toBe('function');
    }
  });

  test('bind() drops stale props bound to the old proc', async () => {
    using proc = Process.open(victim.pid);
    const mod = proc.module('victim.exe')!;
    const off = proc.offsets({
      'victim.exe': { g_i32: Number(victim.addr.g_i32) - mod.base },
    });
    await off.ready();
    // @ts-expect-error populated prop
    expect(off.g_i32).toBeDefined();
    const proc2 = Process.open(victim.pid);
    try {
      off.bind(proc2);
      // @ts-expect-error populated prop was cleared
      expect(off.g_i32).toBeUndefined();
      await off.ready();
      // @ts-expect-error populated prop rebound to proc2
      expect(off.g_i32.readInt32()).toBe(0x12345678);
    } finally {
      proc2.close();
    }
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

  test("entity 'ref' field decodes a pointer (was dead type)", () => {
    using proc = Process.open(victim.pid);
    const e = proc.entity(victim.addr.g_ptr, { p: [0, 'ref'] });
    expect(e.snapshot<{ p: bigint }>().p).toBe(victim.addr.g_i32);
    expect(e.read('p')).toBe(victim.addr.g_i32);
  });

  test.each([
    ['string:0', 'zero width'],
    ['string:x', 'non-numeric width'],
    ['string:-4', 'negative width'],
    ['wstring:0', 'zero wstring width'],
  ])('entity schema %j rejected at compile (%s)', (type, _w) => {
    using proc = Process.open(victim.pid);
    expect(() =>
      proc.entity(victim.addr.g_entity, { s: [0, type as any] }),
    ).toThrow(TypeError);
  });

  test.each([
    [{ stride: 4, max: -1 }, 'negative max'],
    [{ stride: 4, max: 1e9 }, 'max over cap'],
    [{ stride: 4, max: 1.5 }, 'non-integer max'],
    [{ stride: 0 }, 'zero stride'],
    [{ stride: -4 }, 'negative stride'],
  ])('entityList rejects %j (%s)', (opts, _w) => {
    using proc = Process.open(victim.pid);
    expect(() => proc.entityList({ first: 0n, ...opts } as any)).toThrow(
      TypeError,
    );
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
