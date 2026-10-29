/**
 * abuse3 — adversarial fuzz of the HIGH-LEVEL API (hacks.ts):
 *   proc.addr / pointers / entity / entityList / readMany /
 *   findPointersTo / offsets (+ Address/Offsets/Entity/EntityList classes).
 *
 * Rules: every malformed input must either work correctly or throw a
 * clean error — never crash, hang, or return silent garbage.
 * Findings are logged to `FINDINGS` and printed at the end; tests assert
 * only "does not throw" / "is an Error" where behavior is unambiguous.
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, Offsets, Address, Entity, EntityList } from '../src/index.js';
import { spawnVictim, type Victim } from './victim.js';

let victim: Victim;
let proc: Process;
let mod: { base: number; size: number };

/** Observed outcomes — transcribed into .opencode/analysis/qa-fuzz3.md */
const FINDINGS: string[] = [];

function rec(
  name: string,
  observed: string,
  verdict: 'ok' | 'bad' | 'critical',
) {
  FINDINGS.push(`${verdict.toUpperCase().padEnd(8)} | ${name} | ${observed}`);
}

/** Run fn, classify outcome. Returns {threw, err, val}. */
function probe<T>(fn: () => T): { threw: boolean; err?: Error; val?: T } {
  try {
    return { threw: false, val: fn() };
  } catch (e: any) {
    return { threw: true, err: e instanceof Error ? e : new Error(String(e)) };
  }
}

/** Async variant — the fn returns a promise; awaits it. */
async function probeAsync<T>(
  fn: () => Promise<T> | T,
): Promise<{ threw: boolean; err?: Error; val?: T }> {
  try {
    return { threw: false, val: await fn() };
  } catch (e: any) {
    return { threw: true, err: e instanceof Error ? e : new Error(String(e)) };
  }
}

function rva(sym: bigint): number {
  return Number(sym) - mod.base;
}

beforeAll(async () => {
  victim = await spawnVictim();
  proc = Process.open(victim.pid);
  mod = proc.module('victim.exe')! as any;
});

afterAll(() => {
  proc?.close();
  victim?.kill();
  console.log('\n===== abuse3 findings =====\n' + FINDINGS.join('\n'));
});

/* ---------------- proc.addr — expression fuzz ---------------- */

describe('proc.addr expression fuzz', () => {
  const rvaHex = () => `0x${rva(victim.addr.g_i32).toString(16)}`;

  test.each([
    ["' ' (whitespace)", ' ', true],
    ["'+' lone", '+', true],
    ["'-' lone", '-', true],
    ["'mod' (no ext, no such module)", 'mod', true],
    ["'mod+' (module 'mod' missing)", 'mod+', true],
    ["'+0x10' (no module)", '+0x10', true],
    ["'0x' (empty hex)", '0x', true],
    ["'0xGG' (bad hex)", '0xGG', true],
    ["'victim.exe+0x10+' (trailing +)", 'victim.exe+0x10+', true],
    ["'victim' (no extension)", 'victim', true],
    ["'victim+0x10' (no ext + rva)", 'victim+0x10', true],
    ["'victim.exe-0x10' (minus)", 'victim.exe-0x10', true],
  ])('addr(%s) throws', (_n, expr, shouldThrow) => {
    const p = probe(() => proc.addr(expr));
    if (shouldThrow && !p.threw)
      rec(`addr('${expr}')`, `no throw → base=${proc.addr(expr).base}`, 'bad');
    else
      rec(
        `addr('${expr}')`,
        p.threw ? `threw ${p.err!.name}: ${p.err!.message.slice(0, 60)}` : 'ok',
        'ok',
      );
    expect(p.threw).toBe(true);
  });

  test("addr('victim.exe + 0x10') — spaces around '+' (lenient)", () => {
    const p = probe(() => proc.addr('victim.exe + 0x10'));
    if (p.threw)
      rec(
        "addr('victim.exe + 0x10')",
        `threw ${p.err!.message.slice(0, 50)}`,
        'ok',
      );
    else
      rec(
        "addr('victim.exe + 0x10')",
        `accepted → base=0x${p.val!.base.toString(16)} (lenient)`,
        'ok',
      );
    // Either is acceptable; just must not crash.
  });

  test("addr('VICTIM.EXE+rva') — case-insensitive module", () => {
    const a = proc.addr(`VICTIM.EXE+${rvaHex()}`);
    expect(a.resolve()).toBe(victim.addr.g_i32);
    rec("addr('VICTIM.EXE+...')", 'resolved (case-insensitive)', 'ok');
  });

  test("addr('0x10') — bare hex string base", () => {
    const a = proc.addr('0x10');
    expect(a.base).toBe(0x10n);
    rec("addr('0x10')", 'base=0x10 accepted', 'ok');
  });

  test("addr('victim.exe+0xFFFFFFFFFFFFFFFF') — huge rva", () => {
    const a = proc.addr('victim.exe+0xFFFFFFFFFFFFFFFF');
    const q = probe(() => a.resolve());
    const rd = probe(() => a.readInt32());
    rec(
      'addr(huge rva)',
      `resolve=${q.threw ? 'threw' : 'ok'}, read=${rd.threw ? rd.err!.name : 'silent!'}`,
      rd.threw ? 'ok' : 'critical',
    );
    expect(rd.threw).toBe(true);
  });

  test.each([
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-0', -0],
    ['0.5 (non-integer)', 0.5],
  ])('addr(g_ppp, %s) chain element', (label, off) => {
    const p = probe(() => proc.addr(victim.addr.g_ppp, off).resolve());
    if (!p.threw) {
      rec(
        `chain ${label}`,
        `resolved → 0x${(p.val as bigint).toString(16)}`,
        'ok',
      );
    } else {
      rec(
        `chain ${label}`,
        `threw ${p.err!.name}: ${p.err!.message.slice(0, 50)}`,
        'ok',
      );
    }
    // -0 resolves to same value (ok); non-integers must throw (BigInt coercion)
    if (label === '-0') expect(p.threw).toBe(false);
    else expect(p.threw).toBe(true);
  });

  test('chain 2^53 — last offset is added, not dereffed (documented)', () => {
    // With a single chain element there is NO deref — resolve() returns
    // base-deref + offset. Huge offset → huge non-canonical address; reading
    // it fails with ReadError. Not silent garbage: the error surfaces on use.
    const a = proc.addr(victim.addr.g_ppp, 2 ** 53);
    const resolved = a.resolve();
    expect(resolved).toBe(
      proc.readPointer(victim.addr.g_ppp) + BigInt(2 ** 53),
    );
    expect(() => a.readInt32()).toThrow();
    rec('chain 2^53', 'huge addr computed, read → ReadError', 'ok');
  });

  test('chain[0]=-1 (negative last offset) — legal, added to deref', () => {
    // Documented semantics: last offset is ADDED after derefs (CE allows
    // negative offsets). resolve() must not throw; it returns ptr-1.
    const a = proc.addr(victim.addr.g_ppp, -1);
    expect(a.resolve()).toBe(proc.readPointer(victim.addr.g_ppp) - 1n);
    rec('chain -1 last', 'resolved to ptr-1 (documented semantics)', 'ok');
  });

  test("heuristic FP: 'mod+0x100' + chain[0]=256 decimal (same value)", () => {
    // rva=0x100 in string, chain[0]=256 → ambiguous by design
    const p = probe(() => proc.addr('victim.exe+0x100', 256));
    rec(
      "'mod+0x100'+chain 256",
      p.threw ? `threw ${(p.err as any)?.code}` : 'no throw',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('AMBIGUOUS_ADDRESS_EXPR');
  });

  test("heuristic FN: 'mod+0x10' + chain[0]=0x10 but legit deref intent", () => {
    // This is the documented ambiguity — it throws (by design); confirm code.
    const p = probe(() => proc.addr('victim.exe+0x10', 0x10));
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('AMBIGUOUS_ADDRESS_EXPR');
  });

  test('addr on closed proc — numeric base lazy, module base eager', () => {
    const dead = Process.open(victim.pid);
    const aNum = probe(() => dead.addr(victim.addr.g_i32)); // lazy — no read yet
    const aMod = probe(() => dead.addr('victim.exe+0x10')); // module() → assertOpen? actually module() asserts
    dead.close();
    // after close: resolve/read must throw
    const late = probe(() => dead.addr(victim.addr.g_i32).readInt32());
    rec(
      'addr on closed proc',
      `num=${aNum.threw ? 'threw' : 'ok'}, mod=${aMod.threw ? 'threw' : 'ok'}, after-close read=${late.threw ? late.err!.name : 'silent'}`,
      late.threw ? 'ok' : 'critical',
    );
    expect(late.threw).toBe(true);
  });

  test('Address on unmapped base — resolve ok, read throws', () => {
    const a = proc.addr(0xdead0000n);
    expect(a.resolve()).toBe(0xdead0000n); // no chain → no read
    expect(() => a.readInt32()).toThrow();
    rec('unmapped base read', 'ReadError', 'ok');
  });
});

/* ---------------- proc.pointers ---------------- */

describe('proc.pointers fuzz', () => {
  test('empty {} → empty map', () => {
    const p = proc.pointers({});
    expect(Object.keys(p).length).toBe(0);
    rec('pointers({})', 'empty map', 'ok');
  });

  test('def [] (empty array) — clean TypeError naming the def', () => {
    const p = probe(() => proc.pointers({ a: [] as any }));
    rec(
      'pointers({a:[]})',
      p.threw
        ? `threw ${p.err!.name}: ${p.err!.message.slice(0, 50)}`
        : `base=${(p.val as any).a?.base}`,
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
    expect(p.err!.message).toContain('"a"');
  });

  test.each([
    ['number def', { a: 5 }],
    ['null def', { a: null }],
    ['undefined def', { a: undefined }],
  ])('non-array def %s', (_l, defs) => {
    const p = probe(() => proc.pointers(defs as any));
    rec(
      `pointers ${_l}`,
      p.threw ? `threw ${p.err!.name}` : 'no throw',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
  });

  test("string def 'victim.exe+0x10' — TypeError (FIXED: no char iteration)", () => {
    const p = probe(() => proc.pointers({ a: 'victim.exe+0x10' as any }));
    rec(
      'pointers string def',
      p.threw ? `threw ${p.err!.name}` : `created ${typeof p.val}`,
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
  });

  test('extra array elements — every element is a deref hop (documented)', () => {
    // [g_ppp, 0,0,0] → g_i32. A 4th 0 derefs *g_i32's value* as a pointer —
    // garbage result but deterministic semantics, not a crash.
    const a = proc.pointers({ x: [victim.addr.g_ppp, 0, 0, 0, 0] });
    const four = probe(() => a.x.resolve());
    const three = proc.pointers({ x: [victim.addr.g_ppp, 0, 0, 0] });
    expect(three.x.resolve()).toBe(victim.addr.g_i32);
    rec(
      'extra chain elems',
      four.threw
        ? `threw ${four.err!.name}`
        : `extra hop dereffed → 0x${(four.val as bigint).toString(16)}`,
      'ok',
    );
  });

  test('duplicate names — last wins silently', () => {
    const p = proc.pointers({
      a: [victim.addr.g_i32],
      a: [victim.addr.g_u32],
    } as any);
    rec('duplicate keys', 'JS dedupes at object level', 'ok');
    expect(p.a).toBeDefined();
  });
});

/* ---------------- Offsets ---------------- */

describe('Offsets fuzz', () => {
  test.each([
    ['{} empty', '{}'],
    ['[] array', '[]'],
    ['null', 'null'],
    ['{"victim.exe":"notanobject"}', '{"victim.exe":"notanobject"}'],
    ['{"victim.exe":{"x":"notanumber"}}', '{"victim.exe":{"x":"notanumber"}}'],
    ['garbage json', '{not json'],
  ])('Offsets.load(%s)', (_l, json) => {
    const p = probe(() => Offsets.load(json));
    rec(
      `Offsets.load ${json.slice(0, 30)}`,
      p.threw ? `threw ${p.err!.name}` : 'parsed ok',
      'ok',
    );
  });

  test('ready() called twice — idempotent', async () => {
    const off = proc.offsets({
      'victim.exe': { g_i32: rva(victim.addr.g_i32) },
    });
    await off.ready();
    await expect(off.ready()).resolves.toBeDefined();
    rec('ready() twice', 'idempotent', 'ok');
  });

  test('ready() before bind — unbound Offsets', async () => {
    const off = Offsets.load({ 'victim.exe': { x: 0x10 } });
    const p = await probeAsync(() => off.ready());
    // FIXED: ready() now throws instead of silently latching resolved=true
    rec(
      'ready() before bind',
      p.threw ? `threw ${p.err!.name}` : 'resolved silently (no proc)',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err!.message).toContain('not bound');
    // resolved must NOT be latched — bind + ready still works
    off.bind(proc);
    await off.ready();
    expect((off as any).x).toBeDefined();
  });

  test('ready() reserved-name collision — typed error, no clobber', async () => {
    const off = proc.offsets({
      signatures: { resolve: { rva: 0x10, module: 'victim.exe' } },
    });
    const p = await probeAsync(() => off.ready());
    rec(
      'ready() reserved name',
      p.threw ? `threw ${(p.err as any)?.code}` : 'no throw',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('RESERVED_OFFSET_NAME');
    expect(typeof off.resolve).toBe('function');
  });

  test('Offsets.load string classifier — typed errors, not raw TypeError', () => {
    for (const [label, json] of [
      ['minus form', { x: 'mod-0x10' }],
      ['double plus', { x: 'a+0x1+0x2' }],
      ['bad rva', { x: 'mod+xyz' }],
      ['empty rva', { x: 'mod+' }],
    ] as const) {
      const p = probe(() => Offsets.load(json));
      rec(
        `load string ${label}`,
        p.threw ? `threw ${(p.err as any)?.code}` : 'parsed',
        p.threw ? 'ok' : 'bad',
      );
      expect(p.threw).toBe(true);
      expect((p.err as any).code).toBe('INVALID_OFFSET_ENTRY');
    }
    // AOB strings still classify as patterns
    const db = Offsets.load({ sig: '48 8B 05 ? ? ? ?' } as any);
    expect(db.keys()).toContain('sig');
  });

  test('flat {module, rva} entry accepted (was silently dropped)', async () => {
    const off = proc.offsets({
      g_i32: { module: 'victim.exe', rva: rva(victim.addr.g_i32) },
    } as any);
    const a = await off.resolve('g_i32');
    expect(a).toBe(victim.addr.g_i32);
    rec('flat {module,rva}', 'resolved', 'ok');
  });

  test('bind() clears stale populated props', async () => {
    const off = proc.offsets({
      'victim.exe': { g_i32: rva(victim.addr.g_i32) },
    });
    await off.ready();
    const old = (off as any).g_i32;
    expect(old).toBeDefined();
    const other = Process.open(victim.pid);
    try {
      off.bind(other);
      expect((off as any).g_i32).toBeUndefined(); // stale prop dropped
      await off.ready();
      expect((off as any).g_i32.readInt32()).toBe(0x12345678);
    } finally {
      other.close();
    }
    rec('bind() clears stale props', 'ok', 'ok');
  });

  test('resolve() without bind — throws', async () => {
    const off = Offsets.load({ 'victim.exe': { x: 0x10 } });
    await expect(off.resolve('x')).rejects.toThrow('not bound');
    rec('resolve unbound', 'threw not-bound', 'ok');
  });

  test('Offsets.resolve — name not in db', async () => {
    const off = proc.offsets({ 'victim.exe': { x: 0x10 } });
    const p = await probeAsync(() => off.resolve('nosuch'));
    rec(
      'resolve unknown name',
      p.threw ? `threw ${(p.err as any)?.code}` : 'returned',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('UNKNOWN_OFFSET');
  });

  test('entry with BOTH pattern AND rva — pattern wins', async () => {
    const off = proc.offsets({
      signatures: {
        both: {
          module: 'victim.exe',
          pattern: '48 8B 05 AA BB CC 90 90 DE AD BE EF 00 11 22 33',
          rva: 0xdead,
        },
      },
    });
    const a = await off.resolve('both');
    expect(a).toBe(victim.addr.g_pattern); // pattern branch, not base+0xdead
    rec('pattern+rva entry', 'pattern wins', 'ok');
  });

  test('entry with NEITHER pattern nor rva — throws INVALID_OFFSET_ENTRY', async () => {
    const off = proc.offsets({
      signatures: { bad: { module: 'victim.exe' } as any },
    });
    const p = await probeAsync(() => off.resolve('bad'));
    rec(
      'entry no pattern/rva',
      p.threw ? `threw ${(p.err as any)?.code}` : 'returned',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('INVALID_OFFSET_ENTRY');
  });

  test('entry with rva but module missing — throws', async () => {
    const off = proc.offsets({
      signatures: { x: { module: 'nosuch.dll', rva: 0x10 } },
    });
    const p = await probeAsync(() => off.resolve('x'));
    rec(
      'rva + missing module',
      p.threw ? `threw ${(p.err as any)?.code}` : 'returned',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
  });

  test('pattern matching nothing — PATTERN_NOT_FOUND', async () => {
    const off = proc.offsets({
      signatures: {
        nope: {
          module: 'victim.exe',
          pattern: 'AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99',
        },
      },
    });
    await expect(off.resolve('nope')).rejects.toThrow(/not found/i);
    rec('pattern no match', 'PATTERN_NOT_FOUND', 'ok');
  });

  test('pattern matching too much — PATTERN_NOT_UNIQUE', async () => {
    const off = proc.offsets({
      signatures: { many: { module: 'victim.exe', pattern: 'DE AD' } },
    });
    const p = await probeAsync(() => off.resolve('many'));
    rec(
      'pattern multi-match',
      p.threw ? `threw ${(p.err as any)?.code}` : 'returned',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect((p.err as any).code).toBe('PATTERN_NOT_UNIQUE');
  });
});

/* ---------------- Entity ---------------- */

describe('Entity schema fuzz', () => {
  const base = () => victim.addr.g_entity;

  test('negative field offset — size=0, snapshot reads 0 bytes, decode OOB', () => {
    // offset=-4, w=4 → size stays 0 → readBuffer(addr, 0) → empty buf →
    // decodeField(buf, -4) → RangeError (negative offset into empty buffer).
    const p = probe(() => proc.entity(base(), { x: [-4, 'int32'] }).snapshot());
    rec(
      'entity neg offset',
      p.threw ? `threw ${p.err!.name}` : `x=${(p.val as any).x}`,
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
  });

  test('huge offset 0x7FFFFF — readBuffer cap? ReadError?', () => {
    const p = probe(() =>
      proc.entity(base(), { x: [0x7fffff, 'int32'] }).snapshot(),
    );
    rec(
      'entity huge offset',
      p.threw ? `threw ${p.err!.name}` : 'decoded',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true); // readBuffer(size≈8MB+4) — within 512MB cap → RPM fails → ReadError
  });

  test('overlapping fields — allowed (documented?)', () => {
    const e = proc.entity(victim.addr.g_i32, {
      lo: [0, 'int32'],
      same: [0, 'uint32'],
    });
    const s = e.snapshot() as any;
    expect(s.lo).toBe(s.same | 0);
    rec('overlapping fields', 'decoded same bytes', 'ok');
  });

  test('unknown FieldType string → TypeError at schema compile', () => {
    const p = probe(() => proc.entity(base(), { x: [0, 'wat' as any] }));
    rec(
      'unknown field type',
      p.threw ? `threw ${p.err!.name}` : 'created',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
  });

  test('empty schema {} — size=0 readBuffer(0)', () => {
    const p = probe(() => proc.entity(base(), {}).snapshot());
    rec(
      'empty schema',
      p.threw
        ? `threw ${p.err!.name}`
        : `size=0 snapshot=${JSON.stringify(p.val)}`,
      'ok',
    );
  });

  test('snapshot on unmapped addr — ReadError', () => {
    const e = proc.entity(0xdead0000n, { x: [0, 'int32'] });
    expect(() => e.snapshot()).toThrow();
    rec('unmapped snapshot', 'ReadError', 'ok');
  });

  test("ref field — 'ref' decodes a pointer-width value (FIXED)", () => {
    const e = proc.entity(victim.addr.g_ptr, { p: [0, 'ref'] });
    const s = e.snapshot() as any;
    rec("'ref' field type", `p=0x${s.p.toString(16)}`, 'ok');
    expect(s.p).toBe(victim.addr.g_i32);
  });

  test('string:NaN → TypeError at schema compile (FIXED)', () => {
    const p = probe(() =>
      proc.entity(base(), { s: [0, ('string:' + 'x') as any] }),
    );
    rec(
      'string:bad width',
      p.threw ? `threw ${p.err!.name}` : 'compiled',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
  });

  test('string:0 → TypeError at schema compile (FIXED)', () => {
    const p = probe(() => proc.entity(base(), { s: [0, 'string:0' as any] }));
    rec(
      'string:0',
      p.threw ? `threw ${p.err!.name}` : 'compiled',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
  });
});

/* ---------------- EntityList ---------------- */

describe('EntityList fuzz', () => {
  test.each([
    ['stride=0', { first: 0n, stride: 0, max: 5 }],
    ['stride=-4', { first: 0n, stride: -4, max: 3 }],
    ['stride=NaN', { first: 0n, stride: 2.5, max: 3 }],
  ])('%s → TypeError (FIXED)', (_l, opts) => {
    const p = probe(() => proc.entityList(opts as any));
    rec(
      `EntityList ${_l}`,
      p.threw ? `threw ${p.err!.name}` : 'accepted',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
  });

  test('next=self cycle — max cap stops infinite loop', () => {
    // g_ptr points to g_i32. Write g_ptr's own addr into g_i32's low bytes?
    // Simpler: craft node where *node == node → self-loop.
    // g_ppp→g_pp→g_ptr→g_i32. If we make readPointer(X)==X, list loops.
    // Use g_pp slot: write &g_pp into *(&g_pp) → self.
    const pp = victim.addr.g_pp;
    const saved = proc.readPointer(pp);
    proc.writePointer(pp, pp);
    try {
      const list = proc.entityList({ first: pp, next: 0, max: 10 });
      const arr = list.toArray();
      // FIXED: cycle detection stops at the repeated node — a self-loop yields
      // 1 element, not `max` duplicates.
      expect(arr.length).toBe(1);
      expect(arr[0]).toBe(pp);
    } finally {
      proc.writePointer(pp, saved);
    }
    rec(
      'next=self cycle',
      'cycle detected — stops at repeat (no hang, no dupes)',
      'ok',
    );
  });

  test('max=0 → empty list (0 is legal)', () => {
    const list = proc.entityList({
      first: victim.addr.g_array,
      stride: 4,
      max: 0,
    });
    expect(list.toArray().length).toBe(0);
    rec('max=0', 'empty', 'ok');
  });

  test.each([
    ['max=-1', -1],
    ['max=NaN', NaN],
    ['max=1e9 (over cap)', 1e9],
    ['max=0.5', 0.5],
  ])('%s → TypeError (FIXED)', (_l, max) => {
    const p = probe(() =>
      proc.entityList({ first: victim.addr.g_array, stride: 4, max }),
    );
    rec(
      `EntityList ${_l}`,
      p.threw ? `threw ${p.err!.name}` : 'accepted',
      p.threw ? 'ok' : 'bad',
    );
    expect(p.threw).toBe(true);
    expect(p.err).toBeInstanceOf(TypeError);
  });

  test('first=null pointer (linked) — read fails → empty', () => {
    // next!=undefined → linked mode: readPointer(first+next). first=0 → ReadError → iterator catches → empty
    const list = proc.entityList({ first: 0n, next: 0, max: 5 });
    const arr = list.toArray();
    expect(arr.length).toBe(0);
    rec('first=null linked', 'empty (catch swallows)', 'ok');
  });

  test('no stride and no next — constructor throws', () => {
    expect(() => proc.entityList({ first: 0n } as any)).toThrow(/either/);
    rec('no stride/next', 'TypeError', 'ok');
  });
});

/* ---------------- readMany ---------------- */

describe('readMany fuzz', () => {
  test('empty reqs → []', () => {
    expect(proc.readMany([])).toEqual([]);
    rec('readMany []', 'empty', 'ok');
  });

  test('addr=0 → null', () => {
    const [v] = proc.readMany([{ addr: 0n, type: 'int32' }]);
    expect(v).toBeNull();
    rec('readMany addr=0', 'null', 'ok');
  });

  test('uint64 straddling page boundary (real data)', () => {
    // g_array is 64*4=256B; place a straddle: read 8B at last-4 of page? Need a committed next page.
    // Use g_bigbuf (4KB) — read last 8 bytes starting at bigbuf+0xFF8 (within page).
    const addr = victim.addr.g_bigbuf + 0xff8n;
    const [v] = proc.readMany([{ addr, type: 'uint64' }]);
    expect(v).not.toBeNull();
    // true straddle: page boundary between two committed pages
    const q1 = proc.queryAddress(victim.addr.g_bigbuf)! as any;
    if (q1 && q1.state === 0x1000) {
      const straddle = victim.addr.g_bigbuf + 0xffcn; // uint64 → bytes FFC..1003
      const [sv] = proc.readMany([{ addr: straddle, type: 'uint64' }]);
      // next page may or may not be committed; either null or real value, NOT garbage
      rec(
        'readMany straddle',
        sv === null ? 'null (next page unmapped)' : `val=${sv}`,
        'ok',
      );
    }
  });

  test('duplicate addrs — decode each independently', () => {
    const [a, b] = proc.readMany([
      { addr: victim.addr.g_i32, type: 'int32' },
      { addr: victim.addr.g_i32, type: 'int32' },
    ]);
    expect(a).toBe(b);
    rec('readMany dup addrs', 'both decoded', 'ok');
  });

  test('type=pointer on x64 → 8B read (fine here)', () => {
    const [p] = proc.readMany([{ addr: victim.addr.g_ptr, type: 'pointer' }]);
    expect(p).toBe(victim.addr.g_i32);
    rec("readMany 'pointer'", '8B ptr', 'ok');
  });

  test('addr spanning unmapped page → null, not garbage', () => {
    // guard region second page is PAGE_GUARD — queryAddress reports committed? NOACCESS.
    const guardPg = victim.addr.g_guard + 0x1000n;
    const [v] = proc.readMany([{ addr: guardPg, type: 'int32' }]);
    expect(v).toBeNull();
    rec('readMany guard page', 'null', 'ok');
  });
});

/* ---------------- findPointersTo ---------------- */

describe('findPointersTo fuzz', () => {
  test('target=0 — would match every null ptr; scoped to module', async () => {
    const hits = await proc.findPointersTo(0n, { module: 'victim.exe' });
    expect(Array.isArray(hits)).toBe(true);
    rec('findPointersTo(0)', `${hits.length} hits in victim.exe`, 'ok');
  }, 15000);

  test('target in unmapped range → [] (no pointers stored)', async () => {
    const hits = await proc.findPointersTo(0xdead0000n, {
      module: 'victim.exe',
    });
    expect(hits).toEqual([]);
    rec('findPointersTo unmapped', '[]', 'ok');
  });

  test('module does not exist → []', async () => {
    const hits = await proc.findPointersTo(victim.addr.g_i32, {
      module: 'nosuch.dll',
    });
    expect(hits).toEqual([]);
    rec('findPointersTo bad module', '[]', 'ok');
  });
});
