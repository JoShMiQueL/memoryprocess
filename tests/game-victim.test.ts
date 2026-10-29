// End-to-end audit of the cheat-dev layer against a simulated game engine
// (tests/gamevictim.exe): polymorphic heap entities, a ticking sim thread,
// orbiting camera view matrix, PAGE_GUARD region. All assertions are
// predicate/liveness-based — the sim mutates everything continuously.
//
// Chain semantics (resolvePointer / proc.addr): `base` is DEREFERENCED
// first, then every offset except the last is a deref hop; the last offset
// is ADDED. So `proc.addr(&g_engine, 0x18, 0x20, 0, 0)` ≡
//   readPtr(&g_engine) → eng; readPtr(eng+0x18) → world;
//   readPtr(world+0x20) → el; readPtr(el+0x00) → array; +0.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Process, Offsets } from '../src/index.js';
import type { EntitySchema } from '../src/index.js';
import { spawnGameVictim, type GameVictim } from './gamevictim.js';

let gv: GameVictim;
beforeAll(async () => {
  gv = await spawnGameVictim();
});
afterAll(() => {
  gv?.kill();
});

/* Offsets mirrored from gamevictim.c's documented layout. */
const O = {
  world: 0x18,
  net: 0x30,
  entities: 0x20,
  localPlayer: 0x28,
  viewMatrix: 0x40,
  elArray: 0x00,
  elCount: 0x08,
  health: 0x38,
  maxHealth: 0x3c,
  id: 0x08,
  name: 0x0c,
  pos: 0x2c,
  flags: 0x44,
  vtable: 0x00,
  displayName: 0x50,
  inv: 0x90,
  invMoney: 0x40,
  subType: 0x98,
} as const;

const ENTITY_SCHEMA: EntitySchema = {
  id: [O.id, 'int32'],
  name: [O.name, 'string:32'],
  pos: [O.pos, 'vec3'],
  health: [O.health, 'float'],
  maxHealth: [O.maxHealth, 'float'],
  team: [0x40, 'int32'],
  flags: [O.flags, 'uint64'],
  displayName: [O.displayName, 'wstring:32'],
};

const GE = () => gv.addr.g_engine; // &g_engine — static global, chain anchor

/** Resolve the EntityList struct, ptr-array base + live count. */
function entityListAddr(proc: Process): {
  el: bigint;
  first: bigint;
  count: number;
} {
  const el = proc.resolvePointer(GE(), [O.world, O.entities, 0]);
  return {
    el,
    first: proc.readPointer(el + BigInt(O.elArray)),
    count: proc.readInt32(el + BigInt(O.elCount)),
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('gamevictim — engine root & deep pointer chains', () => {
  test("proc.addr('gamevictim.exe', rva) reaches the engine singleton", () => {
    using proc = Process.open(gv.pid);
    const mod = proc.module('gamevictim.exe')!;
    const rva = Number(gv.addr.g_engine) - mod.base;
    // 'mod', rva → &g_engine; chain [0] → *g_engine (the heap object)
    const a = proc.addr('gamevictim.exe', rva, 0);
    expect(a.resolve()).toBe(gv.addr.g_engineObj);
  });

  test('g_engine → world → entities → array (4-hop chain)', () => {
    using proc = Process.open(gv.pid);
    const arr = proc.addr(GE(), O.world, O.entities, O.elArray, 0);
    expect(arr.resolve()).toBe(gv.addr.g_entArray);
    const el = proc.addr(GE(), O.world, O.entities, 0).resolve();
    expect(el).toBe(gv.addr.g_entities);
    const cnt = proc.readInt32(el + BigInt(O.elCount));
    expect(cnt).toBeGreaterThanOrEqual(4);
    expect(cnt).toBeLessThanOrEqual(16);
  });

  test('g_engine → net → tickRate / serverName', () => {
    using proc = Process.open(gv.pid);
    expect(proc.addr(GE(), O.net, 0).resolve()).toBe(gv.addr.g_net);
    expect(proc.readInt32(gv.addr.g_net)).toBe(20);
    const srv = proc.addr(GE(), O.net, 0x08);
    expect(srv.readString(32)).toBe('mpv2-sim-01');
  });
});

describe('gamevictim — live entity list (polymorphic, churning)', () => {
  test('entityList over the ptr array yields live Entity snapshots', () => {
    using proc = Process.open(gv.pid);
    const { first, count } = entityListAddr(proc);
    expect(count).toBeGreaterThanOrEqual(4);
    const seen: string[] = [];
    for (const slotAddr of proc.entityList({
      first,
      stride: 8,
      max: count,
    }) as Iterable<bigint>) {
      const ent = proc.readPointer(slotAddr);
      expect(ent).not.toBe(0n);
      const e = proc.entity(ent, ENTITY_SCHEMA);
      const s = e.snapshot<{
        id: number;
        name: string;
        health: number;
        maxHealth: number;
        flags: bigint;
        displayName: string;
        pos: { x: number; y: number; z: number };
      }>();
      // Mid-churn race: slots are filled from a live heap — a snapshot can
      // catch a partially-constructed or just-freed entity (id=0, empty
      // name, garbage flags). Anything not fully sane is skipped; the
      // count is asserted below over the fully-formed set.
      const fullyFormed =
        s.id > 0 &&
        /^(Player|NPC|Item|Projectile|Vehicle|Prop|Drone|Turret|LocalPlayer)_/.test(
          s.name,
        ) &&
        s.health > 0 &&
        s.health <= s.maxHealth + 0.001 &&
        s.displayName === s.name;
      if (!fullyFormed) continue;
      expect(Number.isFinite(s.pos.x)).toBe(true);
      expect(Number.isFinite(s.pos.z)).toBe(true);
      seen.push(s.name);
    }
    expect(seen.length).toBeGreaterThanOrEqual(4);
    expect(seen.length).toBeLessThanOrEqual(count);
    expect(seen.some((n) => n.startsWith('LocalPlayer'))).toBe(true);
  });

  test('entity.read/write a single field on a heap entity', () => {
    using proc = Process.open(gv.pid);
    const { first } = entityListAddr(proc);
    const ent0 = proc.readPointer(first);
    const e = proc.entity(ent0, {
      health: [O.health, 'float'],
      id: [O.id, 'int32'],
    });
    expect(e.read('id')).toBeGreaterThan(0);
    const before = e.read('health') as number;
    expect(before).toBeGreaterThan(0);
    e.write('health', 42.0);
    expect(Math.abs((e.read('health') as number) - 42.0)).toBeLessThan(0.5);
  });

  test('localPlayer: world+0x28 → entity with inv → money (2nd-level deref)', () => {
    using proc = Process.open(gv.pid);
    const lp = proc.addr(GE(), O.world, O.localPlayer, 0);
    expect(lp.resolve()).toBe(gv.addr.g_localPlayer);
    const lpEnt = proc.entity(gv.addr.g_localPlayer, {
      name: [O.name, 'string:32'],
      inv: [O.inv, 'ref'],
      subType: [O.subType, 'int32'],
    });
    const snap = lpEnt.snapshot<{
      name: string;
      inv: bigint;
      subType: number;
    }>();
    expect(snap.name).toMatch(/^LocalPlayer_/);
    expect(snap.subType).toBe(0xa00); // kind 0 = Player subclass
    expect(snap.inv).not.toBe(0n);
    const money = proc.readFloat(snap.inv + BigInt(O.invMoney));
    expect(money).toBeGreaterThan(0);
    expect(money).toBeLessThan(2000);
  });

  test('subclass discrimination: distinct sub-blob type ids in the list', () => {
    using proc = Process.open(gv.pid);
    const { first, count } = entityListAddr(proc);
    const kinds = new Set<number>();
    for (const slotAddr of proc.entityList({
      first,
      stride: 8,
      max: count,
    }) as Iterable<bigint>) {
      kinds.add(proc.readInt32(proc.readPointer(slotAddr) + BigInt(O.subType)));
    }
    expect(kinds.size).toBeGreaterThanOrEqual(2);
    for (const k of kinds) expect(k).toBeGreaterThanOrEqual(0xa00);
  });
});

describe('gamevictim — viewMatrix (orbiting camera)', () => {
  test('16 floats resolve via chain and CHANGE between reads', async () => {
    using proc = Process.open(gv.pid);
    const vm = proc.addr(GE(), O.world, O.viewMatrix);
    expect(vm.resolve()).toBe(gv.addr.g_viewMatrix);
    const r1 = vm.readBuffer(64);
    await sleep(300);
    const r2 = vm.readBuffer(64);
    expect(r1.length).toBe(64);
    expect(r1.equals(r2)).toBe(false); // camera orbits every 50ms tick
    expect(r1.readFloatLE(60)).toBe(1.0); // m[15]
    expect(r2.readFloatLE(60)).toBe(1.0);
    for (let i = 0; i < 15; i++)
      expect(Number.isFinite(r2.readFloatLE(i * 4))).toBe(true);
  });
});

describe('gamevictim — findPointersTo / Offsets', () => {
  test('findPointersTo(localPlayer) finds its entity-list slot + world field', async () => {
    using proc = Process.open(gv.pid);
    const { first, count } = entityListAddr(proc);
    expect(count).toBeGreaterThanOrEqual(4);
    // localPlayer is never killed by the sim → stable scan target
    const hits = await proc.findPointersTo(gv.addr.g_localPlayer);
    const inList = hits.filter(
      (h) => h >= first && h < first + 8n * 64n && (h - first) % 8n === 0n,
    );
    expect(inList.length).toBeGreaterThanOrEqual(1);
    // world->localPlayer also stores the pointer
    const world = proc.resolvePointer(GE(), [O.world, 0]);
    expect(hits).toContain(world + BigInt(O.localPlayer));
  });

  test('Offsets with a cs2-style json resolves g_engine → chain works', async () => {
    using proc = Process.open(gv.pid);
    const mod = proc.module('gamevictim.exe')!;
    const off = Offsets.of(proc, {
      'gamevictim.exe': {
        dwGameEngine: Number(gv.addr.g_engine) - mod.base,
        dwMarker: Number(gv.addr.g_marker) - mod.base,
      },
      netvars: { m_iHealth: O.health, m_vecOrigin: O.pos },
    });
    await off.ready();
    // @ts-expect-error proxy-populated
    expect(off.dwGameEngine.add(0).resolve()).toBe(gv.addr.g_engineObj);
    expect(off.netvars.m_iHealth).toBe(O.health);
    // @ts-expect-error proxy-populated
    expect(off.dwMarker.readBuffer(4).toString('latin1')).toBe('MPGV');
    // cheat-style chain: dwGameEngine → eng → world → localPlayer
    // @ts-expect-error proxy-populated
    const lp = off.dwGameEngine
      .add(O.world) // deref eng+0x18 → World*
      .add(O.localPlayer) // world+localPlayer → Entity*
      .add(0)
      .resolve();
    expect(lp).toBe(gv.addr.g_localPlayer);
  });

  test('AOB marker scan → scanUnique finds the sentinel in .data', async () => {
    using proc = Process.open(gv.pid);
    const hit = await proc.scanUnique(
      '4D 50 47 56 00 11 22 33 44 55 66 77 88 99 AA BB',
      { module: 'gamevictim.exe' },
    );
    expect(hit).toBe(gv.addr.g_marker);
  });
});

describe('gamevictim — liveness & edge regions', () => {
  test('sim thread alive: entity[0] health/pos (or identity) changes ~400ms', async () => {
    using proc = Process.open(gv.pid);
    const { first } = entityListAddr(proc);
    const ent0 = proc.readPointer(first);
    const s1 = proc
      .entity(ent0, { health: [O.health, 'float'], pos: [O.pos, 'vec3'] })
      .snapshot<{ health: number; pos: { x: number; y: number } }>();
    await sleep(400);
    const { first: first2, count } = entityListAddr(proc);
    expect(first2).toBe(first); // the array buffer itself doesn't move
    const ent0b = proc.readPointer(first);
    const s2 = proc
      .entity(ent0b, { health: [O.health, 'float'], pos: [O.pos, 'vec3'] })
      .snapshot<{ health: number; pos: { x: number; y: number } }>();
    const alive =
      ent0b !== ent0 ||
      s2.health !== s1.health ||
      s2.pos.x !== s1.pos.x ||
      s2.pos.y !== s1.pos.y;
    expect(alive).toBe(true);
    expect(count).toBeGreaterThanOrEqual(4);
  });

  test('readSafe across the PAGE_GUARD boundary zero-fills the guarded page', () => {
    using proc = Process.open(gv.pid);
    const buf = proc.readSafe(gv.addr.g_guard, 0x2000);
    expect(buf.length).toBe(0x2000);
    expect(buf.subarray(0, 0x100).every((b) => b === 0xc5)).toBe(true);
    expect(buf.subarray(0x1000).every((b) => b === 0)).toBe(true);
  });
});
