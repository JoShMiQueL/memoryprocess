import {
  Process,
  type ScanOptions,
  type ScanValueOptions,
  type ScanValueType,
} from './process.js';
import { ScanError, MemoryProcessError } from './errors.js';

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

/** Primitive field kinds understood by {@link Entity} / {@link Hacks.readMany}. */
export type FieldType =
  | 'int32'
  | 'uint32'
  | 'int64'
  | 'uint64'
  | 'float'
  | 'double'
  | 'pointer'
  | `string:${number}`
  | `wstring:${number}`
  | 'vec2'
  | 'vec3'
  | 'vec4'
  | 'ref';

/** Schema for {@link Entity}: field name → [offset, type]. */
export type EntitySchema = Record<string, [number, FieldType]>;

/** Declarative signature/offset entry (hazedumper / cs2-dumper compatible). */
export interface SigEntry {
  /** AOB pattern string ("48 8B 05 ? ? ? ?") — omit for a static RVA. */
  pattern?: string;
  /** Module to scan inside (e.g. 'client.dll'). Required for `pattern`. */
  module?: string;
  /**
   * After the hit:
   * - `relative: true` → `offsets[0]` is the rip-displacement position inside
   *   the instruction (default 3); `offsets[1..]` are then walked as a pointer
   *   dereference chain from the resolved address.
   * - `read` set → `offsets[0]` is where to read the pointer/`u32`/`u64`; the
   *   read value is dereferenced once and `offsets[1..]` walked as a chain.
   * - neither → `offsets` are walked as a pointer chain starting at the hit.
   */
  offsets?: number[];
  /** Add to the final result (hazedumper "extra"). */
  extra?: number;
  /** Hit is an instruction with a RIP-relative operand. */
  relative?: boolean;
  /** Deref width at `hit + offsets[0]` for non-relative sigs. */
  read?: 'u32' | 'u64' | 'ptr';
  /** Static RVA added to `module` base when no `pattern` is given. */
  rva?: number;
}

/** A signature database — either a flat name→entry map or hazedumper-shaped. */
export type OffsetsJson =
  | Record<string, SigEntry | number | string>
  | {
      signatures?: Record<string, SigEntry | number | string>;
      netvars?: Record<string, SigEntry | number | string>;
      timestamp?: string;
    };

const READ_WIDTHS: Record<string, number> = {
  int32: 4,
  uint32: 4,
  int64: 8,
  uint64: 8,
  float: 4,
  double: 8,
  pointer: 8,
};

const VALUE_READERS: Record<
  string,
  (buf: Buffer, off: number) => number | bigint
> = {
  int32: (b, o) => b.readInt32LE(o),
  uint32: (b, o) => b.readUInt32LE(o),
  int64: (b, o) => b.readBigInt64LE(o),
  uint64: (b, o) => b.readBigUInt64LE(o),
  float: (b, o) => b.readFloatLE(o),
  double: (b, o) => b.readDoubleLE(o),
  pointer: (b, o) => b.readBigUInt64LE(o),
};

/* ------------------------------------------------------------------ */
/* Address — cached base + fluent offset/deref chain                    */
/* ------------------------------------------------------------------ */

/**
 * A lazily-resolved pointer-chain address. `add()`/`deref()` build the chain;
 * `resolve()`/`ptr()` walk it once via {@link Process.resolvePointer}.
 *
 * `deref()` is a readability marker only — `resolvePointer` already dereferences
 * every offset except the last. `ptr()` returns the final resolved address;
 * `readPointer()` reads the 8-byte value AT that address (one extra hop).
 */
export class Address {
  readonly base: bigint;
  readonly chain: readonly number[];

  constructor(
    private proc: Process,
    base: number | bigint,
    chain: readonly number[] = [],
  ) {
    this.base = BigInt(base);
    this.chain = chain;
  }

  /** Derive a new Address with `off` appended to the chain. Immutable. */
  add(off: number | bigint): Address {
    return new Address(this.proc, this.base, [...this.chain, Number(off)]);
  }

  /**
   * Marker documenting that the *next* `add()`/`read*()` crosses a pointer.
   * Returns a new Address — pure no-op on the chain itself.
   */
  deref(): Address {
    return this;
  }

  /** Final address after walking the whole chain. */
  resolve(): bigint {
    if (this.chain.length === 0) return this.base;
    return this.proc.resolvePointer(this.base, this.chain);
  }

  /** Alias for {@link resolve}. */
  ptr(): bigint {
    return this.resolve();
  }

  /** Read the pointer stored AT the resolved address (one hop past `ptr()`). */
  readPointer(): bigint {
    return this.proc.readPointer(this.resolve());
  }

  readInt32(): number {
    return this.proc.readInt32(this.resolve());
  }
  readUInt32(): number {
    return this.proc.readUInt32(this.resolve());
  }
  readInt64(): bigint {
    return this.proc.readInt64(this.resolve());
  }
  readUInt64(): bigint {
    return this.proc.readUInt64(this.resolve());
  }
  readFloat(): number {
    return this.proc.readFloat(this.resolve());
  }
  readDouble(): number {
    return this.proc.readDouble(this.resolve());
  }
  readBuffer(size: number): Buffer {
    return this.proc.readBuffer(this.resolve(), size);
  }
  readString(max?: number): string {
    return this.proc.readString(this.resolve(), max);
  }
  readWideString(maxChars?: number): string {
    return this.proc.readWideString(this.resolve(), maxChars);
  }

  writeInt32(v: number): boolean {
    return this.proc.writeInt32(this.resolve(), v);
  }
  writeUInt32(v: number): boolean {
    return this.proc.writeUInt32(this.resolve(), v);
  }
  writeInt64(v: bigint): boolean {
    return this.proc.writeInt64(this.resolve(), v);
  }
  writeUInt64(v: bigint): boolean {
    return this.proc.writeUInt64(this.resolve(), v);
  }
  writeFloat(v: number): boolean {
    return this.proc.writeFloat(this.resolve(), v);
  }
  writeDouble(v: number): boolean {
    return this.proc.writeDouble(this.resolve(), v);
  }
  writePointer(v: bigint): boolean {
    return this.proc.writePointer(this.resolve(), v);
  }
  writeBuffer(data: Buffer | Uint8Array): boolean {
    return this.proc.writeBuffer(this.resolve(), data);
  }

  toString(): string {
    return `Address(0x${this.base.toString(16)}${this.chain.length ? ` + [${this.chain.map((o) => `0x${o.toString(16)}`).join(',')}]` : ''})`;
  }
}

/* ------------------------------------------------------------------ */
/* OffsetsDb — declarative pattern→resolved-address map                 */
/* ------------------------------------------------------------------ */

export class OffsetsDb {
  private entries = new Map<string, SigEntry | number>();
  private cache = new Map<string, bigint>();
  private proc?: Process;

  private constructor() {}

  /** Parse a hazedumper-style config or a flat `name → entry` map. */
  static load(json: string | OffsetsJson): OffsetsDb {
    const raw: OffsetsJson = typeof json === 'string' ? JSON.parse(json) : json;
    const db = new OffsetsDb();

    const add = (name: string, e: SigEntry | number | string) => {
      if (typeof e === 'number') db.entries.set(name, e);
      else if (typeof e === 'string') db.entries.set(name, { pattern: e });
      else if (e && typeof e === 'object') db.entries.set(name, e as SigEntry);
    };

    if ('signatures' in raw || 'netvars' in raw) {
      for (const [k, v] of Object.entries(raw.signatures ?? {})) add(k, v);
      for (const [k, v] of Object.entries(raw.netvars ?? {})) add(k, v);
    } else {
      for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        add(k, v as SigEntry | number | string);
      }
    }
    return db;
  }

  /** Bind this database to a live {@link Process} (enables {@link resolve}). */
  bind(proc: Process): this {
    this.proc = proc;
    this.cache.clear();
    return this;
  }

  /** Names of all loaded offsets/signatures. */
  keys(): string[] {
    return [...this.entries.keys()];
  }

  /**
   * Resolve `name` to a final address. Cached after first resolution.
   * Throws when the entry is unknown, the pattern isn't unique, or the module
   * isn't loaded.
   */
  async resolve(name: string): Promise<bigint> {
    const hit = this.cache.get(name);
    if (hit !== undefined) return hit;
    if (!this.proc) throw new Error('OffsetsDb is not bound to a Process');

    const e = this.entries.get(name);
    if (e === undefined)
      throw new MemoryProcessError(`unknown offset: ${name}`, 'UNKNOWN_OFFSET');

    let addr: bigint;
    if (typeof e === 'number') {
      addr = BigInt(e);
    } else if (e.pattern) {
      addr = await this.resolveSig(e);
    } else if (e.rva !== undefined) {
      const mod = this.proc.module(e.module ?? this.#firstModule());
      if (!mod) throw new ScanError(0, `module ${e.module ?? '?'} for ${name}`);
      addr = BigInt(mod.base) + BigInt(e.rva);
    } else {
      throw new MemoryProcessError(
        `offset ${name} has neither pattern nor rva`,
        'INVALID_OFFSET_ENTRY',
      );
    }

    this.cache.set(name, addr);
    return addr;
  }

  /** Resolve a named offset into an {@link Address} bound to `proc`. */
  async addr(name: string): Promise<Address> {
    return new Address(this.proc!, await this.resolve(name));
  }

  /** Resolve many names at once into `{name → addr}`. */
  async resolveAll(names?: string[]): Promise<Record<string, bigint>> {
    const out: Record<string, bigint> = {};
    const want = names ?? this.keys();
    for (const n of want) out[n] = await this.resolve(n);
    return out;
  }

  #firstModule(): string {
    const m = this.proc!.modules()[0];
    if (!m) throw new ScanError(0, 'no modules loaded');
    return m.path.split(/[\\/]/).pop()!.toLowerCase();
  }

  private async resolveSig(e: SigEntry): Promise<bigint> {
    const proc = this.proc!;
    const hit = await proc.scanUnique(e.pattern!, {
      module: e.module,
    });

    const offs = e.offsets ?? [];
    const extra = BigInt(e.extra ?? 0);

    if (e.relative) {
      // RIP-relative: displacement position defaults to +3 (mov rax,[rip+x]).
      const dispOff = offs[0] ?? 3;
      let a = proc.resolveRIPRelative(hit, dispOff);
      for (const off of offs.slice(1)) a = proc.readPointer(a) + BigInt(off);
      return a + extra;
    }

    if (e.read) {
      // hazedumper "read" sig: read u32/u64/ptr at hit+offsets[0], that value
      // is the pointer; walk offsets[1..] as a dereference chain.
      const readOff = offs[0] ?? 0;
      let a: bigint;
      if (e.read === 'u32') a = BigInt(proc.readUInt32(hit + BigInt(readOff)));
      else if (e.read === 'u64') a = proc.readUInt64(hit + BigInt(readOff));
      else a = proc.readPointer(hit + BigInt(readOff));
      for (const off of offs.slice(1)) a = proc.readPointer(a) + BigInt(off);
      return a + extra;
    }

    // Plain chain: walk the hit as a pointer chain.
    let a = hit;
    for (const off of offs) a = proc.readPointer(a) + BigInt(off);
    return a + extra;
  }
}

/* ------------------------------------------------------------------ */
/* Entity — typed view over a region                                    */
/* ------------------------------------------------------------------ */

interface CompiledField {
  name: string;
  offset: number;
  type: FieldType;
  width: number; // bytes
}

function compileSchema(schema: EntitySchema): {
  fields: CompiledField[];
  size: number;
} {
  const fields: CompiledField[] = [];
  let size = 0;
  for (const [name, [offset, type]] of Object.entries(schema)) {
    const w = fieldWidth(type);
    fields.push({ name, offset, type, width: w });
    if (offset + w > size) size = offset + w;
  }
  return { fields, size };
}

function fieldWidth(type: FieldType): number {
  if (type.startsWith('string:')) return Number.parseInt(type.slice(7), 10);
  if (type.startsWith('wstring:'))
    return Number.parseInt(type.slice(8), 10) * 2;
  if (type === 'vec2') return 8;
  if (type === 'vec3') return 12;
  if (type === 'vec4') return 16;
  const w = READ_WIDTHS[type];
  if (!w) throw new TypeError(`unknown entity field type ${type}`);
  return w;
}

function decodeField(
  buf: Buffer,
  off: number,
  type: FieldType,
): number | bigint | string | { x: number; y: number; z?: number; w?: number } {
  if (type.startsWith('string:')) {
    const max = Number.parseInt(type.slice(7), 10);
    const end = buf.indexOf(0, off);
    return buf
      .subarray(off, end === -1 || end - off > max ? off + max : end)
      .toString('utf8');
  }
  if (type.startsWith('wstring:')) {
    const max = Number.parseInt(type.slice(8), 10) * 2;
    let end = off;
    for (let i = off; i + 1 < Math.min(buf.length, off + max); i += 2) {
      if (buf[i] === 0 && buf[i + 1] === 0) {
        end = i;
        break;
      }
      end = i + 2;
    }
    return buf.subarray(off, Math.min(end, off + max)).toString('utf16le');
  }
  if (type === 'vec2')
    return { x: buf.readFloatLE(off), y: buf.readFloatLE(off + 4) };
  if (type === 'vec3')
    return {
      x: buf.readFloatLE(off),
      y: buf.readFloatLE(off + 4),
      z: buf.readFloatLE(off + 8),
    };
  if (type === 'vec4')
    return {
      x: buf.readFloatLE(off),
      y: buf.readFloatLE(off + 4),
      z: buf.readFloatLE(off + 8),
      w: buf.readFloatLE(off + 12),
    };
  if (type === 'ref') return buf.readBigUInt64LE(off);
  const r = VALUE_READERS[type];
  if (!r) throw new TypeError(`cannot decode field type ${type}`);
  return r(buf, off);
}

/** A typed, `readRegion`-backed view over an entity in remote memory. */
export class Entity {
  private fields: CompiledField[];
  private size: number;

  constructor(
    private proc: Process,
    readonly addr: bigint,
    schema: EntitySchema,
  ) {
    const c = compileSchema(schema);
    this.fields = c.fields;
    this.size = c.size;
  }

  /**
   * ONE `readBuffer` covering the whole schema; all fields decoded locally.
   * Refreshes every call — cheap per-frame snapshot.
   */
  snapshot<T = Record<string, unknown>>(): T {
    const buf = this.proc.readBuffer(this.addr, this.size);
    const out: Record<string, unknown> = {};
    for (const f of this.fields)
      out[f.name] = decodeField(buf, f.offset, f.type);
    return out as T;
  }

  /** Live-read a single field. */
  read(
    name: string,
  ):
    | number
    | bigint
    | string
    | { x: number; y: number; z?: number; w?: number } {
    const f = this.fields.find((x) => x.name === name);
    if (!f) throw new RangeError(`unknown entity field ${name}`);
    if (f.type.startsWith('string:') || f.type.startsWith('wstring:')) {
      const buf = this.proc.readBuffer(this.addr + BigInt(f.offset), f.width);
      return decodeField(buf, 0, f.type);
    }
    const buf = this.proc.readBuffer(this.addr + BigInt(f.offset), f.width);
    return decodeField(buf, 0, f.type);
  }

  /** Live-write a single field. */
  write(name: string, value: number | bigint | string): boolean {
    const f = this.fields.find((x) => x.name === name);
    if (!f) throw new RangeError(`unknown entity field ${name}`);
    const at = this.addr + BigInt(f.offset);
    if (typeof value === 'string') {
      if (f.type.startsWith('wstring:'))
        return this.proc.writeWideString(at, value);
      return this.proc.writeString(at, value);
    }
    const w = VALUE_READERS[f.type] ? f.width : 0;
    if (!w) throw new TypeError(`field ${name} is not a scalar`);
    if (f.type === 'int64' || f.type === 'uint64' || f.type === 'pointer')
      return this.proc.writePointer(at, BigInt(value));
    const buf = Buffer.alloc(w);
    if (f.type === 'float') buf.writeFloatLE(Number(value));
    else if (f.type === 'double') buf.writeDoubleLE(Number(value));
    else buf.writeUInt32LE(Number(value) >>> 0);
    return this.proc.writeBuffer(at, buf);
  }
}

/* ------------------------------------------------------------------ */
/* EntityList — array-stride or linked-list iteration                   */
/* ------------------------------------------------------------------ */

export interface EntityListOptions {
  /** First address: array base (stride mode) or address of head ptr (linked). */
  first: bigint | number;
  /**
   * Linked-list mode: offset of the "next" pointer inside each node.
   * Walk: `cur = readPtr(first + next)` then `yield cur; cur = readPtr(cur + next)`.
   */
  next?: number;
  /** Array mode: byte stride between elements. */
  stride?: number;
  /** Max elements (default 4096 — safety cap). */
  max?: number;
  /** When set, yields {@link Entity} views instead of raw addresses. */
  schema?: EntitySchema;
}

export class EntityList implements Iterable<bigint | Entity> {
  constructor(
    private proc: Process,
    private opts: EntityListOptions,
  ) {
    if (opts.next === undefined && opts.stride === undefined)
      throw new TypeError(
        'EntityList needs either `next` (linked) or `stride` (array)',
      );
  }

  *[Symbol.iterator](): Iterator<bigint | Entity> {
    const { first, next, stride, max = 4096, schema } = this.opts;
    const f = BigInt(first);

    if (stride !== undefined) {
      // Array-stride: yield raw element addresses; skip nothing.
      for (let i = 0; i < max; i++) {
        const a = f + BigInt(i * stride);
        yield schema ? new Entity(this.proc, a, schema) : a;
      }
      return;
    }

    // Linked: first is the address of the head pointer.
    let cur: bigint;
    try {
      cur = this.proc.readPointer(f + BigInt(next!));
    } catch {
      return;
    }
    let n = 0;
    while (cur !== 0n && n < max) {
      yield schema ? new Entity(this.proc, cur, schema) : cur;
      try {
        cur = this.proc.readPointer(cur + BigInt(next!));
      } catch {
        return;
      }
      n++;
    }
  }

  /** Eager-collect all addresses (or entities). */
  toArray(): (bigint | Entity)[] {
    return [...this];
  }
}

/* ------------------------------------------------------------------ */
/* Hacks — the high-level façade                                        */
/* ------------------------------------------------------------------ */

export class Hacks {
  #offsets?: OffsetsDb;

  constructor(readonly proc: Process) {}

  /* ---- Address ---- */
  addr(base: number | bigint): Address {
    return new Address(this.proc, base);
  }

  /* ---- OffsetsDb ---- */
  /** Parse + bind an offsets config to this proc. */
  loadOffsets(json: string | OffsetsJson): OffsetsDb {
    this.#offsets = OffsetsDb.load(json).bind(this.proc);
    return this.#offsets;
  }

  /** The bound offsets db (throws if {@link loadOffsets} wasn't called). */
  offsets(): OffsetsDb {
    if (!this.#offsets)
      throw new Error('call loadOffsets() first — no OffsetsDb bound');
    return this.#offsets;
  }

  /* ---- Entity ---- */
  entity(addr: number | bigint, schema: EntitySchema): Entity {
    return new Entity(this.proc, BigInt(addr), schema);
  }

  /* ---- EntityList ---- */
  entityList(opts: EntityListOptions): EntityList {
    return new EntityList(this.proc, opts);
  }

  /* ---- readMany — page-grouped batch read ---- */
  /**
   * Batch-read many typed values. Groups requests by 4KB page and does ONE
   * `readSafe` per page — 10-50× fewer N-API crossings for ESP-style loops.
   * Returns `null` for any address that can't be decoded.
   */
  readMany(
    reqs: {
      addr: number | bigint;
      type:
        | 'int32'
        | 'uint32'
        | 'int64'
        | 'uint64'
        | 'float'
        | 'double'
        | 'pointer';
    }[],
  ): (number | bigint | null)[] {
    const out = new Array<number | bigint | null>(reqs.length).fill(null);
    const PAGE = 0x1000n;
    const byPage = new Map<
      bigint,
      { idx: number; off: number; type: string; width: number }[]
    >();
    for (let i = 0; i < reqs.length; i++) {
      const r = reqs[i]!;
      const a = BigInt(r.addr);
      const page = a / PAGE;
      const off = Number(a % PAGE);
      const width = READ_WIDTHS[r.type];
      if (!width) throw new TypeError(`unknown readMany type ${r.type}`);
      let g = byPage.get(page);
      if (!g) {
        g = [];
        byPage.set(page, g);
      }
      g.push({ idx: i, off, type: r.type, width });
    }
    const MEM_COMMIT = 0x1000;
    const UNREADABLE = 0x01 | 0x100; // PAGE_NOACCESS | PAGE_GUARD
    const readableMask = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
    for (const [page, list] of byPage) {
      // readSafe zero-fills inaccessible pages — it never signals "bad", so
      // gate on queryAddress to distinguish real 0x00000000 from unmapped.
      const q = this.proc.queryAddress(page * PAGE);
      if (
        !q ||
        q.state !== MEM_COMMIT ||
        (q.protection & UNREADABLE) !== 0 ||
        (q.protection & 0xff & readableMask) === 0
      )
        continue;
      let buf: Buffer;
      try {
        // Read one page + max width so straddles at the tail still decode.
        buf = this.proc.readSafe(page * PAGE, 0x1000 + 8);
      } catch {
        continue;
      }
      for (const { idx, off, type, width } of list) {
        if (off + width > buf.length) continue;
        try {
          out[idx] = VALUE_READERS[type]!(buf, off);
        } catch {
          /* leave null */
        }
      }
    }
    return out;
  }

  /* ---- findPointersTo — shallow "who points at this" scan ---- */
  /**
   * Find all aligned locations whose stored pointer equals `target`.
   * `scanValue` has no `'pointer'` type — encodes the needle as `uint64`
   * (8-byte LE). Set `onlyWritable:false` to include `.rdata` pointers.
   */
  async findPointersTo(
    target: number | bigint,
    opts: {
      module?: string;
      start?: number | bigint;
      end?: number | bigint;
      onlyWritable?: boolean;
      alignment?: number;
    } = {},
  ): Promise<bigint[]> {
    // scanValue has no 'pointer' type — a uint64 LE encoding of the address
    // is byte-identical to a stored x64 pointer.
    return this.proc.scanValue(BigInt(target), {
      type: 'uint64',
      module: opts.module,
      start: opts.start,
      end: opts.end,
      onlyWritable: opts.onlyWritable ?? true,
      alignment: opts.alignment ?? this.proc.pointerSize,
    });
  }

  /* ---- convenience passthroughs ---- */
  scan(pattern: string, opts?: ScanOptions): Promise<bigint[]> {
    return this.proc.scan(pattern, opts);
  }
  scanFirst(pattern: string, opts?: ScanOptions): Promise<bigint | null> {
    return this.proc.scanFirst(pattern, opts);
  }
  scanUnique(pattern: string, opts?: ScanOptions): Promise<bigint> {
    return this.proc.scanUnique(pattern, opts);
  }
  scanValue(
    value: number | bigint,
    opts?: ScanValueOptions,
  ): Promise<bigint[]> {
    return this.proc.scanValue(value, opts);
  }
  nextScan(
    hits: readonly bigint[],
    value: number | bigint,
    opts?: { type?: ScanValueType; range?: [number | bigint, number | bigint] },
  ): Promise<bigint[]> {
    return this.proc.nextScan(hits, value, opts);
  }
  freeze(
    addr: number | bigint,
    type: ScanValueType,
    value: number | bigint,
    intervalMs?: number,
  ): () => void {
    return this.proc.freeze(addr, type, value, intervalMs);
  }
  watch(
    addr: number | bigint,
    cb: (n: number, o: number) => void,
    intervalMs?: number,
  ): () => void {
    return this.proc.watch(addr, cb, intervalMs);
  }
}
