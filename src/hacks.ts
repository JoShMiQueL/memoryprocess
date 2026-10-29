import type {
  ModuleInfo,
  Process,
  ScanOptions,
  ScanValueOptions,
  ScanValueType,
} from './process.js';
import { ScanError, MemoryProcessError, InvalidSchemaError } from './errors.js';

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

/** Primitive field kinds understood by {@link Entity} / {@link Process.readMany}. */
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

/** Pointer-width-aware scalar width: 'pointer'/'ref' follow `ptrSize`. */
function scalarWidth(type: string, ptrSize: number): number | undefined {
  if (type === 'pointer' || type === 'ref') return ptrSize;
  return READ_WIDTHS[type];
}

/** Read a pointer of the target's width (4 on WoW64, 8 native). */
function readPtr(buf: Buffer, off: number, ptrSize: number): bigint {
  return ptrSize === 4
    ? BigInt(buf.readUInt32LE(off))
    : buf.readBigUInt64LE(off);
}

/* ------------------------------------------------------------------ */
/* Address — cached base + fluent offset/deref chain                    */
/* ------------------------------------------------------------------ */

/** Strict parse of an unsigned hex/dec literal — rejects '', '0x', 'GG', signs. */
function parseUint(what: string, s: string): bigint {
  const t = s.trim();
  if (t === '' || /^[-+]/.test(t))
    throw new MemoryProcessError(
      `invalid ${what}: "${s}" — expected unsigned hex/dec`,
      'INVALID_ADDRESS_EXPR',
    );
  let v: bigint;
  try {
    v = BigInt(t);
  } catch {
    throw new MemoryProcessError(
      `invalid ${what}: "${s}" — expected unsigned hex/dec`,
      'INVALID_ADDRESS_EXPR',
    );
  }
  if (v < 0n)
    throw new MemoryProcessError(
      `invalid ${what}: "${s}" — must be ≥ 0`,
      'INVALID_ADDRESS_EXPR',
    );
  return v;
}

/** Does `s` look like a module reference (letters/dots) rather than a numeric literal? */
const LOOKS_LIKE_MODULE = /[a-zA-Z]/;

/**
 * Resolve a `"module+rva"` string, a bare numeric string, or a numeric base
 * to `{ base, rvaInString }` — the latter is the rva embedded in a
 * `'mod+rva'` expression (0n when the form has no `+` or the rva is 0), so
 * the caller can detect the ambiguous `('mod+rva', rva, ...)` overlap.
 * Strict: malformed expressions throw `MemoryProcessError` with code
 * `'INVALID_ADDRESS_EXPR'`; a missing module throws `'MODULE_NOT_FOUND'`.
 */
function resolveBase(
  proc: Process,
  base: number | bigint | string,
): { base: bigint; rvaInString: bigint } {
  if (typeof base !== 'string') {
    if (typeof base === 'number' && !Number.isInteger(base))
      throw new MemoryProcessError(
        `invalid address base ${base} — must be an integer`,
        'INVALID_ADDRESS_EXPR',
      );
    return { base: BigInt(base), rvaInString: 0n };
  }
  const s = base.trim();
  const plus = s.indexOf('+');
  const minus = s.indexOf('-');

  if (plus === -1) {
    if (minus > 0) {
      // 'mod-rva' is never a valid expression — but the whole string may be a
      // legitimate dashed module name ('my-mod.dll'). Report the better error.
      if (!proc.module(s)) {
        throw new MemoryProcessError(
          `module ${s} not loaded`,
          'MODULE_NOT_FOUND',
        );
      }
      throw new MemoryProcessError(
        `invalid address "${s}" — use 'module+rva' ('-' offsets aren't supported in the base expression; put negative offsets in the chain)`,
        'INVALID_ADDRESS_EXPR',
      );
    }
    if (LOOKS_LIKE_MODULE.test(s) && !/^0[xX]/.test(s)) {
      // bare module name reaching here means it isn't loaded —
      // moduleFor() checks first and diverts to the module+rva path.
      // BUT an all-hex literal like '1a2b' (letters but no dot/extension)
      // is more likely a bare hex address than a module — prefer that read
      // when it parses and looks like an address; else report missing module.
      if (/^[0-9a-fA-F]+$/.test(s) && /[a-fA-F]/.test(s)) {
        try {
          return { base: BigInt('0x' + s), rvaInString: 0n };
        } catch {
          /* fall through to MODULE_NOT_FOUND */
        }
      }
      throw new MemoryProcessError(
        `module ${s} not loaded`,
        'MODULE_NOT_FOUND',
      );
    }
    return { base: parseUint('address', s), rvaInString: 0n };
  }

  const modName = s.slice(0, plus).trim();
  const rvaStr = s.slice(plus + 1).trim();
  if (modName === '')
    throw new MemoryProcessError(
      `invalid address "${s}" — missing module before '+'`,
      'INVALID_ADDRESS_EXPR',
    );
  if (rvaStr.includes('+') || rvaStr.includes('-'))
    throw new MemoryProcessError(
      `invalid address "${s}" — only one '+' allowed ('module+rva')`,
      'INVALID_ADDRESS_EXPR',
    );
  const mod = proc.module(modName);
  if (!mod)
    throw new MemoryProcessError(
      `module ${modName} not loaded`,
      'MODULE_NOT_FOUND',
    );
  const rva = parseUint('rva', rvaStr);
  return { base: BigInt(mod.base) + rva, rvaInString: rva };
}

/**
 * Bare module name (no `+`) resolving to a loaded module → its ModuleInfo,
 * else undefined. Cheap regex pre-filter avoids a Toolhelp snapshot for
 * numeric-looking strings. Caller reuses the result — one lookup per Address.
 */
function moduleFor(
  proc: Process,
  base: number | bigint | string,
): ModuleInfo | undefined {
  if (typeof base !== 'string') return undefined;
  const s = base.trim();
  if (s.includes('+')) return undefined;
  if (!LOOKS_LIKE_MODULE.test(s) || /^0[xX]/.test(s)) return undefined;
  return proc.module(s);
}

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

  /**
   * `base` may be:
   * - a bigint/number virtual address,
   * - a `"module+rva"` string (`'client.dll+0xDEB99C'`), or
   * - a **bare module name** (`'client.dll'`) — then `chain[0]` is the RVA
   *   (added to the module base, not dereferenced) and `chain[1:]` is the
   *   pointer chain. So `new Address(p, 'game.exe', [0x1F2A3C, 0x10])` ≡
   *   `new Address(p, 'game.exe+0x1F2A3C', [0x10])`.
   *
   * `chain` offsets are walked like {@link Process.resolvePointer}: every
   * offset except the last dereferences the pointer, the last is added.
   *
   * **Canonical form** is `('mod', rva, ...chain)` — every number has exactly
   * one meaning. When `base` already carries a `+rva`, `chain[0]` is a deref
   * hop like any other; if it *equals* the embedded rva (and rva > 0) that's
   * almost always a doubled-rva bug, so it throws `AMBIGUOUS_ADDRESS_EXPR`.
   * Escape hatch for the rare legitimate case: pass the numeric
   * `mod.base + rva` bigint as base instead.
   */
  constructor(
    private proc: Process,
    base: number | bigint | string,
    chain: readonly number[] = [],
  ) {
    const mod = moduleFor(proc, base);
    if (mod) {
      const [rva, ...rest] = chain;
      if (rva !== undefined && (!Number.isInteger(rva) || rva < 0))
        throw new MemoryProcessError(
          `invalid rva ${rva} for module '${base}' — must be a finite integer ≥ 0`,
          'INVALID_ADDRESS_EXPR',
        );
      this.base = BigInt(mod.base) + BigInt(rva ?? 0);
      this.chain = rest;
      return;
    }

    const { base: resolved, rvaInString } = resolveBase(proc, base);
    const c0 = chain[0];
    if (chain.length > 0 && c0 !== undefined && !Number.isInteger(c0))
      throw new MemoryProcessError(
        `invalid chain offset ${c0} — chain offsets must be integers`,
        'INVALID_ADDRESS_EXPR',
      );
    if (
      rvaInString !== 0n &&
      chain.length > 0 &&
      BigInt(c0 as number) === rvaInString
    ) {
      throw new MemoryProcessError(
        `ambiguous expression "${base}" + chain[0]=${chain[0]}: the rva ` +
          `appears twice — once in the string and again as the first chain ` +
          `offset (which dereferences, it does NOT re-add). ` +
          `Did you mean '${(base as string).split('+')[0]!.trim()}', ` +
          `${chain[0]}, ...chain (bare-module form)? If a deref-by-${chain[0]} ` +
          `hop is really intended, pass the numeric base (mod.base + rva) ` +
          `to bypass this check.`,
        'AMBIGUOUS_ADDRESS_EXPR',
      );
    }
    this.base = resolved;
    this.chain = chain;
  }

  /** Derive a new Address with `off` appended to the chain. Immutable. */
  add(off: number | bigint): Address {
    return new Address(this.proc, this.base, [...this.chain, Number(off)]);
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
/* Offsets — declarative pattern→resolved-address map                    */
/* ------------------------------------------------------------------ */

/**
 * A signature/offset database bound to a live {@link Process}.
 *
 * Supports the two layouts real dumper tools emit:
 * - **cs2/GH-dumper**: `{ "client.dll": { "dwEntityList": 0xDEB99C, ... } }`
 *   — module-keyed RVA maps (each value is an offset from the module base).
 * - **hazedumper**: `{ signatures: { name: {module, pattern, offsets, extra,
 *   relative, read, rva} }, netvars: { name: offset } }` — AOB-scan entries.
 * - Flat `{ name: SigEntry | number | "mod+rva" | pattern }` also accepted.
 *
 * After `await off.ready()`, entries are exposed as properties:
 * `off.dwLocalPlayer` (an {@link Address}) and `off.netvars.m_iHealth`
 * (a field offset number) — plus `off.get(name)`/`off.resolve(name)`.
 */
export class Offsets {
  private entries = new Map<string, SigEntry | number>();
  /** module-keyed rva maps: { module: { name: rva } } */
  private moduleRvps = new Map<string, Map<string, number>>();
  private cache = new Map<string, bigint>();
  private proc?: Process;
  /** netvars / plain field offsets (name → offset number) */
  readonly netvars: Record<string, number> = {};
  /** Entries that failed to resolve in the last `ready()` — name → error. */
  readonly failures: Record<string, Error> = {};
  private resolved = false;
  /** Entry names populated as own properties by ready() (removed on re-bind). */
  private populated = new Set<string>();

  private constructor() {}

  /**
   * Parse an offsets config. Detects the cs2-dumper module-keyed layout
   * (`{ "module.dll": { name: rva } }`) vs hazedumper (`signatures`/`netvars`)
   * vs a flat name→entry map. Bind to `proc` via {@link of} or `.bind()`.
   */
  static load(json: string | OffsetsJson): Offsets {
    const raw = (typeof json === 'string' ? JSON.parse(json) : json) as Record<
      string,
      unknown
    >;
    const db = new Offsets();

    // cs2-dumper style: top-level keys that are modules whose value is a
    // {name: rva} map. Members are filtered individually — a map that also
    // holds a non-number key (a nested table, a comment field) doesn't lose
    // the whole module's rvas, it just skips that member.
    const isModuleMap = (v: unknown): v is Record<string, unknown> =>
      !!v &&
      typeof v === 'object' &&
      !Array.isArray(v) &&
      Object.values(v).some((x) => typeof x === 'number');
    const looksModule = (k: string) => /\.(dll|exe)$/i.test(k);

    const add = (name: string, e: SigEntry | number | string) => {
      // A signature/flat entry must not silently clobber a module-map rva of
      // the same name (m9 was one-direction-only). Throw on any collision.
      if (db.entries.has(name))
        throw new MemoryProcessError(
          `offset name "${name}" defined more than once — rename to disambiguate`,
          'DUPLICATE_OFFSET_NAME',
        );
      if (typeof e === 'number') {
        db.entries.set(name, e);
        return;
      }
      if (typeof e === 'string') {
        const s = e.trim();
        if (s.includes('+')) {
          // 'module+rva' — exactly one '+', both sides required.
          const parts = s.split('+');
          if (parts.length !== 2 || !parts[0]!.trim() || !parts[1]!.trim())
            throw new MemoryProcessError(
              `invalid offset entry "${name}": "${e}" — expected 'module+rva'`,
              'INVALID_OFFSET_ENTRY',
            );
          let rva: bigint;
          try {
            rva = BigInt(parts[1]!.trim());
          } catch {
            throw new MemoryProcessError(
              `invalid offset entry "${name}": bad rva "${parts[1]}" — expected unsigned hex/dec`,
              'INVALID_OFFSET_ENTRY',
            );
          }
          if (rva < 0n || rva > BigInt(Number.MAX_SAFE_INTEGER))
            throw new MemoryProcessError(
              `invalid offset entry "${name}": rva out of range`,
              'INVALID_OFFSET_ENTRY',
            );
          db.entries.set(name, {
            rva: Number(rva),
            module: parts[0]!.trim(),
          });
          return;
        }
        if (s.includes('-') && !/^[0-9a-fA-F? ]+$/.test(s))
          // dashed non-pattern ('mod-0x10') — '-' is never legal in an entry
          throw new MemoryProcessError(
            `invalid offset entry "${name}": "${e}" — use 'module+rva' ('-' is not supported)`,
            'INVALID_OFFSET_ENTRY',
          );
        // AOB pattern — scanUnique validates the bytes at resolve time.
        db.entries.set(name, { pattern: e });
        return;
      }
      if (e && typeof e === 'object') db.entries.set(name, e as SigEntry);
    };

    const sigs = raw.signatures as
      Record<string, SigEntry | number | string> | undefined;
    const nets = raw.netvars as
      Record<string, SigEntry | number | string> | undefined;

    // collect module-keyed rva maps (cs2-dumper) AND flat sig entries.
    // Module members filtered individually (m8); a name colliding with an
    // already-collected entry throws rather than last-wins silently (m9).
    for (const [k, v] of Object.entries(raw)) {
      if (k === 'signatures' || k === 'netvars' || k === 'timestamp') continue;
      if (looksModule(k) && isModuleMap(v)) {
        const m = new Map<string, number>();
        for (const [name, rva] of Object.entries(v)) {
          if (typeof rva !== 'number') continue; // skip non-rva members
          m.set(name, rva);
          if (db.entries.has(name))
            throw new MemoryProcessError(
              `offset name "${name}" appears in multiple module maps — rename to disambiguate`,
              'DUPLICATE_OFFSET_NAME',
            );
          db.entries.set(name, { module: k, rva });
        }
        db.moduleRvps.set(k, m);
      }
    }
    // hazedumper signatures / netvars / flat map
    for (const [k, v] of Object.entries(sigs ?? {})) add(k, v);
    for (const [k, v] of Object.entries(raw)) {
      if (
        k === 'signatures' ||
        k === 'netvars' ||
        k === 'timestamp' ||
        looksModule(k)
      )
        continue;
      if (
        typeof v === 'number' ||
        typeof v === 'string' ||
        (v &&
          typeof v === 'object' &&
          ('pattern' in (v as object) ||
            'rva' in (v as object) ||
            'offsets' in (v as object)))
      ) {
        // don't clobber an entry already collected from a module map
        if (!db.entries.has(k)) add(k, v as SigEntry | number | string);
      }
    }
    // netvars → plain field offsets
    for (const [k, v] of Object.entries(nets ?? {})) {
      if (typeof v === 'number') db.netvars[k] = v;
      else if (v && typeof v === 'object' && 'offset' in (v as SigEntry))
        db.netvars[k] = (v as SigEntry & { offset: number }).offset;
    }
    return db;
  }

  /** Build + bind in one call: `Offsets.of(proc, json)`. */
  static of(proc: Process, json: string | OffsetsJson): Offsets {
    return Offsets.load(json).bind(proc);
  }

  /** Bind this database to a live {@link Process} (enables {@link resolve}). */
  bind(proc: Process): this {
    this.proc = proc;
    this.cache.clear();
    this.resolved = false;
    // Drop stale Address properties bound to the PREVIOUS proc — leaving them
    // would read from the wrong process while resolve() uses the new one.
    for (const name of this.populated)
      delete (this as Record<string, unknown>)[name];
    this.populated.clear();
    for (const k of Object.keys(this.failures)) delete this.failures[k];
    return this;
  }

  /**
   * Resolve + cache every entry, then expose them as properties:
   * `off.dwLocalPlayer` → `Address`, `off.netvars.*` → number.
   * Call once after construction/bind. Idempotent. Requires a bound proc;
   * entry names colliding with Offsets members throw rather than clobber them.
   */
  async ready(): Promise<this> {
    if (!this.proc)
      throw new MemoryProcessError(
        'Offsets is not bound to a Process — call .bind(proc) or Offsets.of()',
        'NOT_BOUND',
      );
    if (this.resolved) return this;
    for (const name of this.keys()) {
      if (name in this)
        throw new MemoryProcessError(
          `offset name "${name}" collides with a reserved Offsets member — rename it in the database`,
          'RESERVED_OFFSET_NAME',
        );
    }
    for (const name of this.keys()) {
      try {
        const addr = await this.resolve(name);
        (this as Record<string, unknown>)[name] = new Address(this.proc, addr);
        this.populated.add(name);
      } catch (e) {
        // record — an unresolvable entry leaves `off[name]` undefined and the
        // error discoverable via `off.failures`, rather than vanishing silently
        // or aborting the whole ready().
        this.failures[name] = e instanceof Error ? e : new Error(String(e));
      }
    }
    this.resolved = true;
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
    if (!this.proc)
      throw new MemoryProcessError(
        'Offsets is not bound to a Process — call .bind(proc) or Offsets.of()',
        'NOT_BOUND',
      );

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
      if (!mod)
        throw new MemoryProcessError(
          `module ${e.module ?? '?'} for offset '${name}' not loaded`,
          'MODULE_NOT_FOUND',
        );
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
    if (!m)
      throw new MemoryProcessError(
        'no modules loaded in target',
        'MODULE_NOT_FOUND',
      );
    return m.path.split(/[\\/]/).pop()!.toLowerCase();
  }

  private async resolveSig(e: SigEntry): Promise<bigint> {
    const proc = this.proc!;
    const hit = await proc.scanUnique(e.pattern!, {
      module: e.module,
    });

    const offs = e.offsets ?? [];
    const extra = BigInt(e.extra ?? 0);
    // Every chain offset must be an integer — a float in the sig config
    // surfaces as a cryptic BigInt RangeError otherwise (m11).
    const step = (a: bigint, off: number): bigint => {
      if (!Number.isInteger(off))
        throw new MemoryProcessError(
          `invalid offset ${off} in sig chain — offsets must be integers`,
          'INVALID_OFFSET_ENTRY',
        );
      return proc.readPointer(a) + BigInt(off);
    };

    if (e.relative) {
      // RIP-relative: displacement position defaults to +3 (mov rax,[rip+x]).
      const dispOff = offs[0] ?? 3;
      let a = proc.resolveRIPRelative(hit, dispOff);
      for (const off of offs.slice(1)) a = step(a, off);
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
      for (const off of offs.slice(1)) a = step(a, off);
      return a + extra;
    }

    // Plain chain: walk the hit as a pointer chain.
    let a = hit;
    for (const off of offs) a = step(a, off);
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

/**
 * Cap on the schema span (maxOffset+width). snapshot() reads the WHOLE span
 * in one readBuffer — a pathologically sparse schema
 * (`{a:[0], b:[0x4000000]}`) would issue a single enormous RPM. 64KiB
 * already covers real game structs; wider spans should use readMany().
 */
const MAX_SCHEMA_SPAN = 64 * 1024;

function compileSchema(
  schema: EntitySchema,
  ptrSize: number,
): {
  fields: CompiledField[];
  size: number;
} {
  const fields: CompiledField[] = [];
  let size = 0;
  for (const [name, [offset, type]] of Object.entries(schema)) {
    const w = fieldWidth(type, ptrSize);
    fields.push({ name, offset, type, width: w });
    if (offset + w > size) size = offset + w;
  }
  if (size > MAX_SCHEMA_SPAN)
    throw new InvalidSchemaError(
      `schema span too large (${size} bytes > ${MAX_SCHEMA_SPAN}) — ` +
        `snapshot() would read the whole span in one RPM; use readMany() ` +
        `or split the schema`,
    );
  return { fields, size };
}

function stringWidth(type: FieldType, prefix: string, mult: number): number {
  const raw = type.slice(prefix.length);
  if (!/^\d+$/.test(raw))
    throw new TypeError(
      `invalid ${prefix} width in field type "${type}" — expected a positive integer`,
    );
  const n = Number.parseInt(raw, 10);
  if (n <= 0)
    throw new TypeError(
      `invalid ${prefix} width in field type "${type}" — must be > 0`,
    );
  return n * mult;
}

function fieldWidth(type: FieldType, ptrSize: number): number {
  if (type.startsWith('string:')) return stringWidth(type, 'string:', 1);
  if (type.startsWith('wstring:')) return stringWidth(type, 'wstring:', 2);
  if (type === 'vec2') return 8;
  if (type === 'vec3') return 12;
  if (type === 'vec4') return 16;
  const w = scalarWidth(type, ptrSize);
  if (!w) throw new TypeError(`unknown entity field type ${type}`);
  return w;
}

function decodeField(
  buf: Buffer,
  off: number,
  type: FieldType,
  ptrSize = 8,
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
  if (type === 'ref') return readPtr(buf, off, ptrSize);
  if (type === 'pointer') return readPtr(buf, off, ptrSize);
  const r = VALUE_READERS[type];
  if (!r) throw new TypeError(`cannot decode field type ${type}`);
  return r(buf, off);
}

/**
 * A typed, `readRegion`-backed view over an entity in remote memory.
 * NOTE: `read(name)` costs ONE RPM per call — in hot loops prefer
 * {@link Entity.snapshot} (one readBuffer for all fields) over
 * `e.read('x'); e.read('y'); e.read('z')` (three RPMs).
 */
export class Entity {
  private fields: CompiledField[];
  private size: number;
  private ptrSize: number;

  constructor(
    private proc: Process,
    readonly addr: bigint,
    schema: EntitySchema,
  ) {
    this.ptrSize = proc.pointerSize;
    const c = compileSchema(schema, this.ptrSize);
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
      out[f.name] = decodeField(buf, f.offset, f.type, this.ptrSize);
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
    const buf = this.proc.readBuffer(this.addr + BigInt(f.offset), f.width);
    return decodeField(buf, 0, f.type, this.ptrSize);
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
    const w =
      f.type === 'ref' || VALUE_READERS[f.type] !== undefined ? f.width : 0;
    if (!w) throw new TypeError(`field ${name} is not a scalar`);
    if (f.type === 'pointer' || f.type === 'ref')
      return this.ptrSize === 4
        ? this.proc.writeUInt32(at, Number(BigInt(value) & 0xffffffffn))
        : this.proc.writePointer(at, BigInt(value));
    if (f.type === 'int64' || f.type === 'uint64')
      return this.proc.writePointer(at, BigInt(value));
    const buf = Buffer.alloc(w);
    if (f.type === 'float') buf.writeFloatLE(Number(value));
    else if (f.type === 'double') buf.writeDoubleLE(Number(value));
    else {
      // int32/uint32 — reject out-of-range rather than silently wrapping
      // (>>>0 turns -1 into 0xFFFFFFFF, 0x1_0000_0001 into 1).
      const n = Number(value);
      if (!Number.isInteger(n))
        throw new RangeError(`field ${name} needs an integer, got ${value}`);
      if (f.type === 'int32') {
        if (n < -0x80000000 || n > 0x7fffffff)
          throw new RangeError(`field ${name}: int32 out of range ${n}`);
        buf.writeInt32LE(n);
      } else {
        if (n < 0 || n > 0xffffffff)
          throw new RangeError(`field ${name}: uint32 out of range ${n}`);
        buf.writeUInt32LE(n);
      }
    }
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
  /** Safety cap on `max` — prevents accidental OOM/hang in toArray(). */
  static readonly MAX_ELEMENTS = 1_000_000;

  constructor(
    private proc: Process,
    private opts: EntityListOptions,
  ) {
    if (opts.next === undefined && opts.stride === undefined)
      throw new TypeError(
        'EntityList needs either `next` (linked) or `stride` (array)',
      );
    if (
      opts.stride !== undefined &&
      (!Number.isInteger(opts.stride) || opts.stride <= 0)
    )
      throw new TypeError('EntityList `stride` must be an integer > 0');
    const max = opts.max ?? 4096;
    if (!Number.isInteger(max) || max < 0 || max > EntityList.MAX_ELEMENTS)
      throw new TypeError(
        `EntityList \`max\` must be an integer between 0 and ${EntityList.MAX_ELEMENTS}`,
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

    // Linked: first is the address of the head pointer. Track visited nodes —
    // a malformed `next` chain that loops back on itself would otherwise yield
    // duplicates until `max` is hit (bounded, but wasteful and wrong).
    const visited = new Set<bigint>();
    let cur: bigint;
    try {
      cur = this.proc.readPointer(f + BigInt(next!));
    } catch {
      return;
    }
    let n = 0;
    while (cur !== 0n && n < max && !visited.has(cur)) {
      visited.add(cur);
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
/* Standalone helpers used by the Process methods below                 */
/* ------------------------------------------------------------------ */

/**
 * Batch-read many typed values. Groups requests by 4KB page and does ONE
 * `readSafe` per page — 10-50× fewer N-API crossings for ESP-style loops.
 * Returns `null` for any address that can't be decoded.
 */
export function readMany(
  proc: Process,
  reqs: {
    addr: number | bigint;
    type:
      'int32' | 'uint32' | 'int64' | 'uint64' | 'float' | 'double' | 'pointer';
  }[],
): (number | bigint | null)[] {
  const out = new Array<number | bigint | null>(reqs.length).fill(null);
  const PAGE = 0x1000n;
  const ptrSize = proc.pointerSize;
  const byPage = new Map<
    bigint,
    { idx: number; off: number; type: string; width: number }[]
  >();
  for (let i = 0; i < reqs.length; i++) {
    const r = reqs[i]!;
    const a = BigInt(r.addr);
    const page = a / PAGE;
    const off = Number(a % PAGE);
    const width = scalarWidth(r.type, ptrSize);
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
  // R/RW/RX/RWX/EXECUTE_READ/EXECUTE_READWRITE — PAGE_EXECUTE (0x10) is
  // deliberately excluded: it's rare in user-mode and ReadProcessMemory on
  // execute-only pages is inconsistent, so readMany returns null there
  // (where readBuffer would attempt the read and fail differently).
  const readableMask = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
  for (const [page, list] of byPage) {
    // readSafe zero-fills inaccessible pages — it never signals "bad", so
    // gate on queryAddress to distinguish real 0x00000000 from unmapped.
    const q = proc.queryAddress(page * PAGE);
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
      buf = proc.readSafe(page * PAGE, 0x1000 + 8);
    } catch {
      continue;
    }
    // The readable region containing page start ends at regionEnd — a request
    // whose span crosses it reads zero-fill for its tail (regions are
    // page-granular but can END mid-4KB-page if a smaller region is followed
    // by unmapped/NOACCESS space).
    const regionEnd = BigInt(q.baseAddress) + BigInt(q.size);
    for (const { idx, off, type, width } of list) {
      if (off + width > buf.length) continue;
      const reqEnd = page * PAGE + BigInt(off + width);
      if (reqEnd > regionEnd) {
        // crosses the region boundary — tail must live in a readable region too
        const qe = proc.queryAddress(reqEnd - 1n);
        if (
          !qe ||
          qe.state !== MEM_COMMIT ||
          (qe.protection & UNREADABLE) !== 0 ||
          (qe.protection & 0xff & readableMask) === 0
        )
          continue; // straddle into unreadable region → null, not a false 0
      }
      try {
        out[idx] =
          type === 'pointer'
            ? readPtr(buf, off, ptrSize)
            : VALUE_READERS[type]!(buf, off);
      } catch {
        /* leave null */
      }
    }
  }
  return out;
}

/**
 * Find all aligned locations whose stored pointer equals `target`.
 * `scanValue` has no `'pointer'` type — encodes the needle as `uint64`
 * (8-byte LE) or `uint32` on WoW64 targets. Set `onlyWritable:false` to
 * include `.rdata` pointers.
 */
export function findPointersTo(
  proc: Process,
  target: number | bigint,
  opts: {
    module?: string;
    start?: number | bigint;
    end?: number | bigint;
    onlyWritable?: boolean;
    alignment?: number;
  } = {},
): Promise<bigint[]> {
  return proc
    .scanValue(BigInt(target), {
      type: proc.pointerSize === 4 ? 'uint32' : 'uint64',
      module: opts.module,
      start: opts.start,
      end: opts.end,
      onlyWritable: opts.onlyWritable ?? true,
      alignment: opts.alignment ?? proc.pointerSize,
    })
    .then((hits) => hits.map((h) => h.addr));
}
