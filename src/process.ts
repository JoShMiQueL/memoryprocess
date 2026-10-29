import { writeFileSync } from 'node:fs';
import { native } from './native.js';
import {
  ProcessNotFoundError,
  AccessDeniedError,
  ReadError,
  WriteError,
  ScanError,
  InjectError,
} from './errors.js';
import {
  Address,
  Entity,
  EntityList,
  Offsets,
  readMany as readManyImpl,
  findPointersTo as findPointersToImpl,
  type EntitySchema,
  type EntityListOptions,
  type OffsetsJson,
} from './hacks.js';

export interface ProcessInfo {
  pid: number;
  name: string;
}
export interface ModuleInfo {
  base: number;
  size: number;
  path: string;
}
export interface Region {
  baseAddress: number;
  size: number;
  protection: number;
  type: number;
}
export interface ThreadContext {
  rip: bigint;
  rsp: bigint;
  rbp: bigint;
  dr0: bigint;
  dr1: bigint;
  dr2: bigint;
  dr3: bigint;
  /** Debug status register — B0..B3 bits identify which breakpoint fired. */
  dr6: bigint;
  dr7: bigint;
  eflags: bigint;
}

export const Protection = {
  PAGE_NOACCESS: 0x01,
  PAGE_READONLY: 0x02,
  PAGE_READWRITE: 0x04,
  PAGE_WRITECOPY: 0x08,
  PAGE_EXECUTE: 0x10,
  PAGE_EXECUTE_READ: 0x20,
  PAGE_EXECUTE_READWRITE: 0x40,
  PAGE_EXECUTE_WRITECOPY: 0x80,
  PAGE_GUARD: 0x100,
  // unprefixed aliases for convenience
  READWRITE: 0x04,
  EXECUTE_READ: 0x20,
  EXECUTE_READWRITE: 0x40,
  EXECUTE_WRITECOPY: 0x80,
} as const;

export const AllocationType = {
  MEM_COMMIT: 0x1000,
  MEM_RESERVE: 0x2000,
  MEM_TOP_DOWN: 0x100000,
} as const;

export const ProcessAccess = {
  ALL: 0x1fffff,
  VM_READ: 0x0010,
  VM_WRITE: 0x0020,
  VM_OPERATION: 0x0008,
  QUERY_INFORMATION: 0x0400,
  QUERY_LIMITED: 0x1000,
  CREATE_THREAD: 0x0002,
  SUSPEND_RESUME: 0x0800,
  READ_WRITE_QUERY: 0x0010 | 0x0020 | 0x0008 | 0x0400,
} as const;

export interface HookHandle {
  src: bigint;
  dst: bigint;
  stub: bigint;
  stolen: Buffer;
}

export interface ScanOptions {
  /** start address (default 0) */
  start?: number | bigint;
  /** end address (default: top of user space) */
  end?: number | bigint;
  /** restrict to a module's range */
  module?: string;
  /** restrict to a named PE section of `module` (e.g. '.text'); requires `module` */
  section?: string;
  /** only scan readable regions (default true) */
  onlyReadable?: boolean;
}

export type ScanValueType =
  'int32' | 'uint32' | 'int64' | 'uint64' | 'float' | 'double';
export type WriteValueType = ScanValueType | 'pointer';

export interface ScanValueOptions {
  /** value type (default 'int32') */
  type?: ScanValueType;
  /** start address (default 0) */
  start?: number | bigint;
  /** end address (default: top of user space) */
  end?: number | bigint;
  /** restrict to a module's range */
  module?: string;
  /** only scan writable regions (default true) */
  onlyWritable?: boolean;
  /** candidate alignment in bytes (default: value width) */
  alignment?: number;
}

// Convert a start/end bound to a finite number; undefined stays undefined so
// the native side can apply its default. Non-finite or garbage input throws
// rather than silently scanning [0, user-top] or nothing.
const toNum = (v: number | bigint | undefined): number | undefined => {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n))
    throw new RangeError('start/end must be a finite number');
  return n;
};

const MAX_READ_BYTES = 512 * 1024 * 1024;
function checkSize(size: number): void {
  if (!Number.isFinite(size) || size < 0 || size > MAX_READ_BYTES)
    throw new RangeError('size must be a finite number between 0 and 512MB');
}

// Guard: the native layer uses unchecked As<Number>/As<String> casts, so a
// wrong-typed JS arg becomes a pending N-API exception — then the C++ code
// throws AGAIN (napi_throw while an exception is pending) and Bun aborts with
// "NAPI FATAL ERROR". Validate every arg that must be a Number/String here,
// before it can cross the boundary with a bad type.
function checkNumber(v: unknown, name: string): asserts v is number {
  if (typeof v !== 'number') throw new TypeError(`${name} must be a number`);
  if (Number.isNaN(v)) throw new RangeError(`${name} must be a number`);
}
function checkAddr(v: unknown, name = 'address'): asserts v is number | bigint {
  if (typeof v !== 'number' && typeof v !== 'bigint')
    throw new TypeError(`${name} must be number|bigint`);
}
function checkStr(v: unknown, name: string): asserts v is string {
  if (typeof v !== 'string') throw new TypeError(`${name} must be a string`);
}

// Encode a typed little-endian value for value scans / writes.
export function encodeValue(
  type: WriteValueType,
  value: number | bigint,
): Buffer {
  const b = Buffer.alloc(
    type === 'int64' ||
      type === 'uint64' ||
      type === 'double' ||
      type === 'pointer'
      ? 8
      : 4,
  );
  switch (type) {
    case 'int32':
      b.writeInt32LE(Number(value));
      break;
    case 'uint32':
      b.writeUInt32LE(Number(value) >>> 0);
      break;
    case 'int64':
      b.writeBigInt64LE(BigInt(value));
      break;
    case 'uint64':
      b.writeBigUInt64LE(BigInt(value));
      break;
    case 'pointer':
      b.writeBigUInt64LE(BigInt(value));
      break;
    case 'float':
      b.writeFloatLE(Number(value));
      break;
    case 'double':
      b.writeDoubleLE(Number(value));
      break;
    default:
      throw new TypeError(`unknown type ${type}`);
  }
  return b;
}

function decodeValue(
  buf: Buffer,
  off: number,
  type: WriteValueType,
): number | bigint {
  switch (type) {
    case 'int32':
      return buf.readInt32LE(off);
    case 'uint32':
      return buf.readUInt32LE(off);
    case 'int64':
      return buf.readBigInt64LE(off);
    case 'uint64':
      return buf.readBigUInt64LE(off);
    case 'pointer':
      return buf.readBigUInt64LE(off);
    case 'float':
      return buf.readFloatLE(off);
    case 'double':
      return buf.readDoubleLE(off);
    default:
      throw new TypeError(`unknown type ${type}`);
  }
}

const VALUE_WIDTHS: Record<WriteValueType, number> = {
  int32: 4,
  uint32: 4,
  float: 4,
  int64: 8,
  uint64: 8,
  double: 8,
  pointer: 8,
};

/** Types accepted by scanValue/nextScan ('pointer' is write-only). */
const VALID_SCAN_TYPES: readonly ScanValueType[] = [
  'int32',
  'uint32',
  'int64',
  'uint64',
  'float',
  'double',
];

const REL32_MIN = -0x80000000n;
const REL32_MAX = 0x7fffffffn;
function checkRel32(rel: bigint): void {
  if (rel < REL32_MIN || rel > REL32_MAX)
    throw new Error(
      `target out of rel32 range (rel=${rel}, must be within ±2GB)`,
    );
}

export class Process implements Disposable {
  #handle: number;
  readonly pid: number;
  // freeze()/watch() intervals — tracked so close() can kill them; otherwise
  // they keep polling handle 0 forever after close.
  #timers = new Set<ReturnType<typeof setInterval>>();

  private constructor(handle: number, pid: number) {
    this.#handle = handle;
    this.pid = pid;
  }

  /**
   * Open a process by name ("notepad.exe") or pid.
   * Default access is least-privilege VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION.
   * Pass `{ access }` (or a raw access number) to override.
   * Throws ProcessNotFoundError / AccessDeniedError.
   */
  static open(
    nameOrPid: string | number,
    opts?: { access?: number } | number,
  ): Process {
    const access = typeof opts === 'number' ? opts : opts?.access;
    if (
      access !== undefined &&
      (typeof access !== 'number' || !Number.isFinite(access))
    )
      throw new TypeError('access must be a number');
    try {
      const { handle, pid } = native.openProcess(nameOrPid, access);
      return new Process(handle, pid);
    } catch (e: any) {
      if (e?.code === 'PROCESS_NOT_FOUND')
        throw new ProcessNotFoundError(nameOrPid);
      if (e?.code === 'ACCESS_DENIED' || e?.win32code === 5)
        throw new AccessDeniedError(
          typeof nameOrPid === 'number' ? nameOrPid : -1,
        );
      throw e;
    }
  }

  /** Open with read-only access (VM_READ|QUERY_INFORMATION). */
  static openReadOnly(nameOrPid: string | number): Process {
    return Process.open(nameOrPid, {
      access: ProcessAccess.VM_READ | ProcessAccess.QUERY_INFORMATION,
    });
  }

  /** List running processes without opening a handle. */
  static list(): ProcessInfo[] {
    return native.listProcesses();
  }

  /** Find first process by name (case-insensitive). */
  static find(name: string): ProcessInfo | undefined {
    const want = name.toLowerCase();
    return native
      .listProcesses()
      .find(
        (p) =>
          p.name.toLowerCase() === want ||
          p.name.toLowerCase() === `${want}.exe`,
      );
  }

  get handle(): number {
    return this.#handle;
  }

  private assertOpen() {
    if (!this.#handle) throw new Error('Process handle is closed');
  }

  // ---- reads ----
  readInt32(addr: number | bigint): number {
    return this.#read<number>(addr, 'int32');
  }
  readUInt32(addr: number | bigint): number {
    return this.#read<number>(addr, 'uint32');
  }
  readInt64(addr: number | bigint): bigint {
    return this.#read<bigint>(addr, 'int64');
  }
  readUInt64(addr: number | bigint): bigint {
    return this.#read<bigint>(addr, 'uint64');
  }
  readFloat(addr: number | bigint): number {
    return this.#read<number>(addr, 'float');
  }
  readDouble(addr: number | bigint): number {
    return this.#read<number>(addr, 'double');
  }
  readPointer(addr: number | bigint): bigint {
    return this.#read<bigint>(addr, 'pointer');
  }

  readBuffer(addr: number | bigint, size: number): Buffer {
    this.assertOpen();
    checkAddr(addr);
    checkNumber(size, 'size');
    checkSize(size);
    try {
      return native.readBuffer(this.#handle, Number(addr), size);
    } catch {
      throw new ReadError(addr);
    }
  }

  readString(
    addr: number | bigint,
    max = 256,
    encoding: 'utf8' | 'ascii' = 'utf8',
  ): string {
    const buf = this.readBuffer(addr, max);
    const end = buf.indexOf(0);
    return buf.subarray(0, end === -1 ? buf.length : end).toString(encoding);
  }

  /** Read a NUL-terminated UTF-16 (wide) string. */
  readWideString(addr: number | bigint, maxChars = 256): string {
    const buf = this.readBuffer(addr, maxChars * 2);
    let end = buf.length;
    for (let i = 0; i + 1 < buf.length; i += 2) {
      if (buf[i] === 0 && buf[i + 1] === 0) {
        end = i;
        break;
      }
    }
    return buf.subarray(0, end).toString('utf16le');
  }

  readUInt16(addr: number | bigint): number {
    return this.readBuffer(addr, 2).readUInt16LE(0);
  }
  readUInt8(addr: number | bigint): number {
    return this.readBuffer(addr, 1).readUInt8(0);
  }

  /**
   * Fault-tolerant read: returns a `size`-byte buffer; spans covering
   * inaccessible/uncommitted pages come back zeroed instead of throwing.
   * Throws ReadError only if the handle itself is invalid.
   */
  readSafe(addr: number | bigint, size: number): Buffer {
    this.assertOpen();
    checkAddr(addr);
    checkNumber(size, 'size');
    checkSize(size);
    try {
      return native.readSafe(this.#handle, Number(addr), size);
    } catch (e: any) {
      throw new ReadError(addr, e?.win32code);
    }
  }

  /** Read a flat struct by a shape of {name: [offset, type]}. */
  readStruct<
    T extends Record<string, [number, 'int32' | 'uint32' | 'float' | 'double']>,
  >(
    addr: number | bigint,
    shape: T,
  ): {
    [K in keyof T]: T[K][1] extends 'int64' | 'uint64' | 'pointer'
      ? bigint
      : number;
  } {
    const out: Record<string, number | bigint> = {};
    for (const [k, [off, type]] of Object.entries(shape)) {
      out[k] = this.readValueAt(Number(addr) + off, type);
    }
    return out as any;
  }

  readValueAt(addr: number | bigint, type: string): number | bigint {
    this.assertOpen();
    checkAddr(addr);
    checkStr(type, 'type');
    try {
      return native.readValue(this.#handle, Number(addr), type);
    } catch {
      throw new ReadError(addr);
    }
  }

  /** Follow a pointer chain: read pointer at `base`, then apply each offset. */
  resolvePointer(base: number | bigint, offsets: readonly number[]): bigint {
    let addr = this.readPointer(base);
    for (let i = 0; i < offsets.length - 1; i++) {
      addr = this.readPointer(addr + BigInt(offsets[i]!));
    }
    return addr + BigInt(offsets[offsets.length - 1] ?? 0);
  }

  #read<T extends number | bigint>(addr: number | bigint, type: string): T {
    this.assertOpen();
    checkAddr(addr);
    try {
      return native.readValue(this.#handle, Number(addr), type) as T;
    } catch {
      throw new ReadError(addr);
    }
  }

  // ---- writes ----
  writeInt32(addr: number | bigint, v: number): boolean {
    return this.#write(addr, 'int32', v);
  }
  writeUInt32(addr: number | bigint, v: number): boolean {
    return this.#write(addr, 'uint32', v);
  }
  writeInt64(addr: number | bigint, v: bigint): boolean {
    return this.#write(addr, 'int64', v);
  }
  writeUInt64(addr: number | bigint, v: bigint): boolean {
    return this.#write(addr, 'uint64', v);
  }
  writeFloat(addr: number | bigint, v: number): boolean {
    return this.#write(addr, 'float', v);
  }
  writeDouble(addr: number | bigint, v: number): boolean {
    return this.#write(addr, 'double', v);
  }
  writePointer(addr: number | bigint, v: bigint): boolean {
    return this.#write(addr, 'pointer', v);
  }
  writeUInt8(addr: number | bigint, v: number): boolean {
    return this.writeBuffer(addr, Buffer.from([v & 0xff]));
  }
  writeUInt16(addr: number | bigint, v: number): boolean {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v & 0xffff);
    return this.writeBuffer(addr, b);
  }

  /** Write raw bytes. */
  writeBuffer(addr: number | bigint, data: Buffer | Uint8Array): boolean {
    this.assertOpen();
    checkAddr(addr);
    if (!(data instanceof Uint8Array) && typeof data !== 'string')
      throw new TypeError('data must be a Buffer or Uint8Array');
    const ok = native.writeBuffer(
      this.#handle,
      Number(addr),
      Buffer.from(data),
    );
    if (!ok) throw new WriteError(addr);
    return ok;
  }

  #write(addr: number | bigint, type: string, v: number | bigint): boolean {
    this.assertOpen();
    checkAddr(addr);
    const ok = native.writeValue(this.#handle, Number(addr), type, v);
    if (!ok) throw new WriteError(addr);
    return ok;
  }

  // ---- modules / regions ----
  modules(): ModuleInfo[] {
    this.assertOpen();
    return native.getModules(this.#handle, this.pid);
  }
  module(name: string): ModuleInfo | undefined {
    const want = name.toLowerCase();
    return this.modules().find(
      (m) => m.path.split(/[\\/]/).pop()!.toLowerCase() === want,
    );
  }
  regions(): Region[] {
    this.assertOpen();
    return native.getRegions(this.#handle);
  }

  // ---- memory management ----
  /**
   * Allocate memory in the remote process. Returns base address (bigint).
   * `nearAddress` is passed to VirtualAllocEx as the lpAddress hint — used to
   * land allocations within ±2GB of a target (required for rel32 patches).
   */
  alloc(
    size: number,
    protection: number = Protection.PAGE_EXECUTE_READWRITE,
    nearAddress?: number | bigint,
  ): bigint {
    this.assertOpen();
    checkNumber(size, 'size');
    checkNumber(protection, 'protection');
    if (nearAddress !== undefined) checkAddr(nearAddress, 'nearAddress');
    return native.allocMemory(
      this.#handle,
      size,
      protection,
      nearAddress === undefined ? undefined : Number(nearAddress),
    );
  }
  /** Free remote memory allocated with {@link alloc}. */
  free(addr: number | bigint): boolean {
    this.assertOpen();
    checkAddr(addr);
    return native.freeMemory(this.#handle, Number(addr));
  }
  /** Change page protection. Returns previous protection. */
  protect(addr: number | bigint, size: number, protection: number): number {
    this.assertOpen();
    checkAddr(addr);
    checkNumber(size, 'size');
    checkNumber(protection, 'protection');
    return native.protectMemory(this.#handle, Number(addr), size, protection);
  }

  /** Write bytes that may live in a protected/code region: protect→write→restore→flush. */
  writeProtected(addr: number | bigint, data: Buffer | Uint8Array): boolean {
    this.assertOpen();
    const old = this.protect(
      addr,
      data.length,
      Protection.PAGE_EXECUTE_READWRITE,
    );
    try {
      return this.writeBuffer(addr, data);
    } finally {
      // Best-effort restore: a failure here must not mask the write's real
      // result. If it does fail the region stays RWX — warn so a weakening
      // doesn't pass silently.
      try {
        this.protect(addr, data.length, old);
        native.flushInstructions(this.#handle, Number(addr), data.length);
      } catch (e: any) {
        console.warn(
          `memoryprocess: failed to restore protection at 0x${BigInt(addr).toString(16)} — region left RWX:`,
          e?.message ?? e,
        );
      }
    }
  }
  /** NOP `len` bytes at `addr` (0x90). */
  nop(addr: number | bigint, len: number): boolean {
    return this.writeProtected(addr, Buffer.alloc(len, 0x90));
  }
  /** Write an E9 relative jump from `src` to `dst` (5 bytes). Throws when `dst` is outside rel32 range. */
  patchJump(src: number | bigint, dst: number | bigint): boolean {
    const rel = BigInt(dst) - (BigInt(src) + 5n);
    checkRel32(rel);
    const buf = Buffer.alloc(5);
    buf[0] = 0xe9;
    buf.writeInt32LE(Number(rel), 1);
    return this.writeProtected(src, buf);
  }
  /** Write an E8 relative call from `src` to `dst` (5 bytes). Throws when `dst` is outside rel32 range. */
  patchCall(src: number | bigint, dst: number | bigint): boolean {
    const rel = BigInt(dst) - (BigInt(src) + 5n);
    checkRel32(rel);
    const buf = Buffer.alloc(5);
    buf[0] = 0xe8;
    buf.writeInt32LE(Number(rel), 1);
    return this.writeProtected(src, buf);
  }

  // ---- disasm / hooks / shellcode ----

  /**
   * Instruction-length decode only — no mnemonics (not a full disassembler).
   * Uses the embedded HDE64 decoder on up to 4096 bytes read at `addr`.
   */
  disassemble(
    addr: number | bigint,
    count: number,
  ): { address: bigint; size: number; bytes: Buffer }[] {
    this.assertOpen();
    checkAddr(addr);
    checkNumber(count, 'count');
    const base = BigInt(addr);
    const raw = native.readBuffer(
      this.#handle,
      Number(addr),
      Math.min(count * 16, 4096),
    );
    const insns = native.disasmInstructions(this.#handle, Number(addr), count);
    return insns.map((i) => ({
      address: base + BigInt(i.offset),
      size: i.length,
      bytes: Buffer.from(raw.subarray(i.offset, i.offset + i.length)),
    }));
  }

  /**
   * Classic trampoline hook: steals whole instructions at `src` until >=5
   * bytes are covered, copies them to a remote stub ending in a jmp back to
   * `src+stolenLen`, then overwrites `src` with an E9 jmp to `dst` (padded
   * with 0xCC to stolenLen). Returns a {@link HookHandle} for {@link unhook}.
   */
  hook(src: number | bigint, dst: number | bigint): HookHandle {
    this.assertOpen();
    checkAddr(src, 'src');
    checkAddr(dst, 'dst');
    const s = BigInt(src),
      d = BigInt(dst);
    const insns = this.disassemble(s, 16);
    let stolenLen = 0;
    for (const i of insns) {
      stolenLen += i.size;
      if (stolenLen >= 5) break;
    }
    if (stolenLen < 5) throw new WriteError(s);
    const stolen = this.readBuffer(s, stolenLen);

    // The stub needs to reach `s` with a rel32 jmp-back, so it MUST land
    // within ±2GB of `src`. Hint VirtualAllocEx at candidate pages inside the
    // window; if the window is exhausted this throws rather than silently
    // writing a truncated rel32.
    const stub = this.#allocNear(
      s,
      stolenLen + 5,
      Protection.PAGE_EXECUTE_READWRITE,
    );
    try {
      const back = Buffer.alloc(stolenLen + 5);
      stolen.copy(back, 0);
      back[stolenLen] = 0xe9;
      const relBack = s + BigInt(stolenLen) - (stub + BigInt(stolenLen) + 5n);
      checkRel32(relBack);
      back.writeInt32LE(Number(relBack), stolenLen + 1);
      this.writeBuffer(stub, back);

      const patch = Buffer.alloc(stolenLen, 0xcc);
      patch[0] = 0xe9;
      const relDst = d - (s + 5n);
      checkRel32(relDst);
      patch.writeInt32LE(Number(relDst), 1);
      this.writeProtected(s, patch);
    } catch (e) {
      // Don't orphan an RWX page in the victim when the patch fails — free the
      // stub (best effort) and rethrow the original error.
      try {
        this.free(stub);
      } catch {
        /* victim may be gone */
      }
      throw e;
    }

    return { src: s, dst: d, stub, stolen };
  }

  /**
   * Allocate `size` bytes within rel32 range (±2GB) of `target` in the remote
   * process. Tries VirtualAllocEx hints on 64KB-spaced candidates below and
   * above the target; falls back to a non-hinted alloc (then range-checks).
   */
  #allocNear(target: bigint, size: number, protection: number): bigint {
    const WINDOW = 0x7fff0000n; // stay comfortably inside ±2GB
    const STEP = 0x10000n; // 64KB allocation granularity
    const lo = target > WINDOW ? target - WINDOW : 0x10000n;
    const hi =
      target + WINDOW < 0x7fffffffffffn ? target + WINDOW : 0x7fffffffffffn;
    // scan outward from the target — first hits are likeliest to be free
    for (const hint of [
      target,
      target - STEP,
      target + STEP,
      lo,
      lo + STEP,
      hi - STEP,
    ]) {
      if (hint < lo || hint > hi) continue;
      const q = this.queryAddress(hint);
      if (q !== null) continue; // occupied — pick a different candidate
      try {
        const p = this.alloc(size, protection, hint);
        if (p >= lo && p <= hi) return p;
        this.free(p);
      } catch {
        /* hint rejected — try next */
      }
    }
    // walk below the target in 64KB steps looking for a free gap
    for (let hint = target - STEP; hint >= lo; hint -= STEP) {
      if (this.queryAddress(hint) !== null) continue;
      try {
        const p = this.alloc(size, protection, hint);
        if (p >= lo && p <= hi) return p;
        this.free(p);
      } catch {
        /* keep walking */
      }
    }
    for (let hint = target + STEP; hint <= hi; hint += STEP) {
      if (this.queryAddress(hint) !== null) continue;
      try {
        const p = this.alloc(size, protection, hint);
        if (p >= lo && p <= hi) return p;
        this.free(p);
      } catch {
        /* keep walking */
      }
    }
    // last resort: unhinted — usually lands in low VA on fresh processes
    const p = this.alloc(size, protection);
    const rel = p - target;
    if (rel >= REL32_MIN && rel <= REL32_MAX) return p;
    this.free(p);
    throw new Error(
      `target out of rel32 range: could not allocate within ±2GB of 0x${target.toString(16)}`,
    );
  }

  /** Restore stolen bytes at `h.src` and free the stub. Returns combined ok. */
  unhook(h: HookHandle): boolean {
    this.assertOpen();
    const ok = this.writeProtected(h.src, h.stolen);
    const freed = this.free(h.stub);
    return ok && freed;
  }

  /**
   * Copy `bytes` into fresh RWX remote memory, run it on a remote thread
   * (lpParameter=`param`), wait up to `timeoutMs`, then free the memory.
   * Returns the thread exit code or null on failure/timeout.
   */
  execShellcode(
    bytes: Buffer | Uint8Array,
    param = 0,
    timeoutMs = 10000,
  ): number | null {
    this.assertOpen();
    const addr = this.alloc(bytes.length, Protection.PAGE_EXECUTE_READWRITE);
    try {
      this.writeBuffer(addr, bytes);
      return this.callRemote(addr, param, timeoutMs);
    } finally {
      this.free(addr);
    }
  }

  // ---- threads / info ----
  /** Is this a 32-bit process under WOW64 (relevant to pointer width). */
  get isWow64(): boolean {
    this.assertOpen();
    return native.isWow64(this.#handle);
  }
  /** Pointer size in bytes for this process. */
  get pointerSize(): number {
    return this.isWow64 ? 4 : 8;
  }
  /** Thread IDs owned by this process. */
  threads(): number[] {
    this.assertOpen();
    return native.listThreads(this.pid);
  }
  /**
   * First thread reported by the Toolhelp snapshot for this process — in
   * practice the main/owner thread for typical targets. Returns null when the
   * process has no threads.
   */
  get mainThread(): number | null {
    this.assertOpen();
    return this.threads()[0] ?? null;
  }
  /** Suspend a thread by id. */
  suspendThread(tid: number): boolean {
    this.assertOpen();
    checkNumber(tid, 'tid');
    return native.suspendThread(tid);
  }
  /** Resume a thread by id. */
  resumeThread(tid: number): boolean {
    this.assertOpen();
    checkNumber(tid, 'tid');
    return native.resumeThread(tid);
  }
  /** Suspend all threads of this process (for atomic patching). */
  suspendAll(): number[] {
    const t = this.threads();
    t.forEach((id) => this.suspendThread(id));
    return t;
  }
  /** Resume all threads of this process. */
  resumeAll(): void {
    this.threads().forEach((id) => this.resumeThread(id));
  }
  /**
   * Suspend the whole process atomically via NtSuspendProcess — preferred over
   * {@link suspendAll} which races with new-thread creation. Pair with
   * {@link resumeProcess}.
   */
  suspendProcess(): boolean {
    this.assertOpen();
    return native.suspendProcess(this.pid);
  }
  /** Resume a process suspended by {@link suspendProcess}. */
  resumeProcess(): boolean {
    this.assertOpen();
    return native.resumeProcess(this.pid);
  }
  /**
   * Wait for the process to exit. Resolves the exit code, or null on timeout.
   * Pass no timeoutMs to wait indefinitely.
   */
  waitForExit(timeoutMs?: number): Promise<number | null> {
    this.assertOpen();
    return native.waitForExit(this.pid, timeoutMs);
  }
  /**
   * Grant the CALLING process SeDebugPrivilege so it can open
   * protected/system processes. Returns false when the token can't hold the
   * privilege (e.g. not elevated).
   */
  static enableDebugPrivilege(): boolean {
    return native.enableDebugPrivilege();
  }

  // ---- tier-3: query / context / remote call ----

  /**
   * VirtualQueryEx on a single address. Returns region info including
   * `allocationBase` and `state` (MEM_COMMIT 0x1000 / MEM_RESERVE 0x2000 /
   * MEM_FREE 0x10000), or null when the address is invalid/unmapped.
   */
  queryAddress(
    addr: number | bigint,
  ): (Region & { allocationBase: number; state: number }) | null {
    this.assertOpen();
    checkAddr(addr);
    return native.queryAddress(this.#handle, Number(addr));
  }

  /**
   * Full thread context (x64) including debug registers.
   * Suspend the thread first ({@link suspendThread}) for a stable snapshot.
   * Returns null if the thread cannot be opened.
   */
  getThreadContext(tid: number): ThreadContext | null {
    this.assertOpen();
    checkNumber(tid, 'tid');
    return native.getThreadContext(tid);
  }

  /**
   * Patch selected context fields and write the context back.
   * Suspend the thread first. Accepted fields: rip, rsp, rbp, dr0..dr3, dr7,
   * eflags (number|bigint).
   */
  setThreadContext(
    tid: number,
    ctx: Partial<Record<keyof ThreadContext, number | bigint>>,
  ): boolean {
    this.assertOpen();
    checkNumber(tid, 'tid');
    if (ctx === null || typeof ctx !== 'object')
      throw new TypeError('ctx must be an object');
    return native.setThreadContext(tid, ctx);
  }

  /**
   * Execute `fnAddr` on a new remote thread with `param` as lpParameter and
   * wait up to `timeoutMs` for it to exit. Returns the thread exit code, or
   * null on failure/timeout.
   */
  callRemote(
    fnAddr: bigint | number,
    param = 0,
    timeoutMs = 10000,
  ): number | null {
    this.assertOpen();
    checkAddr(fnAddr, 'fnAddr');
    return native.callRemote(this.pid, fnAddr, param, timeoutMs);
  }

  // ---- tier-3: hardware breakpoints ----

  /**
   * Arm a hardware breakpoint in Dr{slot} (0-3) on thread `tid`.
   * `kind`: 'exec' (RW=00, the default) | 'write' (RW=01, data writes) |
   * 'readwrite' (RW=11, data reads+writes). LEN encodes `size` (1|2|4|8);
   * for 'exec' the CPU requires LEN=00 (ignored otherwise).
   * Suspend the thread first, then resume with {@link resumeThread}.
   *
   * WARNING: without a debugger attached to the target, a fired hardware
   * breakpoint delivers an unhandled #DB and usually crashes it. Use
   * {@link findWhatWrites} (which owns the debug session) for write hits.
   */
  hwBreakpoint(
    tid: number,
    addr: bigint | number,
    slot: 0 | 1 | 2 | 3,
    size: 1 | 2 | 4 | 8 = 1,
    kind: 'exec' | 'write' | 'readwrite' = 'exec',
  ): boolean {
    this.assertOpen();
    if (!Number.isInteger(slot) || slot < 0 || slot > 3)
      throw new RangeError('slot must be 0..3');
    if (size !== 1 && size !== 2 && size !== 4 && size !== 8)
      throw new RangeError('size must be 1|2|4|8');
    const rwBits =
      kind === 'exec'
        ? 0n
        : kind === 'write'
          ? 1n
          : kind === 'readwrite'
            ? 3n
            : (() => {
                throw new TypeError(`unknown breakpoint kind ${kind}`);
              })();
    const ctx = this.getThreadContext(tid);
    if (!ctx) return false;
    // Intel Dr7 LEN encoding: 00=1 byte, 01=2, 11=4, 10=8 (exec forces 00)
    const lenBits =
      kind === 'exec'
        ? 0n
        : size === 1
          ? 0n
          : size === 2
            ? 1n
            : size === 4
              ? 3n
              : 2n;
    const shift = BigInt(16 + slot * 4);
    let dr7 = ctx.dr7;
    dr7 &= ~(0xfn << shift); // clear RW+LEN for this slot
    dr7 |= (rwBits | (lenBits << 2n)) << shift;
    dr7 |= 1n << BigInt(slot * 2); // local enable L{slot}
    const patch: Record<string, bigint> = { dr7 };
    patch[`dr${slot}`] = BigInt(addr);
    return this.setThreadContext(tid, patch);
  }

  /** Clear Dr{slot} (address + enable/RW/LEN bits in Dr7) on thread `tid`. */
  clearHwBreakpoint(tid: number, slot: 0 | 1 | 2 | 3): boolean {
    this.assertOpen();
    if (!Number.isInteger(slot) || slot < 0 || slot > 3)
      throw new RangeError('slot must be 0..3');
    const ctx = this.getThreadContext(tid);
    if (!ctx) return false;
    const shift = BigInt(16 + slot * 4);
    let dr7 = ctx.dr7;
    dr7 &= ~(0xfn << shift);
    dr7 &= ~(3n << BigInt(slot * 2)); // clear local+global enable
    const patch: Record<string, bigint> = { dr7 };
    patch[`dr${slot}`] = 0n;
    return this.setThreadContext(tid, patch);
  }

  /**
   * Cheat Engine "find what writes to this address": attaches a temporary
   * debugger (DebugActiveProcess), arms a hardware WRITE breakpoint (Dr7
   * RW=01) on every thread, pumps the debug event loop for `timeoutMs`
   * collecting EXCEPTION_SINGLE_STEP hits, then restores debug registers and
   * detaches — the target is left running and un-debugged.
   *
   * Returns up to `maxHits` records. `rip` is the address reported by the
   * CPU; because a data breakpoint is a *trap* it fires AFTER the write, so
   * `rip` points at the instruction FOLLOWING the write (same caveat CE has).
   * `threadContext` is the full register snapshot at the hit (incl. dr6).
   *
   * Requires permission to debug the target — call
   * {@link Process.enableDebugPrivilege} first (needed even for your own
   * children on some systems; win32 5 otherwise).
   */
  findWhatWrites(
    addr: bigint | number,
    opts: {
      /** breakpoint width in bytes (default 4; must be 1|2|4|8) */
      size?: 1 | 2 | 4 | 8;
      /** how long to watch, ms (default 1000, max 60000) */
      timeoutMs?: number;
      /** stop after this many hits (default 32, max 1024) */
      maxHits?: number;
    } = {},
  ): Promise<{ rip: bigint; tid: number; threadContext: ThreadContext }[]> {
    this.assertOpen();
    checkAddr(addr);
    const size = opts.size ?? 4;
    if (size !== 1 && size !== 2 && size !== 4 && size !== 8)
      throw new RangeError('size must be 1|2|4|8');
    const timeoutMs = opts.timeoutMs ?? 1000;
    const maxHits = opts.maxHits ?? 32;
    return native.findWhatWrites(
      this.pid,
      addr,
      size,
      timeoutMs,
      maxHits,
    ) as Promise<{ rip: bigint; tid: number; threadContext: ThreadContext }[]>;
  }

  // ---- tier-3: code cave ----

  /**
   * Find the first run of >= minLen consecutive 0x00 or 0xCC bytes inside
   * committed, executable regions. When `opts.module` is set the search is
   * bounded to that module; `opts.start`/`opts.end` bound it explicitly.
   * Returns the cave address or null.
   */
  findCodeCave(
    minLen: number,
    opts: {
      module?: string;
      start?: number | bigint;
      end?: number | bigint;
    } = {},
  ): bigint | null {
    this.assertOpen();
    if (!Number.isFinite(minLen) || minLen < 1) return null;
    const EXEC =
      Protection.PAGE_EXECUTE |
      Protection.PAGE_EXECUTE_READ |
      Protection.PAGE_EXECUTE_READWRITE |
      Protection.PAGE_EXECUTE_WRITECOPY;
    const MEM_COMMIT = 0x1000;

    let lo = opts.start !== undefined ? BigInt(opts.start) : 0n;
    let hi = opts.end !== undefined ? BigInt(opts.end) : 0x7fffffffffffffn;
    if (opts.module) {
      const m = this.module(opts.module);
      if (!m) return null;
      lo = BigInt(m.base);
      hi = BigInt(m.base + m.size);
    }

    for (const r of this.regions()) {
      if ((r.protection & EXEC) === 0) continue;
      const rLo = BigInt(r.baseAddress),
        rHi = rLo + BigInt(r.size);
      const s = rLo > lo ? rLo : lo,
        e = rHi < hi ? rHi : hi;
      if (s >= e) continue;
      const q = this.queryAddress(s);
      if (!q || q.state !== MEM_COMMIT) {
        // regions() only returns committed allocations in practice, but confirm
        if (!q) continue;
      }
      const buf = this.readSafe(s, Number(e - s));
      let run = 0;
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i]!;
        if (b === 0x00 || b === 0xcc) {
          if (++run >= minLen) return s + BigInt(i - run + 1);
        } else run = 0;
      }
    }
    return null;
  }

  // ---- tier-3: exports / strings / arrays / misc ----

  /**
   * Resolve an exported symbol in a remote module by parsing its PE export
   * table via remote reads. Returns the absolute address or null.
   */
  resolveExport(moduleName: string, exportName: string): bigint | null {
    this.assertOpen();
    return this.#resolveExportImpl(moduleName, exportName, 0);
  }

  #resolveExportImpl(
    moduleName: string,
    exportName: string,
    depth: number,
  ): bigint | null {
    if (depth > 4) return null; // chained-forwarder cycle guard
    const m = this.module(moduleName);
    if (!m) return null;
    const base = BigInt(m.base);
    try {
      const hdr = this.readSafe(base, 0x1000);
      if (hdr.readUInt16LE(0) !== 0x5a4d) return null; // MZ
      const peOff = hdr.readUInt32LE(0x3c);
      const nt = this.readSafe(base + BigInt(peOff), 0x400);
      if (nt.readUInt32LE(0) !== 0x4550) return null; // PE\0\0
      const magic = nt.readUInt16LE(0x18);
      const ddBase = magic === 0x20b ? 0x88 : 0x78; // optional-header data dir offset
      const expRva = nt.readUInt32LE(ddBase);
      const expSize = nt.readUInt32LE(ddBase + 4);
      if (!expRva) return null;
      const exp = this.readSafe(base + BigInt(expRva), 0x28);
      const nNames = exp.readUInt32LE(0x18);
      const nFuncs = exp.readUInt32LE(0x14);
      const namesRva = exp.readUInt32LE(0x20);
      const ordsRva = exp.readUInt32LE(0x24);
      const funcsRva = exp.readUInt32LE(0x1c);
      if (nNames > 0x100000 || nFuncs > 0x100000) return null; // corrupt PE guard
      const names = this.readSafe(base + BigInt(namesRva), nNames * 4);
      for (let i = 0; i < nNames; i++) {
        const nameRva = names.readUInt32LE(i * 4);
        let name: string;
        try {
          name = this.readString(base + BigInt(nameRva), 256);
        } catch {
          continue;
        } // one bad name RVA mustn't kill the whole walk
        if (name !== exportName) continue;
        const ord = this.readSafe(
          base + BigInt(ordsRva) + BigInt(i * 2),
          2,
        ).readUInt16LE(0);
        if (ord >= nFuncs) return null;
        const fnRva = this.readSafe(
          base + BigInt(funcsRva) + BigInt(ord * 4),
          4,
        ).readUInt32LE(0);
        // Forwarder: RVA points INSIDE the export directory → it's an ASCII
        // "DLLNAME.ExportName" string (common for kernel32→KernelBase stubs).
        if (fnRva >= expRva && fnRva < expRva + expSize) {
          const fwd = this.readString(base + BigInt(fnRva), 256);
          const dot = fwd.indexOf('.');
          if (dot <= 0) return null;
          const dll = fwd.slice(0, dot).toLowerCase();
          const fn = fwd.slice(dot + 1);
          const target = /\.dll$/i.test(dll) ? dll : `${dll}.dll`;
          return this.#resolveExportImpl(target, fn, depth + 1);
        }
        return base + BigInt(fnRva);
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Write `str` (encoded, default utf8) plus a NUL terminator at `addr`. */
  writeString(
    addr: number | bigint,
    str: string,
    encoding: 'utf8' | 'ascii' = 'utf8',
  ): boolean {
    return this.writeBuffer(
      addr,
      Buffer.concat([Buffer.from(str, encoding), Buffer.from([0])]),
    );
  }

  /** Write `str` as UTF-16LE plus a 00 00 terminator at `addr`. */
  writeWideString(addr: number | bigint, str: string): boolean {
    return this.writeBuffer(
      addr,
      Buffer.concat([Buffer.from(str, 'utf16le'), Buffer.from([0, 0])]),
    );
  }

  /**
   * Read `count` contiguous values of `type` in a single read.
   * Returns number[] for int32/uint32, Float32Array for 'float',
   * Float64Array for 'double'.
   */
  readArray(
    addr: number | bigint,
    type: 'int32' | 'uint32' | 'float' | 'double',
    count: number,
  ): number[] | Float32Array | Float64Array {
    const width = type === 'double' ? 8 : 4;
    const buf = this.readBuffer(addr, count * width);
    const aligned = buf.buffer.slice(
      buf.byteOffset,
      buf.byteOffset + buf.byteLength,
    );
    switch (type) {
      case 'int32':
        return Array.from(new Int32Array(aligned, 0, count));
      case 'uint32':
        return Array.from(new Uint32Array(aligned, 0, count));
      case 'float':
        return new Float32Array(aligned, 0, count);
      case 'double':
        return new Float64Array(aligned, 0, count);
    }
  }

  /** Module (from {@link modules}) whose [base, base+size) contains `addr`. */
  moduleFromAddress(addr: number | bigint): ModuleInfo | null {
    this.assertOpen();
    const a = BigInt(addr);
    return (
      this.modules().find(
        (m) => a >= BigInt(m.base) && a < BigInt(m.base + m.size),
      ) ?? null
    );
  }

  /**
   * Dump a loaded module's committed image (readSafe) to `outPath`.
   * Returns `outPath` on success.
   */
  dumpModule(name: string, outPath: string): string {
    this.assertOpen();
    const m = this.module(name);
    if (!m) throw new ReadError(0n);
    const buf = this.readSafe(m.base, m.size);
    writeFileSync(outPath, buf);
    return outPath;
  }

  // ---- helpers ----
  /** Resolve a RIP-relative address: `hit + offset + 4 + rel32` (x64 mov/movaps sigs). */
  resolveRIPRelative(hitAddr: number | bigint, offset = 3): bigint {
    const rel = this.readInt32(BigInt(hitAddr) + BigInt(offset));
    return BigInt(hitAddr) + BigInt(offset) + 4n + BigInt(rel);
  }
  /** Read a whole region once into a buffer and expose offset accessors (bulk-read perf). */
  readRegion(addr: number | bigint, size: number): RegionView {
    const buf = this.readBuffer(addr, size);
    return new RegionView(buf, BigInt(addr));
  }

  // ---- pattern scan (async) ----
  async scan(pattern: string, opts: ScanOptions = {}): Promise<bigint[]> {
    this.assertOpen();
    checkStr(pattern, 'pattern');
    let start = toNum(opts.start);
    let end = toNum(opts.end);
    if (opts.module) {
      const m = this.module(opts.module);
      if (!m) return []; // module not loaded — never silently scan all of VA
      start = m.base;
      end = m.base + m.size;
      if (opts.section) {
        const sec = this.#sectionRange(BigInt(m.base), opts.section);
        if (!sec) return []; // module has no such section
        start = sec[0];
        end = sec[1];
      }
    }
    return native.scan(this.pid, pattern, {
      start,
      end,
      onlyReadable: opts.onlyReadable ?? true,
    });
  }

  /**
   * Parse a module's PE section headers remotely and return [start, end) for
   * the section named `name` (e.g. '.text'), or null. Virtual addresses.
   */
  #sectionRange(base: bigint, name: string): [number, number] | null {
    try {
      const hdr = this.readSafe(base, 0x1000);
      if (hdr.readUInt16LE(0) !== 0x5a4d) return null;
      const peOff = hdr.readUInt32LE(0x3c);
      const nt = this.readSafe(base + BigInt(peOff), 0x400);
      if (nt.readUInt32LE(0) !== 0x4550) return null;
      const optSize = nt.readUInt16LE(0x14); // SizeOfOptionalHeader
      const nSections = nt.readUInt16LE(0x6);
      const sectionsOff = 0x18 + optSize;
      const secs = this.readSafe(
        base + BigInt(peOff + sectionsOff),
        nSections * 40,
      );
      const want = name.toLowerCase();
      for (let i = 0; i < nSections; i++) {
        const sName = secs
          .subarray(i * 40, i * 40 + 8)
          .toString('ascii')
          .replace(/\0.*$/, '')
          .toLowerCase();
        if (sName === want) {
          const vsize = secs.readUInt32LE(i * 40 + 8);
          const va = secs.readUInt32LE(i * 40 + 12);
          const raw = secs.readUInt32LE(i * 40 + 16);
          const sz = vsize || raw;
          const start = base + BigInt(va);
          return [Number(start), Number(start + BigInt(sz))];
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Cheat-Engine-style typed value scan: find all (aligned) little-endian
   * occurrences of `value` in committed memory. Default scans writable
   * regions only — pass `onlyWritable: false` to include read-only data.
   */
  async scanValue(
    value: number | bigint,
    opts: ScanValueOptions = {},
  ): Promise<bigint[]> {
    this.assertOpen();
    const type = opts.type ?? 'int32';
    if (!VALID_SCAN_TYPES.includes(type))
      throw new TypeError(
        `invalid scanValue type ${type} — use one of ${VALID_SCAN_TYPES.join('/')}`,
      );
    const needle = encodeValue(type, value);
    let start = toNum(opts.start);
    let end = toNum(opts.end);
    if (opts.module) {
      const m = this.module(opts.module);
      if (!m) return []; // module not loaded — never silently scan all of VA
      start = m.base;
      end = m.base + m.size;
    }
    return native.scanValue(this.pid, needle, {
      start,
      end,
      onlyWritable: opts.onlyWritable ?? true,
      alignment: opts.alignment ?? VALUE_WIDTHS[type],
    });
  }

  /**
   * Refine a previous scan (CE "next scan"): re-reads each hit and keeps only
   * addresses whose current value still equals `value` (or falls inside
   * `opts.range = [lo, hi]` — CE "value between"). Reads are batched one
   * readSafe per 4KB page group, so it's fast on large hit lists.
   */
  async nextScan(
    hits: readonly bigint[],
    value: number | bigint,
    opts: {
      type?: ScanValueType;
      range?: [number | bigint, number | bigint];
    } = {},
  ): Promise<bigint[]> {
    this.assertOpen();
    if (hits.length === 0) return [];
    const type = opts.type ?? 'int32';
    if (!VALID_SCAN_TYPES.includes(type))
      throw new TypeError(
        `invalid nextScan type ${type} — use one of ${VALID_SCAN_TYPES.join('/')}`,
      );
    const width = VALUE_WIDTHS[type];
    const PAGE = 0x1000n;

    // group hits by 4KB page
    const byPage = new Map<bigint, { hit: bigint; off: number }[]>();
    for (const h of hits) {
      const page = BigInt(h) / PAGE;
      const off = Number(BigInt(h) % PAGE);
      let g = byPage.get(page);
      if (!g) {
        g = [];
        byPage.set(page, g);
      }
      g.push({ hit: BigInt(h), off });
    }

    const isFloat = type === 'float' || type === 'double';
    const matches = (v: number | bigint): boolean => {
      if (opts.range) {
        const [lo, hi] = opts.range;
        if (isFloat) return Number(v) >= Number(lo) && Number(v) <= Number(hi);
        return BigInt(v) >= BigInt(lo) && BigInt(v) <= BigInt(hi);
      }
      if (isFloat) return Math.abs(Number(v) - Number(value)) < 1e-6;
      return BigInt(v) === BigInt(value);
    };

    const out: bigint[] = [];
    const pages = [...byPage.entries()];
    const BATCH = 64;
    for (let i = 0; i < pages.length; i += BATCH) {
      const slice = pages.slice(i, i + BATCH);
      const bufs = await Promise.all(
        slice.map(([page]) =>
          Promise.resolve().then(() => {
            // Overlap the page read by `width` bytes so a value straddling the
            // page boundary (possible with alignment:1) is still re-checked.
            try {
              return this.readSafe(page * PAGE, 0x1000 + width);
            } catch {
              return null;
            }
          }),
        ),
      );
      for (let j = 0; j < slice.length; j++) {
        const buf = bufs[j];
        if (!buf) continue;
        for (const { hit, off } of slice[j]![1]) {
          if (off + width > buf.length) continue;
          try {
            if (matches(decodeValue(buf, off, type))) out.push(hit);
          } catch {
            /* unreadable tail */
          }
        }
      }
      // yield to the event loop so huge hit lists don't starve timers
      if (i + BATCH < pages.length) await Promise.resolve();
    }
    return out;
  }

  /**
   * Freeze a remote value: writes `value` at `addr` every `intervalMs`.
   * Returns an unfreeze function. Write failures are ignored (target may
   * exit); call the returned function (or close()) to stop.
   */
  freeze(
    addr: number | bigint,
    type: ScanValueType,
    value: number | bigint,
    intervalMs = 50,
  ): () => void {
    this.assertOpen();
    checkAddr(addr);
    if (!(type in VALUE_WIDTHS)) throw new TypeError(`unknown type ${type}`);
    const stop = () => {
      clearInterval(timer);
      this.#timers.delete(timer);
    };
    const timer = setInterval(() => {
      if (!this.#handle) {
        stop();
        return;
      } // self-clear after close()
      try {
        native.writeValue(
          this.#handle,
          Number(addr),
          type,
          type === 'int64' || type === 'uint64' ? BigInt(value) : value,
        );
      } catch {
        /* closed or unwritable — ignore */
      }
    }, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
    this.#timers.add(timer);
    return stop;
  }

  /** First match for `pattern`, or null when nothing matches. */
  async scanFirst(
    pattern: string,
    opts: ScanOptions = {},
  ): Promise<bigint | null> {
    const hits = await this.scan(pattern, opts);
    return hits.length ? hits[0]! : null;
  }

  /** Exactly-one-match scan. Throws ScanError when 0 or >1 hits. */
  async scanUnique(pattern: string, opts: ScanOptions = {}): Promise<bigint> {
    const hits = await this.scan(pattern, opts);
    if (hits.length !== 1) throw new ScanError(hits.length, pattern);
    return hits[0]!;
  }

  // ---- dll injection ----
  /**
   * Inject `absolutePath` (a DLL) into this process via LoadLibraryA on a remote
   * thread. Re-opens the process internally with the required rights.
   * Throws InjectError on failure.
   */
  injectDll(absolutePath: string): boolean {
    this.assertOpen();
    checkStr(absolutePath, 'dllPath');
    try {
      return native.injectDll(this.pid, absolutePath);
    } catch (e: any) {
      throw new InjectError(e?.message ?? 'unknown', e?.win32code);
    }
  }

  /**
   * Eject a loaded module via FreeLibrary on a remote thread. Accepts a
   * ModuleInfo or a substring matched (case-insensitive) against module names.
   * Throws InjectError on failure / no match.
   */
  ejectDll(module: ModuleInfo | string): boolean {
    this.assertOpen();
    let base: number | undefined;
    if (typeof module === 'string') {
      const want = module.toLowerCase();
      const m = this.modules().find((m) => {
        const name = m.path.split(/[\\/]/).pop()!.toLowerCase();
        return name.includes(want);
      });
      if (!m) throw new InjectError(`module not found: ${module}`);
      base = m.base;
    } else {
      base = module.base;
    }
    try {
      return native.ejectDll(this.pid, base);
    } catch (e: any) {
      throw new InjectError(e?.message ?? 'unknown', e?.win32code);
    }
  }

  // ---- watch ----
  /**
   * Poll `readInt32` at `addr` every `intervalMs`; invoke `cb(newVal, oldVal)`
   * on change. Returns an unsubscribe function. Read failures are ignored
   * (the target may exit or the page may become inaccessible).
   */
  watch(
    addr: number | bigint,
    cb: (newVal: number, oldVal: number) => void,
    intervalMs = 50,
  ): () => void {
    this.assertOpen();
    let prev: number | undefined;
    try {
      prev = this.readInt32(addr);
    } catch {
      /* start uninitialized */
    }
    const stop = () => {
      clearInterval(timer);
      this.#timers.delete(timer);
    };
    const timer = setInterval(() => {
      if (!this.#handle) {
        stop();
        return;
      } // self-clear after close()
      let cur: number;
      try {
        cur = this.readInt32(addr);
      } catch {
        return;
      }
      if (prev === undefined || cur !== prev) {
        const old = prev;
        prev = cur;
        if (old !== undefined) {
          // Swallow callback exceptions — a throwing user cb inside a
          // setInterval must not crash the process or spam unhandled errors.
          try {
            cb(cur, old);
          } catch {
            /* user callback fault */
          }
        }
      }
    }, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
    this.#timers.add(timer);
    return stop;
  }

  /** Close the process handle. Idempotent; also stops freeze()/watch() timers. */
  close(): void {
    for (const t of this.#timers) clearInterval(t);
    this.#timers.clear();
    if (this.#handle) {
      native.closeHandle(this.#handle);
      this.#handle = 0;
    }
  }

  // ---- high-level cheat-dev helpers ----

  /**
   * Fluent pointer-chain address. **Canonical form:**
   * `addr('module', rva, ...offsets)` — the module name, then the RVA added
   * to its base, then the pointer chain (all-but-last dereference):
   * ```ts
   * proc.addr('game.exe', 0x1F2A3C, 0x10, 0x28, 0x8).readInt32()
   * ```
   * Equivalent accepted forms:
   * ```ts
   * proc.addr('game.exe+0x1F2A3C', 0x10, 0x28, 0x8)  // CE paste-friendly
   * proc.addr(mod.base + 0x1F2A3Cn, 0x10, 0x28, 0x8) // raw bigint base
   * ```
   * In the `'mod+rva'` / bigint forms every `chain` offset is a deref hop —
   * the rva is already in the base. Writing `addr('mod+0x100', 0x100, ...)`
   * (rva repeated as chain[0]) throws `AMBIGUOUS_ADDRESS_EXPR`; pass the
   * numeric base if that deref is truly intended.
   */
  addr(base: number | bigint | string, ...chain: number[]): Address {
    return new Address(this, base, chain);
  }

  /**
   * Named pointer-chain table — a CE-style address list. **Canonical entry
   * form:** `['module', rva, ...offsets]`. `base` may also be a bigint, a
   * `"module+rva"` string, or a raw address — same rules as {@link addr}.
   * Returns a typed map of {@link Address} objects, so chains are defined
   * once and read/written by name:
   * ```ts
   * const p = proc.pointers({
   *   health: ['game.exe', 0x1F2A3C, 0x10, 0x28, 0x8],
   *   mana:   ['game.exe', 0x1F2A3C, 0x18, 0x30],
   *   money:  ['game.exe+0x2B4D80', 0x8],   // CE-string form also fine
   *   raw:    [bigBase, 0x10],              // raw bigint base
   * });
   * p.health.readInt32();   // 87
   * p.mana.writeInt32(999);
   * ```
   * Entries resolve lazily — nothing touches memory until a `.read`/`.resolve`.
   */
  pointers<
    T extends Record<
      string,
      readonly [base: number | bigint | string, ...chain: number[]]
    >,
  >(defs: T): { [K in keyof T]: Address } {
    const out: Record<string, Address> = {};
    for (const [name, def] of Object.entries(defs)) {
      if (!Array.isArray(def) || def.length === 0)
        throw new TypeError(
          `pointers() def "${name}" must be [base, ...offsets]`,
        );
      const [base, ...chain] = def as readonly [
        number | bigint | string,
        ...number[],
      ];
      out[name] = new Address(this, base, chain);
    }
    return out as { [K in keyof T]: Address };
  }

  /**
   * Typed view over a region. `snapshot()` does ONE `readBuffer` covering the
   * whole schema and decodes every field locally — cheap per-frame read for
   * ESP/aimbot loops. `read(name)`/`write(name, v)` hit live memory.
   */
  entity(addr: number | bigint, schema: EntitySchema): Entity {
    return new Entity(this, BigInt(addr), schema);
  }

  /**
   * Iterate an entity list — array-stride (`stride`) or linked-list (`next`).
   * Yields addresses, or {@link Entity} views when `schema` is given.
   */
  entityList(opts: EntityListOptions): EntityList {
    return new EntityList(this, opts);
  }

  /**
   * Batch-read many typed values. Groups requests by 4KB page and does ONE
   * `readSafe` per page — 10-50× fewer N-API crossings than per-address reads.
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
    return readManyImpl(this, reqs);
  }

  /**
   * Shallow "who points at this" scan — find every aligned location storing
   * a pointer to `target` (a lightweight CE pointer-scan). Async.
   */
  findPointersTo(
    target: number | bigint,
    opts: {
      module?: string;
      start?: number | bigint;
      end?: number | bigint;
      onlyWritable?: boolean;
      alignment?: number;
    } = {},
  ): Promise<bigint[]> {
    return findPointersToImpl(this, target, opts);
  }

  /** Parse a sig/offset database (cs2-dumper or hazedumper) bound to this proc. */
  offsets(json: string | OffsetsJson): Offsets {
    return Offsets.of(this, json);
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

/** A read-once-index-locally view over a region buffer. */
export class RegionView {
  constructor(
    private buf: Buffer,
    readonly base: bigint,
  ) {}
  get size() {
    return this.buf.length;
  }
  int32At(off: number) {
    return this.buf.readInt32LE(off);
  }
  uint32At(off: number) {
    return this.buf.readUInt32LE(off);
  }
  floatAt(off: number) {
    return this.buf.readFloatLE(off);
  }
  doubleAt(off: number) {
    return this.buf.readDoubleLE(off);
  }
  ptrAt(off: number) {
    return this.buf.readBigUInt64LE(off);
  }
  stringAt(off: number, max = 256) {
    const end = this.buf.indexOf(0, off);
    return this.buf
      .subarray(off, end === -1 ? off + max : Math.min(end, off + max))
      .toString('utf8');
  }
  bytes(off: number, len: number) {
    return this.buf.subarray(off, off + len);
  }
}
