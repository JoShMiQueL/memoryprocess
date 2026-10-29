import { native } from './native.js'
import { ProcessNotFoundError, AccessDeniedError, ReadError, WriteError, ScanError, InjectError } from './errors.js'

export interface ProcessInfo { pid: number; name: string }
export interface ModuleInfo { base: number; size: number; path: string }
export interface Region { baseAddress: number; size: number; protection: number; type: number }

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
} as const

export const AllocationType = {
  MEM_COMMIT: 0x1000,
  MEM_RESERVE: 0x2000,
  MEM_TOP_DOWN: 0x100000,
} as const

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
} as const

export interface ScanOptions {
  /** start address (default 0) */
  start?: number | bigint
  /** end address (default: top of user space) */
  end?: number | bigint
  /** restrict to a module's range */
  module?: string
  /** only scan readable regions (default true) */
  onlyReadable?: boolean
}

const toNum = (v: number | bigint | undefined) => (v === undefined ? undefined : Number(v))

export class Process implements Disposable {
  #handle: number
  readonly pid: number

  private constructor(handle: number, pid: number) {
    this.#handle = handle
    this.pid = pid
  }

  /**
   * Open a process by name ("notepad.exe") or pid.
   * Default access is least-privilege VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION.
   * Pass `{ access }` (or a raw access number) to override.
   * Throws ProcessNotFoundError / AccessDeniedError.
   */
  static open(nameOrPid: string | number, opts?: { access?: number } | number): Process {
    const access = typeof opts === 'number' ? opts : opts?.access
    try {
      const { handle, pid } = native.openProcess(nameOrPid, access)
      return new Process(handle, pid)
    } catch (e: any) {
      if (e?.code === 'PROCESS_NOT_FOUND') throw new ProcessNotFoundError(nameOrPid)
      if (e?.code === 'ACCESS_DENIED' || e?.win32code === 5) throw new AccessDeniedError(typeof nameOrPid === 'number' ? nameOrPid : -1)
      throw e
    }
  }

  /** Open with read-only access (VM_READ|QUERY_INFORMATION). */
  static openReadOnly(nameOrPid: string | number): Process {
    return Process.open(nameOrPid, { access: ProcessAccess.VM_READ | ProcessAccess.QUERY_INFORMATION })
  }

  /** List running processes without opening a handle. */
  static list(): ProcessInfo[] {
    return native.listProcesses()
  }

  /** Find first process by name (case-insensitive). */
  static find(name: string): ProcessInfo | undefined {
    const want = name.toLowerCase()
    return native.listProcesses().find(p => p.name.toLowerCase() === want || p.name.toLowerCase() === `${want}.exe`)
  }

  get handle(): number { return this.#handle }

  private assertOpen() {
    if (!this.#handle) throw new Error('Process handle is closed')
  }

  // ---- reads ----
  readInt32(addr: number | bigint): number { return this.#read<number>(addr, 'int32') }
  readUInt32(addr: number | bigint): number { return this.#read<number>(addr, 'uint32') }
  readInt64(addr: number | bigint): bigint { return this.#read<bigint>(addr, 'int64') }
  readUInt64(addr: number | bigint): bigint { return this.#read<bigint>(addr, 'uint64') }
  readFloat(addr: number | bigint): number { return this.#read<number>(addr, 'float') }
  readDouble(addr: number | bigint): number { return this.#read<number>(addr, 'double') }
  readPointer(addr: number | bigint): bigint { return this.#read<bigint>(addr, 'pointer') }

  readBuffer(addr: number | bigint, size: number): Buffer {
    this.assertOpen()
    try { return native.readBuffer(this.#handle, Number(addr), size) }
    catch { throw new ReadError(addr) }
  }

  readString(addr: number | bigint, max = 256, encoding: 'utf8' | 'ascii' = 'utf8'): string {
    const buf = this.readBuffer(addr, max)
    const end = buf.indexOf(0)
    return buf.subarray(0, end === -1 ? buf.length : end).toString(encoding)
  }

  /** Read a NUL-terminated UTF-16 (wide) string. */
  readWideString(addr: number | bigint, maxChars = 256): string {
    const buf = this.readBuffer(addr, maxChars * 2)
    let end = buf.length
    for (let i = 0; i + 1 < buf.length; i += 2) {
      if (buf[i] === 0 && buf[i + 1] === 0) { end = i; break }
    }
    return buf.subarray(0, end).toString('utf16le')
  }

  readUInt16(addr: number | bigint): number {
    return this.readBuffer(addr, 2).readUInt16LE(0)
  }
  readUInt8(addr: number | bigint): number {
    return this.readBuffer(addr, 1).readUInt8(0)
  }

  /**
   * Fault-tolerant read: returns a `size`-byte buffer; spans covering
   * inaccessible/uncommitted pages come back zeroed instead of throwing.
   * Throws ReadError only if the handle itself is invalid.
   */
  readSafe(addr: number | bigint, size: number): Buffer {
    this.assertOpen()
    try { return native.readSafe(this.#handle, Number(addr), size) }
    catch (e: any) { throw new ReadError(addr, e?.win32code) }
  }

  /** Read a flat struct by a shape of {name: [offset, type]}. */
  readStruct<T extends Record<string, [number, 'int32'|'uint32'|'float'|'double']>>(
    addr: number | bigint, shape: T
  ): { [K in keyof T]: T[K][1] extends 'int64'|'uint64'|'pointer' ? bigint : number } {
    const out: Record<string, number | bigint> = {}
    for (const [k, [off, type]] of Object.entries(shape)) {
      out[k] = this.readValueAt(Number(addr) + off, type)
    }
    return out as any
  }

  readValueAt(addr: number | bigint, type: string): number | bigint {
    this.assertOpen()
    try { return native.readValue(this.#handle, Number(addr), type) }
    catch { throw new ReadError(addr) }
  }

  /** Follow a pointer chain: read pointer at `base`, then apply each offset. */
  resolvePointer(base: number | bigint, offsets: readonly number[]): bigint {
    let addr = this.readPointer(base)
    for (let i = 0; i < offsets.length - 1; i++) {
      addr = this.readPointer(addr + BigInt(offsets[i]!))
    }
    return addr + BigInt(offsets[offsets.length - 1] ?? 0)
  }

  #read<T extends number | bigint>(addr: number | bigint, type: string): T {
    this.assertOpen()
    try { return native.readValue(this.#handle, Number(addr), type) as T }
    catch { throw new ReadError(addr) }
  }

  // ---- writes ----
  writeInt32(addr: number | bigint, v: number): boolean { return this.#write(addr, 'int32', v) }
  writeUInt32(addr: number | bigint, v: number): boolean { return this.#write(addr, 'uint32', v) }
  writeInt64(addr: number | bigint, v: bigint): boolean { return this.#write(addr, 'int64', v) }
  writeUInt64(addr: number | bigint, v: bigint): boolean { return this.#write(addr, 'uint64', v) }
  writeFloat(addr: number | bigint, v: number): boolean { return this.#write(addr, 'float', v) }
  writeDouble(addr: number | bigint, v: number): boolean { return this.#write(addr, 'double', v) }
  writePointer(addr: number | bigint, v: bigint): boolean { return this.#write(addr, 'pointer', v) }
  writeUInt8(addr: number | bigint, v: number): boolean { return this.writeBuffer(addr, Buffer.from([v & 0xff])) }
  writeUInt16(addr: number | bigint, v: number): boolean { const b = Buffer.alloc(2); b.writeUInt16LE(v & 0xffff); return this.writeBuffer(addr, b) }

  /** Write raw bytes. */
  writeBuffer(addr: number | bigint, data: Buffer | Uint8Array): boolean {
    this.assertOpen()
    const ok = native.writeBuffer(this.#handle, Number(addr), Buffer.from(data))
    if (!ok) throw new WriteError(addr)
    return ok
  }

  #write(addr: number | bigint, type: string, v: number | bigint): boolean {
    this.assertOpen()
    const ok = native.writeValue(this.#handle, Number(addr), type, v)
    if (!ok) throw new WriteError(addr)
    return ok
  }

  // ---- modules / regions ----
  modules(): ModuleInfo[] { this.assertOpen(); return native.getModules(this.#handle, this.pid) }
  module(name: string): ModuleInfo | undefined {
    const want = name.toLowerCase()
    return this.modules().find(m => m.path.split(/[\\/]/).pop()!.toLowerCase() === want)
  }
  regions(): Region[] { this.assertOpen(); return native.getRegions(this.#handle) }

  // ---- memory management ----
  /** Allocate memory in the remote process. Returns base address (bigint). */
  alloc(size: number, protection: number = Protection.PAGE_EXECUTE_READWRITE): bigint {
    this.assertOpen()
    return native.allocMemory(this.#handle, size, protection)
  }
  /** Free remote memory allocated with {@link alloc}. */
  free(addr: number | bigint): boolean {
    this.assertOpen()
    return native.freeMemory(this.#handle, Number(addr))
  }
  /** Change page protection. Returns previous protection. */
  protect(addr: number | bigint, size: number, protection: number): number {
    this.assertOpen()
    return native.protectMemory(this.#handle, Number(addr), size, protection)
  }

  /** Write bytes that may live in a protected/code region: protect→write→restore→flush. */
  writeProtected(addr: number | bigint, data: Buffer | Uint8Array): boolean {
    this.assertOpen()
    const region = this.regions().find(r => {
      const a = BigInt(r.baseAddress), s = BigInt(r.size), t = BigInt(addr)
      return t >= a && t < a + s
    })
    const old = this.protect(addr, data.length, Protection.PAGE_EXECUTE_READWRITE)
    try {
      return this.writeBuffer(addr, data)
    } finally {
      this.protect(addr, data.length, old ?? Protection.PAGE_EXECUTE_READ)
      native.flushInstructions(this.#handle, Number(addr), data.length)
    }
  }
  /** NOP `len` bytes at `addr` (0x90). */
  nop(addr: number | bigint, len: number): boolean {
    return this.writeProtected(addr, Buffer.alloc(len, 0x90))
  }
  /** Write an E9 relative jump from `src` to `dst` (5 bytes). */
  patchJump(src: number | bigint, dst: number | bigint): boolean {
    const rel = BigInt(dst) - (BigInt(src) + 5n)
    const buf = Buffer.alloc(5)
    buf[0] = 0xe9
    buf.writeInt32LE(Number(BigInt.asIntN(32, rel)), 1)
    return this.writeProtected(src, buf)
  }

  // ---- threads / info ----
  /** Is this a 32-bit process under WOW64 (relevant to pointer width). */
  get isWow64(): boolean { this.assertOpen(); return native.isWow64(this.#handle) }
  /** Pointer size in bytes for this process. */
  get pointerSize(): number { return this.isWow64 ? 4 : 8 }
  /** Thread IDs owned by this process. */
  threads(): number[] { this.assertOpen(); return native.listThreads(this.pid) }
  /** Suspend a thread by id. */
  suspendThread(tid: number): boolean { return native.suspendThread(tid) }
  /** Resume a thread by id. */
  resumeThread(tid: number): boolean { return native.resumeThread(tid) }
  /** Suspend all threads of this process (for atomic patching). */
  suspendAll(): number[] { const t = this.threads(); t.forEach(id => this.suspendThread(id)); return t }
  /** Resume all threads of this process. */
  resumeAll(): void { this.threads().forEach(id => this.resumeThread(id)) }

  // ---- helpers ----
  /** Resolve a RIP-relative address: `hit + offset + 4 + rel32` (x64 mov/movaps sigs). */
  resolveRIPRelative(hitAddr: number | bigint, offset = 3): bigint {
    const rel = this.readInt32(BigInt(hitAddr) + BigInt(offset))
    return BigInt(hitAddr) + BigInt(offset) + 4n + BigInt(rel)
  }
  /** Read a whole region once into a buffer and expose offset accessors (bulk-read perf). */
  readRegion(addr: number | bigint, size: number): RegionView {
    const buf = this.readBuffer(addr, size)
    return new RegionView(buf, BigInt(addr))
  }

  // ---- pattern scan (async) ----
  async scan(pattern: string, opts: ScanOptions = {}): Promise<bigint[]> {
    this.assertOpen()
    let start = toNum(opts.start)
    let end = toNum(opts.end)
    if (opts.module) {
      const m = this.module(opts.module)
      if (m) { start = m.base; end = m.base + m.size }
    }
    return native.scan(this.#handle, pattern, { start, end, onlyReadable: opts.onlyReadable ?? true })
  }

  /** First match for `pattern`, or null when nothing matches. */
  async scanFirst(pattern: string, opts: ScanOptions = {}): Promise<bigint | null> {
    const hits = await this.scan(pattern, opts)
    return hits.length ? hits[0]! : null
  }

  /** Exactly-one-match scan. Throws ScanError when 0 or >1 hits. */
  async scanUnique(pattern: string, opts: ScanOptions = {}): Promise<bigint> {
    const hits = await this.scan(pattern, opts)
    if (hits.length !== 1) throw new ScanError(hits.length, pattern)
    return hits[0]!
  }

  // ---- dll injection ----
  /**
   * Inject `absolutePath` (a DLL) into this process via LoadLibraryA on a remote
   * thread. Re-opens the process internally with the required rights.
   * Throws InjectError on failure.
   */
  injectDll(absolutePath: string): boolean {
    this.assertOpen()
    try { return native.injectDll(this.pid, absolutePath) }
    catch (e: any) { throw new InjectError(e?.message ?? 'unknown', e?.win32code) }
  }

  /**
   * Eject a loaded module via FreeLibrary on a remote thread. Accepts a
   * ModuleInfo or a substring matched (case-insensitive) against module names.
   * Throws InjectError on failure / no match.
   */
  ejectDll(module: ModuleInfo | string): boolean {
    this.assertOpen()
    let base: number | undefined
    if (typeof module === 'string') {
      const want = module.toLowerCase()
      const m = this.modules().find(m => {
        const name = m.path.split(/[\\/]/).pop()!.toLowerCase()
        return name.includes(want)
      })
      if (!m) throw new InjectError(`module not found: ${module}`)
      base = m.base
    } else {
      base = module.base
    }
    try { return native.ejectDll(this.pid, base) }
    catch (e: any) { throw new InjectError(e?.message ?? 'unknown', e?.win32code) }
  }

  // ---- watch ----
  /**
   * Poll `readInt32` at `addr` every `intervalMs`; invoke `cb(newVal, oldVal)`
   * on change. Returns an unsubscribe function. Read failures are ignored
   * (the target may exit or the page may become inaccessible).
   */
  watch(addr: number | bigint, cb: (newVal: number, oldVal: number) => void, intervalMs = 50): () => void {
    this.assertOpen()
    let prev: number | undefined
    try { prev = this.readInt32(addr) } catch { /* start uninitialized */ }
    const timer = setInterval(() => {
      let cur: number
      try { cur = this.readInt32(addr) } catch { return }
      if (prev === undefined || cur !== prev) {
        const old = prev
        prev = cur
        if (old !== undefined) cb(cur, old)
      }
    }, intervalMs)
    if (typeof timer.unref === 'function') timer.unref()
    return () => clearInterval(timer)
  }

  /** Close the process handle. Idempotent. */
  close(): void {
    if (this.#handle) {
      native.closeHandle(this.#handle)
      this.#handle = 0
    }
  }

  [Symbol.dispose](): void { this.close() }
}

/** A read-once-index-locally view over a region buffer. */
export class RegionView {
  constructor(private buf: Buffer, readonly base: bigint) {}
  get size() { return this.buf.length }
  int32At(off: number) { return this.buf.readInt32LE(off) }
  uint32At(off: number) { return this.buf.readUInt32LE(off) }
  floatAt(off: number) { return this.buf.readFloatLE(off) }
  doubleAt(off: number) { return this.buf.readDoubleLE(off) }
  ptrAt(off: number) { return this.buf.readBigUInt64LE(off) }
  stringAt(off: number, max = 256) {
    const end = this.buf.indexOf(0, off)
    return this.buf.subarray(off, end === -1 ? off + max : Math.min(end, off + max)).toString('utf8')
  }
  bytes(off: number, len: number) { return this.buf.subarray(off, off + len) }
}
