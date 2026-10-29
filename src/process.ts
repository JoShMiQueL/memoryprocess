import { writeFileSync } from 'node:fs'
import { native } from './native.js'
import { ProcessNotFoundError, AccessDeniedError, ReadError, WriteError, ScanError, InjectError } from './errors.js'

export interface ProcessInfo { pid: number; name: string }
export interface ModuleInfo { base: number; size: number; path: string }
export interface Region { baseAddress: number; size: number; protection: number; type: number }
export interface ThreadContext {
  rip: bigint; rsp: bigint; rbp: bigint
  dr0: bigint; dr1: bigint; dr2: bigint; dr3: bigint; dr7: bigint
  eflags: bigint
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
  /**
   * First thread reported by the Toolhelp snapshot for this process — in
   * practice the main/owner thread for typical targets. Returns null when the
   * process has no threads.
   */
  get mainThread(): number | null { this.assertOpen(); return this.threads()[0] ?? null }
  /** Suspend a thread by id. */
  suspendThread(tid: number): boolean { return native.suspendThread(tid) }
  /** Resume a thread by id. */
  resumeThread(tid: number): boolean { return native.resumeThread(tid) }
  /** Suspend all threads of this process (for atomic patching). */
  suspendAll(): number[] { const t = this.threads(); t.forEach(id => this.suspendThread(id)); return t }
  /** Resume all threads of this process. */
  resumeAll(): void { this.threads().forEach(id => this.resumeThread(id)) }

  // ---- tier-3: query / context / remote call ----

  /**
   * VirtualQueryEx on a single address. Returns region info including
   * `allocationBase` and `state` (MEM_COMMIT 0x1000 / MEM_RESERVE 0x2000 /
   * MEM_FREE 0x10000), or null when the address is invalid/unmapped.
   */
  queryAddress(addr: number | bigint): (Region & { allocationBase: number; state: number }) | null {
    this.assertOpen()
    return native.queryAddress(this.#handle, Number(addr))
  }

  /**
   * Full thread context (x64) including debug registers.
   * Suspend the thread first ({@link suspendThread}) for a stable snapshot.
   * Returns null if the thread cannot be opened.
   */
  getThreadContext(tid: number): ThreadContext | null {
    this.assertOpen()
    return native.getThreadContext(tid)
  }

  /**
   * Patch selected context fields and write the context back.
   * Suspend the thread first. Accepted fields: rip, rsp, rbp, dr0..dr3, dr7,
   * eflags (number|bigint).
   */
  setThreadContext(tid: number, ctx: Partial<Record<keyof ThreadContext, number | bigint>>): boolean {
    this.assertOpen()
    return native.setThreadContext(tid, ctx)
  }

  /**
   * Execute `fnAddr` on a new remote thread with `param` as lpParameter and
   * wait up to `timeoutMs` for it to exit. Returns the thread exit code, or
   * null on failure/timeout.
   */
  callRemote(fnAddr: bigint | number, param = 0, timeoutMs = 10000): number | null {
    this.assertOpen()
    return native.callRemote(this.pid, fnAddr, param, timeoutMs)
  }

  // ---- tier-3: hardware breakpoints ----

  /**
   * Arm a hardware EXECUTION breakpoint in Dr{slot} (0-3) on thread `tid`.
   * Sets RW=00 (execute) and LEN for `size` (1|2|4|8; only 1 is meaningful for
   * execution breakpoints) plus the local-enable bit in Dr7.
   * Suspend the thread first, then resume with {@link resumeThread}.
   */
  hwBreakpoint(tid: number, addr: bigint | number, slot: 0 | 1 | 2 | 3, size: 1 | 2 | 4 | 8 = 1): boolean {
    this.assertOpen()
    const ctx = this.getThreadContext(tid)
    if (!ctx) return false
    const lenBits = size === 1 ? 0n : size === 2 ? 1n : size === 8 ? 3n : 2n // 00=1 01=2 10=8 11=4
    const shift = BigInt(16 + slot * 4)
    let dr7 = ctx.dr7
    dr7 &= ~(0xfn << shift)                 // clear RW+LEN for this slot
    dr7 |= lenBits << shift                 // RW=00 (exec), LEN=size
    dr7 |= 1n << BigInt(slot * 2)           // local enable L{slot}
    const patch: Record<string, bigint> = { dr7 }
    patch[`dr${slot}`] = BigInt(addr)
    return this.setThreadContext(tid, patch)
  }

  /** Clear Dr{slot} (address + enable/RW/LEN bits in Dr7) on thread `tid`. */
  clearHwBreakpoint(tid: number, slot: 0 | 1 | 2 | 3): boolean {
    this.assertOpen()
    const ctx = this.getThreadContext(tid)
    if (!ctx) return false
    const shift = BigInt(16 + slot * 4)
    let dr7 = ctx.dr7
    dr7 &= ~(0xfn << shift)
    dr7 &= ~(3n << BigInt(slot * 2))        // clear local+global enable
    const patch: Record<string, bigint> = { dr7 }
    patch[`dr${slot}`] = 0n
    return this.setThreadContext(tid, patch)
  }

  // ---- tier-3: code cave ----

  /**
   * Find the first run of >= minLen consecutive 0x00 or 0xCC bytes inside
   * committed, executable regions. When `opts.module` is set the search is
   * bounded to that module; `opts.start`/`opts.end` bound it explicitly.
   * Returns the cave address or null.
   */
  findCodeCave(minLen: number, opts: { module?: string; start?: number | bigint; end?: number | bigint } = {}): bigint | null {
    this.assertOpen()
    const EXEC = Protection.PAGE_EXECUTE | Protection.PAGE_EXECUTE_READ |
      Protection.PAGE_EXECUTE_READWRITE | Protection.PAGE_EXECUTE_WRITECOPY
    const MEM_COMMIT = 0x1000

    let lo = opts.start !== undefined ? BigInt(opts.start) : 0n
    let hi = opts.end !== undefined ? BigInt(opts.end) : 0x7fffffffffffffn
    if (opts.module) {
      const m = this.module(opts.module)
      if (!m) return null
      lo = BigInt(m.base); hi = BigInt(m.base + m.size)
    }

    for (const r of this.regions()) {
      if ((r.protection & EXEC) === 0) continue
      const rLo = BigInt(r.baseAddress), rHi = rLo + BigInt(r.size)
      const s = rLo > lo ? rLo : lo, e = rHi < hi ? rHi : hi
      if (s >= e) continue
      const q = this.queryAddress(s)
      if (!q || q.state !== MEM_COMMIT) {
        // regions() only returns committed allocations in practice, but confirm
        if (!q) continue
      }
      const buf = this.readSafe(s, Number(e - s))
      let run = 0
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i]!
        if (b === 0x00 || b === 0xcc) {
          if (++run >= minLen) return s + BigInt(i - run + 1)
        } else run = 0
      }
    }
    return null
  }

  // ---- tier-3: exports / strings / arrays / misc ----

  /**
   * Resolve an exported symbol in a remote module by parsing its PE export
   * table via remote reads. Returns the absolute address or null.
   */
  resolveExport(moduleName: string, exportName: string): bigint | null {
    this.assertOpen()
    const m = this.module(moduleName)
    if (!m) return null
    const base = BigInt(m.base)
    try {
      const hdr = this.readSafe(base, 0x1000)
      if (hdr.readUInt16LE(0) !== 0x5a4d) return null // MZ
      const peOff = hdr.readUInt32LE(0x3c)
      const nt = this.readSafe(base + BigInt(peOff), 0x400)
      if (nt.readUInt32LE(0) !== 0x4550) return null // PE\0\0
      const magic = nt.readUInt16LE(0x18)
      const ddBase = magic === 0x20b ? 0x88 : 0x78 // optional-header data dir offset
      const expRva = nt.readUInt32LE(ddBase)
      if (!expRva) return null
      const exp = this.readSafe(base + BigInt(expRva), 0x28)
      const nNames = exp.readUInt32LE(0x18)
      const namesRva = exp.readUInt32LE(0x20)
      const ordsRva = exp.readUInt32LE(0x24)
      const funcsRva = exp.readUInt32LE(0x1c)
      const names = this.readSafe(base + BigInt(namesRva), nNames * 4)
      for (let i = 0; i < nNames; i++) {
        const nameRva = names.readUInt32LE(i * 4)
        const name = this.readString(base + BigInt(nameRva), 256)
        if (name === exportName) {
          const ord = this.readSafe(base + BigInt(ordsRva) + BigInt(i * 2), 2).readUInt16LE(0)
          const fnRva = this.readSafe(base + BigInt(funcsRva) + BigInt(ord * 4), 4).readUInt32LE(0)
          return base + BigInt(fnRva)
        }
      }
      return null
    } catch { return null }
  }

  /** Write `str` (encoded, default utf8) plus a NUL terminator at `addr`. */
  writeString(addr: number | bigint, str: string, encoding: 'utf8' | 'ascii' = 'utf8'): boolean {
    return this.writeBuffer(addr, Buffer.concat([Buffer.from(str, encoding), Buffer.from([0])]))
  }

  /** Write `str` as UTF-16LE plus a 00 00 terminator at `addr`. */
  writeWideString(addr: number | bigint, str: string): boolean {
    return this.writeBuffer(addr, Buffer.concat([Buffer.from(str, 'utf16le'), Buffer.from([0, 0])]))
  }

  /**
   * Read `count` contiguous values of `type` in a single read.
   * Returns number[] for int32/uint32, Float32Array for 'float',
   * Float64Array for 'double'.
   */
  readArray(addr: number | bigint, type: 'int32' | 'uint32' | 'float' | 'double', count: number): number[] | Float32Array | Float64Array {
    const width = type === 'double' ? 8 : 4
    const buf = this.readBuffer(addr, count * width)
    const aligned = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
    switch (type) {
      case 'int32': return Array.from(new Int32Array(aligned, 0, count))
      case 'uint32': return Array.from(new Uint32Array(aligned, 0, count))
      case 'float': return new Float32Array(aligned, 0, count)
      case 'double': return new Float64Array(aligned, 0, count)
    }
  }

  /** Module (from {@link modules}) whose [base, base+size) contains `addr`. */
  moduleFromAddress(addr: number | bigint): ModuleInfo | null {
    this.assertOpen()
    const a = BigInt(addr)
    return this.modules().find(m => a >= BigInt(m.base) && a < BigInt(m.base + m.size)) ?? null
  }

  /**
   * Dump a loaded module's committed image (readSafe) to `outPath`.
   * Returns `outPath` on success.
   */
  dumpModule(name: string, outPath: string): string {
    this.assertOpen()
    const m = this.module(name)
    if (!m) throw new ReadError(0n)
    const buf = this.readSafe(m.base, m.size)
    writeFileSync(outPath, buf)
    return outPath
  }

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
