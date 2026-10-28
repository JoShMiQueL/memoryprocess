import { native } from './native.js'
import { ProcessNotFoundError, AccessDeniedError, ReadError, WriteError } from './errors.js'

export interface ProcessInfo { pid: number; name: string }
export interface ModuleInfo { base: number; size: number; path: string }
export interface Region { baseAddress: number; size: number; protection: number; type: number }

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

  /** Open a process by name ("notepad.exe") or pid. Throws ProcessNotFoundError / AccessDeniedError. */
  static open(nameOrPid: string | number, access?: number): Process {
    try {
      const { handle, pid } = native.openProcess(nameOrPid, access)
      return new Process(handle, pid)
    } catch (e: any) {
      if (e?.code === 'PROCESS_NOT_FOUND') throw new ProcessNotFoundError(nameOrPid)
      if (e?.code === 'ACCESS_DENIED' || e?.win32code === 5) throw new AccessDeniedError(typeof nameOrPid === 'number' ? nameOrPid : -1)
      throw e
    }
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

  /** Close the process handle. Idempotent. */
  close(): void {
    if (this.#handle) {
      native.closeHandle(this.#handle)
      this.#handle = 0
    }
  }

  [Symbol.dispose](): void { this.close() }
}
