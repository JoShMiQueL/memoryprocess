export class MemoryProcessError extends Error {
  readonly code: string
  readonly win32code?: number
  constructor(message: string, code: string, win32code?: number) {
    super(message)
    this.name = 'MemoryProcessError'
    this.code = code
    this.win32code = win32code
  }
}
export class ProcessNotFoundError extends MemoryProcessError {
  constructor(name: string | number) { super(`Process not found: ${name}`, 'PROCESS_NOT_FOUND'); this.name = 'ProcessNotFoundError' }
}
export class AccessDeniedError extends MemoryProcessError {
  constructor(pid: number) { super(`Access denied opening pid ${pid} (run elevated?)`, 'ACCESS_DENIED', 5); this.name = 'AccessDeniedError' }
}
export class ReadError extends MemoryProcessError {
  constructor(addr: bigint | number, win32?: number) { super(`ReadProcessMemory failed at 0x${addr.toString(16)}`, 'READ_FAILED', win32); this.name = 'ReadError' }
}
export class WriteError extends MemoryProcessError {
  constructor(addr: bigint | number) { super(`WriteProcessMemory failed at 0x${addr.toString(16)}`, 'WRITE_FAILED'); this.name = 'WriteError' }
}
