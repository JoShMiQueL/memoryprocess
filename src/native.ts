import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const __dir = dirname(fileURLToPath(import.meta.url))

interface Native {
  openProcess(nameOrPid: string | number, access?: number): { handle: number; pid: number }
  closeHandle(handle: number): boolean
  listProcesses(): { pid: number; name: string }[]
  getModules(handle: number, pid: number): { base: number; size: number; path: string }[]
  getRegions(handle: number): { baseAddress: number; size: number; protection: number; type: number }[]
  readValue(handle: number, address: number, type: string): number | bigint
  writeValue(handle: number, address: number, type: string, value: number | bigint): boolean
  readBuffer(handle: number, address: number, size: number): Buffer
  writeBuffer(handle: number, address: number, data: Buffer): boolean
  scan(handle: number, pattern: string, opts?: { start?: number; end?: number; onlyReadable?: boolean }): Promise<bigint[]>
  allocMemory(handle: number, size: number, protection: number): bigint
  freeMemory(handle: number, address: number): boolean
  protectMemory(handle: number, address: number, size: number, protection: number): number
  isWow64(handle: number): boolean
  listThreads(pid: number): number[]
  suspendThread(tid: number): boolean
  resumeThread(tid: number): boolean
  readSafe(handle: number, address: number, size: number): Buffer
  flushInstructions(handle: number, address: number, size: number): boolean
  injectDll(pid: number, dllPath: string): boolean
  ejectDll(pid: number, moduleBase: number): boolean
}

// Resolution order: dist/memoryprocess.node (built/packaged) -> prebuilds via
// node-gyp-build -> build/Release/memoryprocess.node (dev). Works whether this
// file is loaded from src/ (bun test) or bundled into dist/index.js.
const candidates = [
  join(__dir, 'memoryprocess.node'),            // dist/ or src/ (copied for tests)
  join(__dir, '..', 'dist', 'memoryprocess.node'), // src/ -> dist/
  join(__dir, '..', 'build', 'Release', 'memoryprocess.node'), // src/ -> build/
]

export const native: Native = (() => {
  for (const path of candidates) {
    try { return require(path) as Native } catch { /* try next */ }
  }
  try { return require('node-gyp-build')(join(__dir, '..')) as Native } catch { /* fall through */ }
  throw new Error('memoryprocess native addon not found (run `bun run build`)')
})()
