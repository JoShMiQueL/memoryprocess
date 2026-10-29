import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const __dir = dirname(fileURLToPath(import.meta.url));

interface Native {
  openProcess(
    nameOrPid: string | number,
    access?: number,
  ): { handle: number; pid: number };
  closeHandle(handle: number): boolean;
  listProcesses(): { pid: number; name: string }[];
  getModules(
    handle: number,
    pid: number,
  ): { base: number; size: number; path: string }[];
  getRegions(
    handle: number,
  ): { baseAddress: number; size: number; protection: number; type: number }[];
  readValue(handle: number, address: number, type: string): number | bigint;
  writeValue(
    handle: number,
    address: number,
    type: string,
    value: number | bigint,
  ): boolean;
  readBuffer(handle: number, address: number, size: number): Buffer;
  writeBuffer(handle: number, address: number, data: Buffer): boolean;
  scan(
    pid: number,
    pattern: string,
    opts?: { start?: number; end?: number; onlyReadable?: boolean },
  ): Promise<bigint[]>;
  scanValue(
    pid: number,
    needle: Uint8Array,
    opts?: {
      start?: number;
      end?: number;
      onlyWritable?: boolean;
      alignment?: number;
    },
  ): Promise<bigint[]>;
  allocMemory(
    handle: number,
    size: number,
    protection: number,
    nearAddress?: number,
  ): bigint;
  freeMemory(handle: number, address: number): boolean;
  protectMemory(
    handle: number,
    address: number,
    size: number,
    protection: number,
  ): number;
  isWow64(handle: number): boolean;
  listThreads(pid: number): number[];
  suspendThread(tid: number): boolean;
  resumeThread(tid: number): boolean;
  readSafe(handle: number, address: number, size: number): Buffer;
  flushInstructions(handle: number, address: number, size: number): boolean;
  injectDll(pid: number, dllPath: string, timeoutMs?: number): boolean;
  ejectDll(pid: number, moduleBase: number): boolean;
  queryAddress(
    handle: number,
    address: number,
  ): {
    baseAddress: number;
    allocationBase: number;
    size: number;
    protection: number;
    state: number;
    type: number;
  } | null;
  getThreadContext(tid: number): {
    rip: bigint;
    rsp: bigint;
    rbp: bigint;
    dr0: bigint;
    dr1: bigint;
    dr2: bigint;
    dr3: bigint;
    dr6: bigint;
    dr7: bigint;
    eflags: bigint;
  } | null;
  setThreadContext(
    tid: number,
    ctx: Partial<
      Record<
        | 'rip'
        | 'rsp'
        | 'rbp'
        | 'dr0'
        | 'dr1'
        | 'dr2'
        | 'dr3'
        | 'dr6'
        | 'dr7'
        | 'eflags',
        number | bigint
      >
    >,
  ): boolean;
  callRemote(
    pid: number,
    fnAddress: number | bigint,
    param: number | bigint,
    timeoutMs?: number,
  ): number | null;
  disasmInstructions(
    handle: number,
    address: number,
    count: number,
  ): { offset: number; length: number; relative: boolean }[];
  /**
   * Walk instructions at `address` until `minBytes` are covered, then
   * RELOCATE position-relative operands (rel32 branch/call immediates,
   * RIP-relative disp32) so the stolen bytes are correct when executed from
   * `stubAddr` (must be within rel32 range of `address`). External rel8/16
   * branches (incl. LOOP/JECXZ) can't be widened — refused `HOOK_RELOCATE`,
   * like MinHook; rel8/16 internal (target inside the stolen window) and
   * all non-relative instructions copy verbatim. Without `stubAddr` any
   * position-relative instruction is refused (inspection mode).
   * Throws `HOOK_STEAL`/`HOOK_RELOCATE` — returns the relocated bytes.
   */
  hookSteal(
    handle: number,
    address: number,
    minBytesOrOpts?: number | { minBytes?: number; stubAddr?: number | bigint },
    stubAddr?: number | bigint,
  ): { length: number; bytes: Buffer; original: Buffer };
  /**
   * Per-region VirtualProtectEx→write→restore across the whole write span —
   * records each region's real old protection before writing, restores each
   * individually. `restored=false` means part of the span is left weakened.
   */
  writeProtectedMemory(
    handle: number,
    address: number,
    buffer: Buffer,
    protection?: number,
  ): { ok: boolean; restored: boolean; protected: boolean };
  /** Current thread id (TID) — used to refuse self-suspend. */
  currentThreadId(): number;
  suspendProcess(pid: number): boolean;
  resumeProcess(pid: number): boolean;
  enableDebugPrivilege(): boolean;
  waitForExit(pid: number, timeoutMs?: number): Promise<number | null>;
  findWhatWrites(
    pid: number,
    address: number | bigint,
    size: number,
    timeoutMs: number,
    maxHits: number,
  ): Promise<
    {
      rip: bigint;
      tid: number;
      threadContext: {
        rip: bigint;
        rsp: bigint;
        rbp: bigint;
        dr0: bigint;
        dr1: bigint;
        dr2: bigint;
        dr3: bigint;
        dr6: bigint;
        dr7: bigint;
        eflags: bigint;
      };
    }[]
  >;
}

// Resolution order: dist/memoryprocess.node (built/packaged) -> prebuilds via
// node-gyp-build -> build/Release/memoryprocess.node (dev). Works whether this
// file is loaded from src/ (bun test) or bundled into dist/index.js.
const candidates = [
  join(__dir, 'memoryprocess.node'), // dist/ or src/ (copied for tests)
  join(__dir, '..', 'dist', 'memoryprocess.node'), // src/ -> dist/
  join(__dir, '..', 'build', 'Release', 'memoryprocess.node'), // src/ -> build/
];

export const native: Native = (() => {
  // Keep the last real load error: a .node that EXISTS but fails to load
  // (missing VC++ CRT, arch or N-API mismatch, wrong Node ABI) must not be
  // reported as "not found" — surface the underlying loader message.
  let lastErr: unknown;
  for (const path of candidates) {
    try {
      return require(path) as Native;
    } catch (e) {
      lastErr = e;
    }
  }
  try {
    return require('node-gyp-build')(join(__dir, '..')) as Native;
  } catch (e) {
    lastErr = lastErr ?? e;
  }
  const detail = lastErr instanceof Error ? `: ${lastErr.message}` : '';
  throw new Error(
    `memoryprocess native addon failed to load (run \`bun run build\`)${detail}`,
  );
})();
