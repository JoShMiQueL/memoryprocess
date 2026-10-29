# memoryprocess

[![npm](https://img.shields.io/npm/v/memoryprocess)](https://www.npmjs.com/package/memoryprocess)
[![CI](https://github.com/JoShMiQueL/memoryprocess/actions/workflows/ci.yml/badge.svg)](https://github.com/JoShMiQueL/memoryprocess/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Read and write **Windows process memory** from Node.js, Bun, or Deno. N-API native addon, zero runtime dependencies, prebuilt binaries.

> **v2** — complete rewrite. Breaking changes from v1/memoryjs. See [migration](#migrating-from-v1).

## Features

- **Process** — open by name or PID, least-privilege access, `using`/dispose, process listing, `enableDebugPrivilege`
- **Memory R/W** — typed scalar reads/writes (i8–i64, f32/f64, pointers), buffers, strings (UTF-8/UTF-16), fault-tolerant `readSafe`, arrays, flat structs
- **Value hunt (Cheat Engine style)** — `scanValue` exact-value scan, `nextScan` refinement (incl. ranged), `freeze` to lock a value
- **Pattern scan** — async `scan`/`scanFirst`/`scanUnique` with wildcards, module- or section-scoped, off the event loop (`Napi::AsyncWorker`)
- **Allocation & patching** — `alloc`/`free`/`protect`, `writeProtected` (+icache flush), `nop`, `patchJump`/`patchCall`, `hook`/`unhook` (E9 detour + trampoline), `execShellcode`, `disassemble` (x64 instruction lengths), `findCodeCave`
- **Modules** — enumerate, resolve by name or address, `resolveExport`, `dumpModule` to disk
- **Threads** — list/suspend/resume, `mainThread`, whole-process `suspendProcess`/`resumeProcess`, `getThreadContext`/`setThreadContext`, hardware breakpoints (DR0–DR3), `callRemote`
- **DLL injection** — `injectDll`/`ejectDll` round-trip via remote `LoadLibraryA`/`FreeLibrary`
- **Query** — `queryAddress` (VirtualQueryEx), `regions()`, `resolvePointer` chains, `resolveRIPRelative`, `watch` polling, `waitForExit`, `isWow64`/`pointerSize`
- **Typed errors** — `ProcessNotFoundError`, `AccessDeniedError`, `ReadError`, `WriteError`, `ScanError`, `InjectError` (each with `.code`/`.win32code`)

## Install

```bash
bun add memoryprocess    # or: npm install memoryprocess
```

Prebuilt `.node` binaries ship for `win32-x64` — **no compiler needed**. Other setups fall back to a `node-gyp` source build (requires MSVC Build Tools). Node **22+** required (`engines`).

## Quickstart

```ts
import { Process } from 'memoryprocess';

// open notepad.exe (start it first); `using` auto-closes the handle
using proc = Process.open('notepad.exe');
console.log(
  `pid=${proc.pid} wow64=${proc.isWow64} ptrSize=${proc.pointerSize}`,
);

// typed read: the PE magic at the main module base should be 'MZ' (0x5A4D)
const main = proc.modules()[0];
const mz = proc.readUInt16(main.base);
console.log(
  `magic: 0x${mz.toString(16)} (${mz === 0x5a4d ? 'MZ ok' : 'unexpected'})`,
);

// pattern scan (async, off the event loop)
const hits = await proc.scan('4D 5A', { module: 'notepad.exe' });
console.log(`'MZ' bytes found at ${hits.length} address(es)`);

// modules
for (const m of proc.modules()) console.log(m.path, '0x' + m.base.toString(16));
```

## API reference

### Statics

| Method                         | Signature                           | Description                                           |
| ------------------------------ | ----------------------------------- | ----------------------------------------------------- |
| `Process.open`                 | `(nameOrPid, opts?) → Process`      | Open by name or PID; least-privilege by default       |
| `Process.openReadOnly`         | `(nameOrPid) → Process`             | Open with `VM_READ` + `QUERY_INFORMATION` only        |
| `Process.list`                 | `() → ProcessInfo[]`                | All running processes `{ pid, name }`                 |
| `Process.find`                 | `(name) → ProcessInfo \| undefined` | First process matching name (case-insensitive)        |
| `Process.enableDebugPrivilege` | `() → boolean`                      | Grant the caller `SeDebugPrivilege` (needs elevation) |

`opts` for `open`: `{ access?: number }` or a raw access-mask number. Default access is `VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION`.

### Instance state

| Member         | Type        | Description                                |
| -------------- | ----------- | ------------------------------------------ |
| `proc.pid`     | `number`    | Target PID (readonly)                      |
| `proc.handle`  | `number`    | Raw `HANDLE` (getter); 0 after `close()`   |
| `proc.close()` | `() → void` | Idempotent; also stops freeze/watch timers |

### Reads

| Method                                                  | Signature                         | Description                                  |
| ------------------------------------------------------- | --------------------------------- | -------------------------------------------- |
| `readInt32` / `readUInt32` / `readFloat` / `readDouble` | `(addr) → number`                 | Typed scalar reads                           |
| `readInt64` / `readUInt64` / `readPointer`              | `(addr) → bigint`                 | 64-bit reads                                 |
| `readUInt8` / `readUInt16`                              | `(addr) → number`                 | Narrow reads                                 |
| `readValueAt`                                           | `(addr, type) → number \| bigint` | Read any `WriteValueType` by name            |
| `readBuffer`                                            | `(addr, size) → Buffer`           | Raw bytes; throws `ReadError`                |
| `readSafe`                                              | `(addr, size) → Buffer`           | Fault-tolerant; unreadable spans zero-filled |
| `readString`                                            | `(addr, max?, enc?) → string`     | NUL-terminated UTF-8/ASCII                   |
| `readWideString`                                        | `(addr, maxChars?) → string`      | NUL-terminated UTF-16LE                      |
| `readArray`                                             | `(addr, type, count) → Array`     | Flat typed array read                        |
| `readStruct`                                            | `(addr, shape) → object`          | `{name: [offset, type]}` struct decode       |
| `readRegion`                                            | `(addr, size) → RegionView`       | One read, local offset accessors             |

### Writes

| Method                                           | Signature                     | Description                               |
| ------------------------------------------------ | ----------------------------- | ----------------------------------------- |
| `writeInt32` / `writeFloat` / `writePointer` / … | `(addr, v) → boolean`         | Typed scalar writes (throws `WriteError`) |
| `writeUInt8` / `writeUInt16`                     | `(addr, v) → boolean`         | Narrow writes                             |
| `writeBuffer`                                    | `(addr, buf) → boolean`       | Raw bytes                                 |
| `writeString` / `writeWideString`                | `(addr, str, enc?) → boolean` | String writes + NUL terminator            |
| `writeProtected`                                 | `(addr, buf) → boolean`       | Protect→write→restore→flush icache        |
| `nop`                                            | `(addr, len) → boolean`       | Fill with 0x90                            |
| `patchJump`                                      | `(src, dst) → boolean`        | E9 relative jump (5 bytes, ±2 GB)         |
| `patchCall`                                      | `(src, dst) → boolean`        | E8 relative call (5 bytes, ±2 GB)         |

### Code patching & hooks

| Method          | Signature                                      | Description                                                              |
| --------------- | ---------------------------------------------- | ------------------------------------------------------------------------ |
| `disassemble`   | `(addr, count) → Insn[]`                       | x64 instruction-length decode: `{ address, size, bytes }` (no mnemonics) |
| `hook`          | `(src, dst) → HookHandle`                      | Steal ≥5 whole instruction bytes at `src`, build trampoline, write E9    |
| `unhook`        | `(handle) → boolean`                           | Restore stolen bytes, free stub                                          |
| `execShellcode` | `(bytes, param?, timeoutMs?) → number \| null` | Alloc RWX → write → `callRemote` → free; returns exit code               |

`HookHandle`: `{ src, dst, stub, stolen }` — call `stub` via `callRemote` to invoke the original function.

### Memory management & query

| Method         | Signature                           | Description                                                            |
| -------------- | ----------------------------------- | ---------------------------------------------------------------------- |
| `alloc`        | `(size, prot?, nearAddr?) → bigint` | `VirtualAllocEx` (default RWX; `nearAddr` = hint)                      |
| `free`         | `(addr) → boolean`                  | `VirtualFreeEx`                                                        |
| `protect`      | `(addr, size, prot) → number`       | `VirtualProtectEx`; returns old protection                             |
| `queryAddress` | `(addr) → MemoryInfo \| null`       | `VirtualQueryEx` (base, size, state, protection, type, allocationBase) |
| `regions`      | `() → Region[]`                     | All committed regions                                                  |
| `findCodeCave` | `(minLen, opts?) → bigint \| null`  | Run of 0x00/0xCC in executable memory                                  |

### Pattern scan (async)

| Method       | Signature                                    | Description                       |
| ------------ | -------------------------------------------- | --------------------------------- |
| `scan`       | `(pattern, opts?) → Promise<bigint[]>`       | Hex pattern, `??`/`?` wildcards   |
| `scanFirst`  | `(pattern, opts?) → Promise<bigint \| null>` | First hit or null                 |
| `scanUnique` | `(pattern, opts?) → Promise<bigint>`         | Exactly one hit, else `ScanError` |

`opts`: `{ module?, section?, start?, end?, onlyReadable? }` — `section` (e.g. `'.text'`) requires `module`.

### Value scan & freeze (Cheat Engine flow)

| Method      | Signature                                  | Description                                        |
| ----------- | ------------------------------------------ | -------------------------------------------------- |
| `scanValue` | `(value, opts?) → Promise<bigint[]>`       | Exact typed value scan (default: writable regions) |
| `nextScan`  | `(hits, value, opts?) → Promise<bigint[]>` | Refine hits by current value, or `range: [lo, hi]` |
| `freeze`    | `(addr, type, value, ms?) → () => void`    | Re-write `value` every `ms`; returns unfreeze fn   |

`scanValue` opts: `{ type?, module?, start?, end?, onlyWritable?, alignment? }`.
Types: `'int32' | 'uint32' | 'int64' | 'uint64' | 'float' | 'double'` (`'pointer'` is write-only — rejected by scans).

### Modules

| Method              | Signature                           | Description                                            |
| ------------------- | ----------------------------------- | ------------------------------------------------------ |
| `modules`           | `() → ModuleInfo[]`                 | `{ base, size, path }`                                 |
| `module`            | `(name) → ModuleInfo \| undefined`  | Exact filename match                                   |
| `moduleFromAddress` | `(addr) → ModuleInfo \| null`       | Containing module                                      |
| `resolveExport`     | `(module, export) → bigint \| null` | Export address in remote process (forwarders followed) |
| `dumpModule`        | `(name, outPath) → string`          | Dump module image to file                              |

### Threads & process control

| Method                             | Signature                                       | Description                                 |
| ---------------------------------- | ----------------------------------------------- | ------------------------------------------- |
| `threads`                          | `() → number[]`                                 | Thread IDs                                  |
| `mainThread`                       | `→ number \| null` (getter)                     | Main thread ID                              |
| `suspendThread` / `resumeThread`   | `(tid) → boolean`                               | Per-thread control                          |
| `suspendAll` / `resumeAll`         | `() → number[]` / `() → void`                   | All threads                                 |
| `suspendProcess` / `resumeProcess` | `() → boolean`                                  | Atomic `NtSuspendProcess`/`NtResumeProcess` |
| `getThreadContext`                 | `(tid) → ThreadContext \| null`                 | rip/rsp/rbp/dr0–3/dr7/eflags (bigint)       |
| `setThreadContext`                 | `(tid, partial) → boolean`                      | Write back context fields                   |
| `hwBreakpoint`                     | `(tid, addr, slot 0-3, size?) → boolean`        | DR register breakpoint; **suspend first**   |
| `clearHwBreakpoint`                | `(tid, slot) → boolean`                         | Clear DR slot                               |
| `callRemote`                       | `(fnAddr, param?, timeoutMs?) → number \| null` | `CreateRemoteThread`; returns exit code     |
| `waitForExit`                      | `(timeoutMs?) → Promise<number \| null>`        | Process exit code, or null on timeout       |

### Injection & helpers

| Method                    | Signature                      | Description                           |
| ------------------------- | ------------------------------ | ------------------------------------- |
| `injectDll`               | `(absPath) → boolean`          | `LoadLibraryA` on remote thread       |
| `ejectDll`                | `(module \| name) → boolean`   | `FreeLibrary` on remote thread        |
| `resolvePointer`          | `(base, offsets[]) → bigint`   | Follow pointer chain                  |
| `resolveRIPRelative`      | `(hit, offset?) → bigint`      | x64 RIP-relative target               |
| `watch`                   | `(addr, cb, ms?) → () => void` | Poll `readInt32`; returns unsubscribe |
| `isWow64` / `pointerSize` | getters → `boolean` / `number` | Bitness info                          |

### Constants & errors

`Protection` (`PAGE_*`, plus unprefixed aliases), `AllocationType` (`MEM_*`), `ProcessAccess` (`ALL`, `VM_READ`, `READ_WRITE_QUERY`, …).

All failures throw subclasses of `MemoryProcessError` with `.code` and `.win32code`.

## Examples

See [`examples/`](examples/): `basic-read.ts`, `pointer-chain.ts`, `inject-dll.ts`, `code-cave.ts`, `hook-function.ts`, `value-hunt.ts` (scanValue → nextScan → freeze).

## Platform support

|               | Node 22+ | Bun | Deno       |
| ------------- | -------- | --- | ---------- |
| Windows x64   | ✅       | ✅  | ✅ (N-API) |
| Linux / macOS | —        | —   | —          |

Windows-only in v2. The `.node` binary is runtime-agnostic N-API — the same artifact loads in Node, Bun, and Deno. Node support floor is **22** (Maintenance LTS): 24 is Active LTS, 25 is Current, 26 is the newest LTS — CI tests all of them.

## Build from source

Requires MSVC Build Tools (`cl.exe`) and `node-gyp`:

```bash
bun install
bun run build        # native addon + dist bundle
bun test             # builds tests/victim.exe + tests/testdll.dll first
```

## Migrating from v1

| v1 (memoryjs)                            | v2                               |
| ---------------------------------------- | -------------------------------- |
| `openProcess(name)` → `processObject`    | `Process.open(name)` → `Process` |
| `readMemory(handle, addr, type)`         | `proc.readInt32(addr)` etc.      |
| `writeMemory(handle, addr, val, type)`   | `proc.writeX(addr, val)`         |
| `findPattern(handle, sig, type, offset)` | `await proc.scan('AA ?? BB')`    |
| `getModules(pid)`                        | `proc.modules()`                 |
| `closeProcess(handle)`                   | `proc.close()` or `using`        |

---

MIT © JoShMiQueL
