# memoryprocess

[![npm](https://img.shields.io/npm/v/memoryprocess)](https://www.npmjs.com/package/memoryprocess)
[![CI](https://github.com/JoShMiQueL/memoryprocess/actions/workflows/ci.yml/badge.svg)](https://github.com/JoShMiQueL/memoryprocess/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

Read and write **Windows process memory** from Node.js, Bun, or Deno. N-API native addon, zero runtime dependencies, prebuilt binaries.

> **v2** — complete rewrite. Breaking changes from v1/memoryjs. See [migration](#migrating-from-v1).

## Features

- **Process** — open by name or PID, least-privilege access, `using`/dispose, process listing
- **Memory R/W** — typed scalar reads/writes (i8–i64, f32/f64, pointers), buffers, strings (UTF-8/UTF-16), fault-tolerant `readSafe`, arrays, flat structs
- **Pattern scan** — async `scan`/`scanFirst`/`scanUnique` with wildcards, module- or range-scoped, off the event loop (`Napi::AsyncWorker`)
- **Allocation & patching** - `alloc`/`free`/`protect`, `writeProtected` (+icache flush), `nop`, `patchJump`/`patchCall`, `hook`/`unhook` (E9 detour + trampoline), `execShellcode`, `disassemble` (x64 instruction lengths), `findCodeCave`
- **Modules** — enumerate, resolve by name or address, `resolveExport`, `dumpModule` to disk
- **Threads** — list/suspend/resume, `mainThread`, `getThreadContext`/`setThreadContext`, hardware breakpoints (DR0–DR3), `callRemote`
- **DLL injection** — `injectDll`/`ejectDll` round-trip via remote `LoadLibraryA`/`FreeLibrary`
- **Query** — `queryAddress` (VirtualQueryEx), `regions()`, `resolvePointer` chains, `resolveRIPRelative`, `watch` polling, `isWow64`/`pointerSize`
- **Typed errors** — `ProcessNotFoundError`, `AccessDeniedError`, `ReadError`, `WriteError`, `ScanError`, `InjectError` (each with `.code`/`.win32code`)

## Install

```bash
bun add memoryprocess    # or: npm install memoryprocess
```

Prebuilt `.node` binaries ship for `win32-x64` — **no compiler needed**. Other setups fall back to a `node-gyp` source build (requires MSVC Build Tools).

## Quickstart

```ts
import { Process } from 'memoryprocess'

using proc = Process.open('notepad.exe')   // by name or PID; auto-closes on scope exit

// typed reads / writes
const hp = proc.readInt32(addr)
proc.writeFloat(addr, 99.5)

// pattern scan (async)
const hits = await proc.scan('48 8B ?? ?? 00', { module: 'game.dll' })

// modules & regions
for (const m of proc.modules()) console.log(m.path, m.base.toString(16))
```

## API reference

### Statics

| Method | Signature | Description |
|---|---|---|
| `Process.open` | `(nameOrPid, opts?: { access? }) → Process` | Open by name or PID; least-privilege by default |
| `Process.openReadOnly` | `(nameOrPid) → Process` | Open with `VM_READ \| QUERY_INFORMATION` only |
| `Process.list` | `() → ProcessInfo[]` | All running processes `{ pid, name }` |
| `Process.find` | `(name) → ProcessInfo \| undefined` | First process matching name (case-insensitive) |

### Reads

| Method | Signature | Description |
|---|---|---|
| `readInt32` / `readUInt32` / `readFloat` / `readDouble` | `(addr) → number` | Typed scalar reads |
| `readInt64` / `readUInt64` / `readPointer` | `(addr) → bigint` | 64-bit reads |
| `readUInt8` / `readUInt16` | `(addr) → number` | Narrow reads |
| `readBuffer` | `(addr, size) → Buffer` | Raw bytes; throws `ReadError` |
| `readSafe` | `(addr, size) → Buffer` | Fault-tolerant; unreadable spans zero-filled |
| `readString` / `readWideString` | `(addr, max?) → string` | NUL-terminated UTF-8 / UTF-16 |
| `readArray` | `(addr, type, count) → Array` | Flat typed array read |
| `readStruct` | `(addr, shape) → object` | `{name: [offset, type]}` struct decode |
| `readRegion` | `(addr, size) → RegionView` | One read, local offset accessors |

### Writes

| Method | Signature | Description |
|---|---|---|
| `writeInt32` / `writeFloat` / `writePointer` / … | `(addr, v) → boolean` | Typed scalar writes (throws `WriteError`) |
| `writeBuffer` | `(addr, buf) → boolean` | Raw bytes |
| `writeString` / `writeWideString` | `(addr, str, enc?) → boolean` | String writes |
| `writeProtected` | `(addr, buf) → boolean` | Protect→write→restore→flush icache |
| `nop` | `(addr, len) → boolean` | Fill with 0x90 |
| `patchJump` | `(src, dst) → boolean` | E9 relative jump (5 bytes) |
| `patchCall` | `(src, dst) → boolean` | E8 relative call (5 bytes) |

### Code patching & hooks

| Method | Signature | Description |
|---|---|---|
| `disassemble` | `(addr, count) → Insn[]` | x64 instruction-length decode: `{ address, size, bytes }` (no mnemonics) |
| `hook` | `(src, dst) → HookHandle` | Steal ≥5 whole bytes at `src`, build trampoline stub, write E9 detour |
| `unhook` | `(handle) → boolean` | Restore stolen bytes, free stub |
| `execShellcode` | `(bytes, param?, timeoutMs?) → number \| null` | Alloc RWX → write → `callRemote` → free; returns exit code |

`HookHandle`: `{ src, dst, stub, stolen }` — call `stub` via `callRemote` to invoke the original function.

### Memory management & query

| Method | Signature | Description |
|---|---|---|
| `alloc` | `(size, prot?) → bigint` | `VirtualAllocEx` (default RWX) |
| `free` | `(addr) → boolean` | `VirtualFreeEx` |
| `protect` | `(addr, size, prot) → number` | `VirtualProtectEx`; returns old protection |
| `queryAddress` | `(addr) → MemoryInfo \| null` | `VirtualQueryEx` (base, size, state, protection, type) |
| `regions` | `() → Region[]` | All committed regions |
| `findCodeCave` | `(minLen, opts?) → bigint \| null` | Run of 0x00/0xCC in executable memory |

### Pattern scan (async)

| Method | Signature | Description |
|---|---|---|
| `scan` | `(pattern, opts?) → Promise<bigint[]>` | Hex pattern, `??`/`?` wildcards |
| `scanFirst` | `(pattern, opts?) → Promise<bigint \| null>` | First hit or null |
| `scanUnique` | `(pattern, opts?) → Promise<bigint>` | Exactly one hit, else `ScanError` |

`opts`: `{ module?, start?, end?, onlyReadable? }`.

### Modules

| Method | Signature | Description |
|---|---|---|
| `modules` | `() → ModuleInfo[]` | `{ base, size, path }` |
| `module` | `(name) → ModuleInfo \| undefined` | Exact filename match |
| `moduleFromAddress` | `(addr) → ModuleInfo \| null` | Containing module |
| `resolveExport` | `(module, export) → bigint \| null` | Export address in remote process |
| `dumpModule` | `(name, outPath) → string` | Dump module image to file |

### Threads

| Method | Signature | Description |
|---|---|---|
| `threads` | `() → number[]` | Thread IDs |
| `mainThread` | `→ number \| null` | Main thread ID |
| `suspendThread` / `resumeThread` | `(tid) → boolean` | Per-thread control |
| `suspendAll` / `resumeAll` | `() → number[] / void` | All threads (atomic patching) |
| `getThreadContext` | `(tid) → ThreadContext \| null` | rip/rsp/rbp/dr0–3/dr7/eflags (bigint) |
| `setThreadContext` | `(tid, partial) → boolean` | Write back context fields |
| `hwBreakpoint` | `(tid, addr, slot 0-3, size?) → boolean` | DR register breakpoint; **suspend first** |
| `clearHwBreakpoint` | `(tid, slot) → boolean` | Clear DR slot |
| `callRemote` | `(fnAddr, param?, timeoutMs?) → number \| null` | `CreateRemoteThread`; returns exit code |

### Injection & helpers

| Method | Signature | Description |
|---|---|---|
| `injectDll` | `(absPath) → boolean` | `LoadLibraryA` on remote thread |
| `ejectDll` | `(module \| name) → boolean` | `FreeLibrary` on remote thread |
| `resolvePointer` | `(base, offsets[]) → bigint` | Follow pointer chain |
| `resolveRIPRelative` | `(hit, offset?) → bigint` | x64 RIP-relative target |
| `watch` | `(addr, cb, ms?) → () => void` | Poll `readInt32`; returns unsubscribe |
| `isWow64` / `pointerSize` | `→ boolean / number` | Bitness info |

### Constants & errors

`Protection` (`PAGE_*`), `AllocationType` (`MEM_*`), `ProcessAccess` (`ALL`, `VM_READ`, `READ_WRITE_QUERY`, …).

All failures throw subclasses of `MemoryProcessError` with `.code` and `.win32code`.

## Examples

See [`examples/`](examples/): `basic-read.ts`, `pointer-chain.ts`, `inject-dll.ts`, `code-cave.ts`, `hook-function.ts`.

## Platform support

| | Node 20+ | Bun | Deno |
|---|---|---|---|
| Windows x64 | ✅ | ✅ | ✅ (N-API) |
| Linux / macOS | — | — | — |

Windows-only in v2. The `.node` binary is runtime-agnostic N-API — the same artifact loads in Node, Bun, and Deno.

## Build from source

Requires MSVC Build Tools (`cl.exe`) and `node-gyp`:

```bash
bun install
bun run build        # native addon + dist bundle
bun test             # builds tests/victim.exe + tests/testdll.dll first
```

## Migrating from v1

| v1 (memoryjs) | v2 |
|---|---|
| `openProcess(name)` → `processObject` | `Process.open(name)` → `Process` |
| `readMemory(handle, addr, type)` | `proc.readInt32(addr)` etc. |
| `writeMemory(handle, addr, val, type)` | `proc.writeX(addr, val)` |
| `findPattern(handle, sig, type, offset)` | `await proc.scan('AA ?? BB')` |
| `getModules(pid)` | `proc.modules()` |
| `closeProcess(handle)` | `proc.close()` or `using` |

---

MIT © JoShMiQueL
