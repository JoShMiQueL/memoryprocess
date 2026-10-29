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
- **Cheat-dev helpers** — `Address`/`addr()`/`pointers()` CE-style pointer chains, `Entity`/`entityList()` typed struct views, `readMany` page-batched reads, `findPointersTo` pointer-scan, `Offsets` sig databases (cs2-dumper + hazedumper)
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

| Method         | Signature                                             | Description                                                                                             |
| -------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `alloc`        | `(size, prot?, nearAddr?) → bigint`                   | `VirtualAllocEx` (default RWX; `nearAddr` = hint)                                                       |
| `free`         | `(addr) → boolean`                                    | `VirtualFreeEx`                                                                                         |
| `protect`      | `(addr, size, prot) → number`                         | `VirtualProtectEx`; returns old protection                                                              |
| `queryAddress` | `(addr) → Region & { allocationBase, state } \| null` | `VirtualQueryEx` on one address — region fields plus `allocationBase`/`state` (MEM_COMMIT/RESERVE/FREE) |
| `regions`      | `() → Region[]`                                       | All committed regions                                                                                   |
| `findCodeCave` | `(minLen, opts?) → bigint \| null`                    | Run of 0x00/0xCC in executable memory                                                                   |

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

| Method                             | Signature                                       | Description                                                                                                                                                             |
| ---------------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threads`                          | `() → number[]`                                 | Thread IDs                                                                                                                                                              |
| `mainThread`                       | `→ number \| null` (getter)                     | Main thread ID                                                                                                                                                          |
| `suspendThread` / `resumeThread`   | `(tid) → boolean`                               | Per-thread control                                                                                                                                                      |
| `suspendAll` / `resumeAll`         | `() → number[]` / `() → void`                   | All threads                                                                                                                                                             |
| `suspendProcess` / `resumeProcess` | `() → boolean`                                  | Atomic `NtSuspendProcess`/`NtResumeProcess`                                                                                                                             |
| `getThreadContext`                 | `(tid) → ThreadContext \| null`                 | rip/rsp/rbp/dr0–3/dr7/eflags (bigint)                                                                                                                                   |
| `setThreadContext`                 | `(tid, partial) → boolean`                      | Write back context fields                                                                                                                                               |
| `hwBreakpoint`                     | `(tid, addr, slot 0-3, size?, kind?) → boolean` | DR register breakpoint; `kind`: `'exec'`/`'write'`/`'readwrite'` — **suspend first**; without a debugger a hit crashes the target (use `findWhatWrites` for write hits) |
| `clearHwBreakpoint`                | `(tid, slot) → boolean`                         | Clear DR slot                                                                                                                                                           |
| `callRemote`                       | `(fnAddr, param?, timeoutMs?) → number \| null` | `CreateRemoteThread`; returns exit code                                                                                                                                 |
| `waitForExit`                      | `(timeoutMs?) → Promise<number \| null>`        | Process exit code, or null on timeout                                                                                                                                   |
| `findWhatWrites`                   | `(addr, opts?) → Promise<Hit[]>`                | CE "find what writes": temporary debugger + hardware write breakpoint on all threads; returns `{rip, tid, threadContext}[]`                                             |

`findWhatWrites` opts: `{ size?: 1|2|4|8 = 4, timeoutMs? = 1000 (max 60000), maxHits? = 32 (max 1024) }`. Attaches a temporary debugger, watches for `timeoutMs`, then detaches leaving the target running. `rip` points at the instruction _following_ the write (trap semantics, same as CE). Needs debug rights — call `Process.enableDebugPrivilege()` first.

### Injection & helpers

| Method                    | Signature                      | Description                           |
| ------------------------- | ------------------------------ | ------------------------------------- |
| `injectDll`               | `(absPath) → boolean`          | `LoadLibraryA` on remote thread       |
| `ejectDll`                | `(module \| name) → boolean`   | `FreeLibrary` on remote thread        |
| `resolvePointer`          | `(base, offsets[]) → bigint`   | Follow pointer chain                  |
| `resolveRIPRelative`      | `(hit, offset?) → bigint`      | x64 RIP-relative target               |
| `watch`                   | `(addr, cb, ms?) → () => void` | Poll `readInt32`; returns unsubscribe |
| `isWow64` / `pointerSize` | getters → `boolean` / `number` | Bitness info                          |

### Cheat-dev helpers

High-level Cheat Engine–style API layered over the primitives. Exported classes: `Address`, `Entity`, `EntityList`, `Offsets`; types: `EntitySchema`, `FieldType`, `SigEntry`, `OffsetsJson`, `EntityListOptions`.

| Method           | Signature                                      | Description                                                        |
| ---------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| `addr`           | `(base, ...chain) → Address`                   | Fluent pointer-chain address (see forms below)                     |
| `pointers`       | `({name: [base, ...chain]}) → {name: Address}` | Named CE-style address table; resolves lazily                      |
| `entity`         | `(addr, schema) → Entity`                      | Typed struct view: `snapshot()` (one read) / `read`/`write` fields |
| `entityList`     | `(opts) → EntityList`                          | Iterable entity walk — array `stride` or linked-list `next`        |
| `readMany`       | `(reqs) → (number \| bigint \| null)[]`        | Page-batched bulk read — one `readSafe` per touched 4KB page       |
| `findPointersTo` | `(target, opts?) → Promise<bigint[]>`          | "Who points at this" — finds aligned locations storing `target`    |
| `offsets`        | `(json) → Offsets`                             | Parse a sig/offset database bound to this process                  |

**`addr` / `Address` forms** — the canonical form spells the module and RVA as separate args:

```ts
proc.addr('game.exe', 0x1f2a3c, 0x10, 0x28, 0x8); // canonical: module, rva, ...chain
proc.addr('game.exe+0x1F2A3C', 0x10, 0x28, 0x8); // CE paste-friendly
proc.addr(mod.base + 0x1f2a3cn, 0x10, 0x28, 0x8); // raw bigint base
```

In the `'mod+rva'` and bigint forms every `chain` offset is a dereference hop — the rva is already inside the base. Writing `addr('mod+0x100', 0x100, …)` (rva repeated as `chain[0]`) throws `AMBIGUOUS_ADDRESS_EXPR`; pass the numeric base if that deref is really intended. Malformed expressions throw `INVALID_ADDRESS_EXPR`, a missing module `MODULE_NOT_FOUND` (all `MemoryProcessError` subclasses via `.code`).

The returned `Address` has `.base`/`.chain` (immutable — `.add(off)` derives a new one), `.resolve()`/`.ptr()` for the final address, and typed `readX`/`writeX`/`readBuffer`/`readString` methods that resolve-then-access.

**`pointers`** — a named chain table; nothing touches memory until a read/resolve:

```ts
const p = proc.pointers({
  health: ['game.exe', 0x1f2a3c, 0x10, 0x28, 0x8],
  money: ['game.exe+0x2B4D80', 0x8],
});
p.health.readInt32();
p.money.writeInt32(999);
```

**`entity`** — `schema` maps field names to `[offset, type]`. `FieldType`: `'int32'|'uint32'|'int64'|'uint64'|'float'|'double'|'pointer'|'string:N'|'wstring:N'|'vec2'|'vec3'|'vec4'|'ref'`. `snapshot()` does ONE `readBuffer` covering the whole schema — cheap per-frame read for ESP/aimbot loops.

**`entityList`** — `{ first, stride | next, schema?, max? = 4096 }`. `stride` = array element size; `next` = offset of the next-pointer inside each node. Yields addresses, or `Entity` views when `schema` is set. Iterable + `toArray()`.

**`readMany`** — `reqs`: `{ addr, type }[]` where `type` is `'int32'|'uint32'|'int64'|'uint64'|'float'|'double'|'pointer'`; returns `null` per entry that can't be decoded.

**`findPointersTo`** — shallow pointer-scan (encodes `target` as u64 via `scanValue`). `opts`: `{ module?, start?, end?, onlyWritable? = true, alignment? = pointerSize }`.

**`offsets` / `Offsets`** — parses both real dumper layouts:

- **cs2/GH-dumper**: `{ "client.dll": { "dwEntityList": 0xDEB99C, … } }` — module-keyed RVA maps.
- **hazedumper**: `{ signatures: { name: {module, pattern, offsets, extra, relative, read, rva} }, netvars: { name: offset } }` — AOB-scan entries.

```ts
const off = proc.offsets(json);
await off.ready(); // resolves + caches all entries
off.dwLocalPlayer.readInt32(); // each resolved name is an Address
off.netvars.m_iHealth; // netvars are plain field-offset numbers
await off.resolve('dwEntityList'); // → bigint address (cached)
await off.addr('name'); // → Address
await off.resolveAll(); // → { name: bigint }
off.keys(); // all loaded offset names
// Also usable unbound: const db = Offsets.load(json); db.bind(proc);
```

`SigEntry` fields: `pattern` (AOB with `?` wildcards), `module`, `offsets` (rip-displacement position / deref chain), `extra` (hazedumper addend), `relative` (RIP-relative operand), `read` (`'u32'|'u64'|'ptr'` deref width at `hit + offsets[0]`), `rva` (static module offset). Unknown names throw `UNKNOWN_OFFSET`, malformed entries `INVALID_OFFSET_ENTRY`.

### Constants & errors

`Protection` (`PAGE_*`, plus unprefixed aliases), `AllocationType` (`MEM_*`), `ProcessAccess` (`ALL`, `VM_READ`, `READ_WRITE_QUERY`, …).

All failures throw subclasses of `MemoryProcessError` with `.code` and `.win32code`.

## Examples

See [`examples/`](examples/): `basic-read.ts`, `pointer-chain.ts`, `pointer-chains.ts` (addr/pointers/Offsets cheat-table), `inject-dll.ts`, `code-cave.ts`, `hook-function.ts`, `value-hunt.ts` (scanValue → nextScan → freeze).

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
