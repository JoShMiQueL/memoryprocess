# memoryprocess

Read and write **Windows process memory** from Node.js, Bun or Deno. N-API native addon, zero runtime dependencies, prebuilt binaries.

> **v2** — complete rewrite. Breaking changes from v1/memoryjs.

```ts
import { Process } from 'memoryprocess'

using proc = Process.open('notepad.exe')

const hp = proc.readInt32(baseAddr + 0x10)
proc.writeFloat(addr, 99.5)

const hits = await proc.scan('48 8B ?? ?? 00', { module: 'game.dll' })
```

## Install

```bash
npm install memoryprocess   # or: bun add memoryprocess
```

Prebuilt `.node` binaries ship for `win32-x64` — **no compiler needed**. Falls back to `node-gyp` build from source on other setups (requires MSVC).

## API

### `Process.open(nameOrPid, access?)`

Open a process by name (`"notepad.exe"`, case-insensitive) or PID. Returns a `Process`. Throws `ProcessNotFoundError` / `AccessDeniedError`.

```ts
const proc = Process.open('game.exe')
// or
const proc = Process.open(12345)
```

**`using`** support — auto-closes the handle when leaving scope:

```ts
{
  using proc = Process.open('game.exe')
  proc.readInt32(addr)
} // handle closed here
```

### Reads (synchronous, hot path)

```ts
proc.readInt32(addr)      // number
proc.readUInt32(addr)     // number
proc.readInt64(addr)      // bigint
proc.readUInt64(addr)     // bigint
proc.readFloat(addr)      // number
proc.readDouble(addr)     // number
proc.readPointer(addr)    // bigint (deref a pointer)
proc.readBuffer(addr, n)  // Buffer
proc.readString(addr, max=256) // string (NUL-terminated)
```

### Writes (synchronous)

```ts
proc.writeInt32(addr, v)
proc.writeUInt32(addr, v)
proc.writeInt64(addr, v)
proc.writeFloat(addr, v)
proc.writeDouble(addr, v)
proc.writePointer(addr, v)
```

### Modules & regions

```ts
proc.modules()        // [{ base, size, path }]
proc.module('x.dll')  // { base, size, path } | undefined
proc.regions()        // [{ baseAddress, size, protection, type }]
```

### Pattern scan (async — `Napi::AsyncWorker`, doesn't block the loop)

```ts
const hits = await proc.scan('48 8B ?? ?? 00')           // all readable regions
const hits = await proc.scan('DE AD BE EF', {
  module: 'game.dll',          // scope to a module's range
  // or explicit:
  start: 0x140000000n,
  end:   0x141000000n,
  onlyReadable: true,
})
// → bigint[] of matching addresses
```

Pattern bytes are hex, `??` or `?` = wildcard byte.

### Static helpers

```ts
Process.list()                 // [{ pid, name }] — no handle needed
Process.find('notepad')        // { pid, name } | undefined
```

### Errors

Typed subclasses of `MemoryProcessError`:

```ts
try {
  Process.open('missing.exe')
} catch (e) {
  if (e instanceof ProcessNotFoundError) { /* ... */ }
}
// ProcessNotFoundError, AccessDeniedError, ReadError, WriteError
// each has .code and .win32code
```

## Platform support

| | Node | Bun | Deno |
|---|---|---|---|
| Windows x64 | ✅ | ✅ | ✅ (N-API) |
| Linux / macOS | — | — | — |

Windows-only in v2.

## Migrating from v1

| v1 (memoryjs) | v2 |
|---|---|
| `openProcess(name)` → `processObject` | `Process.open(name)` → `Process` |
| `readMemory(handle, addr, type)` | `proc.read<T>(addr)` / `proc.readInt32(addr)` |
| `writeMemory(handle, addr, val, type)` | `proc.writeX(addr, val)` |
| `findPattern(handle, sig, type, offset)` | `await proc.scan('AA ?? BB')` |
| `getModules(pid)` | `proc.modules()` |
| `closeProcess(handle)` | `proc.close()` or `using` |

---

MIT © JoShMiQueL
