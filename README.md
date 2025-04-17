> ⚠️ **WARNING:**
> This package relies heavily on **Bun's native FFI (`bun:ffi`)** for performance and interacting with system APIs.
> Furthermore, it interacts directly with the Windows API and is therefore **only compatible with Windows**.
> 
> Currently, Bun does not provide a polyfill for `bun:ffi` when building for Node.js (`target: 'node'`). Therefore, this package is **only compatible with the Bun runtime** and **will not work** if run directly with Node.js.
> 
> While Bun intends to add polyfills for `bun:*` modules in the future to improve Node.js compatibility for bundled code (see [Bundler Docs](https://bun.sh/docs/bundler#target)), this is not yet implemented for `bun:ffi`.
> 
> **Requirements:**
> *   Bun v1.2.9 or later (required to run the code)

---

<p align="center">
  <img alt="Banner" src="assets/banner.png">
  <br>
  <code>MemoryProcess</code> is an NPM package to read and write process memory
  <br>
  This is a fork of the original <a href="https://github.com/Rob--/memoryjs">memoryjs</a> package, maintained by <a href="https://github.com/JoShMiQueL">JoShMiQueL</a>
</p>

<p align="center">
  <img alt="GitHub License" src="https://img.shields.io/github/license/JoShMiQueL/memoryprocess">
  <a href="https://github.com/JoShMiQueL/memoryprocess/actions/workflows/publish-npm.yml" target="_blank">
    <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/JoShMiQueL/memoryprocess/release.yml?branch=master&style=flat&logo=npm&label=Publish%20to%20npm">
  </a>
  <a href="https://www.npmjs.com/package/memoryprocess" target="_blank">
    <img alt="NPM Downloads" src="https://img.shields.io/npm/dy/%40memoryprocess">
  </a>
  <a href="https://www.npmjs.com/package/memoryprocess" target="_blank">
    <img alt="NPM Version" src="https://img.shields.io/npm/v/%40memoryprocess">
  </a>
</p>

## Current Status

This package is currently under active development. The following core functions are implemented and available for use:

*   `openProcess(processIdentifier: string | number): ProcessInfo`: Opens a process by its name or ID.
*   `closeProcess(handle: number): void`: Closes an opened process handle.
*   `readMemory(handle: number, address: number, dataType: string): any`: Reads memory from a specific address in the target process.
*   `writeMemory(handle: number, address: number, value: any, dataType: string): void`: Writes memory to a specific address in the target process.

The `ProcessInfo` object returned by `openProcess` contains information about the opened process:

```typescript
interface ProcessInfo {
  handle: number;      // Process handle
  processId: number;   // Process ID (PID)
  baseAddress: number; // Base address of the main module
  size: number;        // Size of the main module
  path: string;        // Full path to the process executable
}
```

More functions are planned for future releases to expand the capabilities of this library.

## Data Types

The `dataType` parameter in `readMemory` and `writeMemory` specifies the type of data to be read or written. It accepts a specific set of string literals defined by the `MemoryDataType` type in TypeScript. The `value` parameter for `writeMemory` should correspond to this type, as defined by `MemoryValueType` (number, string, or boolean).

The following data type strings (and their aliases) are supported:

*   **8-bit Signed:** `byte`, `int8`, `char`
*   **8-bit Unsigned:** `ubyte`, `uint8`, `uchar`
*   **16-bit Signed:** `short`, `int16`
*   **16-bit Unsigned:** `ushort`, `uint16`, `word`
*   **32-bit Signed:** `int`, `int32`, `long`
*   **32-bit Unsigned:** `uint`, `uint32`, `ulong`, `dword`
*   **64-bit Signed:** `longlong`, `int64` (uses BigInt)
*   **64-bit Unsigned:** `ulonglong`, `uint64` (uses BigInt)
*   **Floating Point:** `float` (4 bytes), `double` (8 bytes)
*   **Boolean:** `bool` (1 byte, 0 or 1)
*   **String:** `string`, `str` (Null-terminated UTF-8)
