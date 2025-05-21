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
    <img alt="NPM Downloads" src="https://img.shields.io/npm/dy/memoryprocess">
  </a>
  <a href="https://www.npmjs.com/package/memoryprocess" target="_blank">
    <img alt="NPM Version" src="https://img.shields.io/npm/v/memoryprocess">
  </a>
</p>

---

## 🚀 Installation

Install the package using npm:

```bash
npm install memoryprocess
```

Or using yarn:

```bash
yarn add memoryprocess
```

## ✨ Features

*   Read and write to process memory with support for various data types.
*   List processes, modules, and threads.
*   Advanced pattern scanning with wildcard support (`??`).
*   Scan specific memory regions for patterns.
*   Hardware breakpoints and debugging utilities.
*   DLL injection and uninjection.
*   Memory allocation and protection.
*   Improved error handling and input validation for more robust behavior.

## ⚙️ Bundling with Bun
If you want to bundle your `.ts` code to `.js` using Bun, add `memoryprocess` to the `--external` option when running `bun build`. For example:

```bash
bun build src/index.ts --external memoryprocess
```

## 📖 API Reference

**Note:** Many functions have been enhanced with improved error handling and input validation at both the JavaScript and native C++ layers, leading to more predictable and stable behavior. If invalid arguments are provided, functions will typically throw errors.

### Main Functions

- **`openProcess(processIdentifier: string | number, callback?: (error: string | null, process: Process | undefined) => void): Process | undefined`**  
  Opens a process by its name (string) or ID (number).
  Returns a `Process` object if successful (without callback) or `undefined` on failure.
  If a callback is provided, it will be called with `(error, process)`.

  *Example:*
  ```javascript
  const memory = require('memoryprocess');
  try {
    const processObject = memory.openProcess('notepad.exe');
    if (processObject) {
      console.log('Notepad Handle:', processObject.handle);
      memory.closeHandle(processObject.handle);
    } else {
      console.log('Notepad not found or could not be opened.');
    }
  } catch (e) {
    console.error('Error opening process:', e.message);
  }
  ```

- **`closeHandle(handle: number): boolean`**  
  Closes an opened process handle. Returns `true` on success, `false` on failure.

- **`getProcesses(callback?: (error: string | null, processes: Process[] | undefined) => void): Process[] | undefined`**  
  Retrieves a list of all currently running processes.
  Returns an array of `Process` objects or `undefined`.
  If a callback is provided, it will be called with `(error, processes)`.

- **`getThreads(processId: number): ThreadEntry[]`**
  Retrieves a list of threads running in the specified process.
  Requires a valid `processId` (must be a positive number).
  Returns an array of `ThreadEntry` objects, each describing a thread. Throws an error if the `processId` is invalid or if the underlying native call fails.

  *Example:*
  ```javascript
  const memory = require('memoryprocess');
  // Assuming 'processObject' is obtained from openProcess and is valid
  // try {
  //   const threads = memory.getThreads(processObject.th32ProcessID);
  //   if (threads.length > 0) {
  //     console.log(`Threads in ${processObject.szExeFile}:`);
  //     threads.forEach(thread => {
  //       console.log(`  Thread ID: ${thread.threadId}, Owner PID: ${thread.ownerProcessId}, Priority: ${thread.basePriority}`);
  //     });
  //   } else {
  //     console.log(`No threads found for ${processObject.szExeFile}.`);
  //   }
  // } catch (e) {
  //   console.error("Error getting threads:", e.message);
  // }
  ```
  *(Note: The example above is commented out as it requires a running process.)*

- **`findModule(moduleName: string, processId: number, callback?: (error: string | null, module: Module | undefined) => void): Module | undefined`**  
  Finds a module by its name within a specific process ID.
  Returns a `Module` object or `undefined`.

- **`getModules(processId: number, callback?: (error: string | null, modules: Module[] | undefined) => void): Module[] | undefined`**  
  Retrieves a list of all modules loaded by a given process ID.
  Returns an array of `Module` objects or `undefined`.

- **`readMemory<T extends DataType>(handle: number, address: number | bigint, dataType: T, callback?: (error: string | null, value: MemoryData<T> | undefined) => void): MemoryData<T> | undefined`**  
  Reads a value of `dataType` from the specified memory `address` in the process with `handle`.
  `address` can be a `number` or `bigint`.

- **`writeMemory(handle: number, address: number | bigint, value: any, dataType: DataType): boolean`**  
  Writes `value` to the specified memory `address` using `dataType`.
  `address` can be a `number` or `bigint`. Returns `true` on success.

#### Pattern Scanning

Pattern strings support `??` as a wildcard to match any byte. For example, `"AB ?? CD"` will match `AB` followed by any byte, then `CD`.

- **`findPattern(...)`**  
  A versatile function to scan for memory patterns. It has several overloads (differentiated by argument types and count at runtime):
    *   Global scan: `findPattern(handle: number, pattern: string, flags?: number, patternOffset?: number, callback?): number | bigint | undefined`
    *   Scan in a specific module: `findPattern(handle: number, moduleName: string, pattern: string, flags?: number, patternOffset?: number, callback?): number | bigint | undefined`
    *   Scan starting from a base address: `findPattern(handle: number, baseAddress: number | bigint, pattern: string, flags?: number, patternOffset?: number, callback?): number | bigint | undefined`
  Returns the found address (number or BigInt) or `0` (`0n`) if not found (when no callback is used).
  The `flags` parameter can be used with `SignatureTypes` constants (e.g., `ST_READ`, `ST_SUBTRACT`).

  *Example (Global scan with wildcard):*
  ```javascript
  const memory = require('memoryprocess');
  // Assuming 'processObject' is obtained from openProcess
  // const pattern = "48 89 5C 24 ?? 57 48 83 EC 20"; // Example pattern with wildcard
  // const foundAddress = memory.findPattern(processObject.handle, pattern, memory.SignatureTypes.ST_NORMAL, 0);
  // if (foundAddress && foundAddress !== 0 && foundAddress !== 0n) {
  //   console.log(`Pattern found at: 0x${foundAddress.toString(16)}`);
  // } else {
  //   console.log("Pattern not found.");
  // }
  ```
  *(Note: The example above is commented out as it requires a running process and a valid pattern for that process to work directly.)*


- **`findPatternInRegion(handle: number, baseAddress: number | bigint, scanSize: number | bigint, pattern: string, flags: number = 0, patternOffset: number = 0): number | bigint`**  
  Scans a specific region of memory for a given pattern.
    *   `handle`: The handle of the process.
    *   `baseAddress`: The starting address of the memory region to scan (number or BigInt, must be > 0).
    *   `scanSize`: The size of the memory region to scan (number or BigInt, must be > 0).
    *   `pattern`: The pattern string to search for (e.g., `"AB ?? CD EF"`). Wildcard `??` is supported.
    *   `flags` (optional, default 0): Native flags such as `SignatureTypes.ST_READ` or `SignatureTypes.ST_SUBTRACT`.
    *   `patternOffset` (optional, default 0): Offset added to the found pattern's address.
  Returns the memory address (number or BigInt) where the pattern was found, or `0` (or `0n`) if not found. Throws an error on invalid input or if the native call fails.

  *Example:*
  ```javascript
  const memory = require('memoryprocess');
  // Assuming 'processObject' is obtained from openProcess and is valid
  // const regionStart = 0x140000000; // Example base address
  // const regionSize = 1024 * 1024;    // Scan 1MB
  // const searchPattern = "8B ?? FF ?? 00"; // Example pattern
  // try {
  //   const address = memory.findPatternInRegion(
  //     processObject.handle,
  //     regionStart,
  //     regionSize,
  //     searchPattern
  //   );
  //   if (address && address !== 0 && address !== 0n) {
  //     console.log(`Pattern found in region at: 0x${address.toString(16)}`);
  //   } else {
  //     console.log("Pattern not found in the specified region.");
  //   }
  // } catch (e) {
  //   console.error("Error scanning region:", e.message);
  // }
  ```
  *(Note: The example above is commented out as it requires a running process and a valid pattern/region for that process to work directly.)*


- **`callFunction(handle: number, args: any[], returnType: number, address: number | bigint, callback?): any`**  
  Calls a function located at `address` in the target process's memory.
  `args` is an array of arguments for the function. `returnType` specifies the expected return type (use `FunctionTypes` constants).
  `address` can be a `number` or `bigint`.

- **`Debugger`**  
  A utility class for process debugging. Provides methods like:
    *   `attach(processId: number, killOnDetach?: boolean): boolean`
    *   `detach(processId: number): boolean`
    *   `setHardwareBreakpoint(processId: number, address: number | bigint, register: number, trigger: number, length: number): number` (returns the register used)
    *   `removeHardwareBreakpoint(processId: number, register: number): boolean`
    *   `monitor(register: number, timeout?: number)`: Internal method to start monitoring a specific register for breakpoint events. Debug events are emitted via `EventEmitter` methods (`on`, `emit`).

- **Advanced Functions:**
  `virtualAllocEx`, `virtualProtectEx`, `getRegions`, `virtualQueryEx`, `injectDll`, `unloadDll`, `openFileMapping`, `mapViewOfFile`.
  These functions provide lower-level control over process memory, protection, DLLs, and file mapping. Refer to their JSDoc comments in `src/memoryprocess.ts` for detailed signatures and usage.

### Main Types and Constants (`types.ts`)

- **`type DataType`**  
  Defines supported data types for memory read/write operations, e.g., `'byte'`, `'int'`, `'int32'`, `'uint32'`, `'int64'`, `'uint64'`, `'float'`, `'double'`, `'bool'`, `'string'`, `'vector3'`, `'vector4'`, `'pointer'`. Includes big-endian variants like `'int32_be'`.

- **`type MemoryData<T extends DataType>`**  
  A utility type that maps a `DataType` string to its corresponding JavaScript type (e.g., `number` for `'int32'`, `bigint` for `'int64'`, `string` for `'string'`, `{x,y,z}` for `'vector3'`).

- **`interface Process`**  
  Contains information about an opened process, including:
    *   `dwSize`: Size of the structure.
    *   `th32ProcessID`: Process ID.
    *   `cntThreads`: Number of execution threads started by the process.
    *   `szExeFile`: Executable file name.
    *   `handle`: The opened handle to the process.
    *   `modBaseAddr`: Base address of the main module (usually a `bigint`).

- **`interface Module`**  
  Contains information about a module loaded in a process, including:
    *   `modBaseAddr`: Base address of the module (usually a `bigint`).
    *   `modBaseSize`: Size of the module in bytes.
    *   `szExePath`: Full path to the module file.
    *   `szModule`: Name of the module.

- **`interface ThreadEntry`**
  Describes a thread within a process:
    *   `threadId: number` - The unique identifier for the thread (TID).
    *   `ownerProcessId: number` - The identifier of the process that owns the thread (PID). This should match the `processId` used to query for threads.
    *   `basePriority: number` - The base priority level of the thread.

- **Constants:**
    *   `FunctionTypes`: For `callFunction` return types (e.g., `T_STRING`, `T_INT`, `T_FLOAT`).
    *   `SignatureTypes`: For pattern scanning flags (`ST_NORMAL`, `ST_READ`, `ST_SUBTRACT`).
    *   `MemoryAccessFlags`, `MemoryPageFlags`, `MemoryAllocationFlags`: For memory protection and allocation.
    *   `HardwareDebugRegisters`, `BreakpointTriggerTypes`: For use with the `Debugger`.

---

> See the [`src`](./src) folder for full JSDoc comments and details on each function/type.
