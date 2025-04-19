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

## 📖 API References (`src`)

### Main Functions

- **openProcess(processIdentifier: string | number, callback?): Process**  
  Opens a process by name or ID. Returns the process handle or undefined if not found.

- **closeHandle(handle: number): boolean**  
  Closes a process handle.

- **getProcesses(callback?): Process[]**  
  Returns the list of running processes.

- **findModule(moduleName: string, processId: number, callback?): Module | undefined**  
  Finds a module by name in a process.

- **getModules(processId: number, callback?): Module[]**  
  Returns the modules loaded by a process.

- **readMemory<T extends DataType>(handle: number, address: number, dataType: T, callback?): MemoryData<T> | undefined**  
  Reads a value from a process's memory.

- **writeMemory(handle: number, address: number, value: any, dataType: DataType): boolean**  
  Writes a value to a process's memory.

- **findPattern(...)**  
  Scans memory patterns (multiple overloads).

- **callFunction(handle: number, args: any[], returnType: number, address: number, callback?): any**  
  Calls a function in the process's memory.

- **Debugger**  
  Utility class for process debugging. Main methods: `attach`, `detach`, `setHardwareBreakpoint`, `removeHardwareBreakpoint`, `monitor`.

- **virtualAllocEx, virtualProtectEx, getRegions, virtualQueryEx, injectDll, unloadDll, openFileMapping, mapViewOfFile**  
  Advanced memory and DLL manipulation functions.

### Main Types and Constants (`types.ts`)

- **type DataType**  
  Supported data types for memory read/write: `'byte'`, `'int32'`, `'float'`, `'string'`, `'vector3'`, etc.

- **type MemoryData<T extends DataType>**  
  Maps a `DataType` to its corresponding JS type (`number`, `bigint`, `string`, `{x,y,z}`...)

- **interface Process**  
  Information about an opened process (PID, handle, etc).

- **interface Module**  
  Information about a module loaded in a process.

- **type Protection, PageProtection, AllocationType, BreakpointTriggerType**  
  Auxiliary types for memory flags and protection.

- **const FunctionTypes, SignatureTypes, MemoryAccessFlags, MemoryPageFlags, HardwareDebugRegisters, BreakpointTriggerTypes**  
  Constants for flags and function types.

---

> See the [`src`](./src) folder for full details and comments on each function/type.
