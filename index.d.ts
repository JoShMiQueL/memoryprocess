declare module '@joshmiquel/memoryjs' {
  export type DataType = 
    | 'byte' | 'ubyte' | 'char' | 'uchar' | 'int8' | 'uint8'
    | 'int16' | 'int16_be' | 'uint16' | 'uint16_be'
    | 'short' | 'short_be' | 'ushort' | 'ushort_be'
    | 'long' | 'long_be' | 'ulong' | 'ulong_be'
    | 'int' | 'int_be' | 'uint' | 'uint_be'
    | 'int32' | 'int32_be' | 'uint32' | 'uint32_be'
    | 'int64' | 'int64_be' | 'uint64' | 'uint64_be'
    | 'dword' | 'dword_be' | 'qword' | 'qword_be'
    | 'float' | 'float_be' | 'double' | 'double_be'
    | 'bool' | 'boolean' | 'ptr' | 'pointer' | 'string' | 'vec3' | 'vec4' | 'vector3' | 'vector4';

  export interface Process {
    dwSize: number;
    th32ProcessID: number;
    cntThreads: number;
    th32ParentProcessID: number;
    pcPriClassBase: number;
    szExeFile: string;
    handle: number;
    modBaseAddr: number;
    modBaseSize: number;
  }

  export interface Module {
    modBaseAddr: number;
    modBaseSize: number;
    szExePath: string;
    szModule: string;
    th32ProcessID: number;
  }

  export interface Region {
    BaseAddress: number;
    RegionSize: number;
    State: number;
    Protection: number;
    Type: number;
  }

  export interface Vector3 {
    x: number;
    y: number;
    z: number;
  }

  export interface Vector4 extends Vector3 {
    w: number;
  }

  // Callback types
  type ProcessCallback = (error: Error | null, process: Process) => void;
  type ProcessesCallback = (error: Error | null, processes: Process[]) => void;
  type ModuleCallback = (error: Error | null, module: Module) => void;
  type ModulesCallback = (error: Error | null, modules: Module[]) => void;
  type MemoryCallback<T> = (error: Error | null, value: T) => void;
  type RegionsCallback = (error: Error | null, regions: Region[]) => void;

  // Main functions
  export function openProcess(processIdentifier: string | number, callback?: ProcessCallback): Process;
  export function closeProcess(handle: number): void;
  export function getProcesses(callback?: ProcessesCallback): Process[];
  export function findModule(moduleName: string, processId: number, callback?: ModuleCallback): Module;
  export function getModules(processId: number, callback?: ModulesCallback): Module[];

  // Memory operations
  export function readMemory<T>(handle: number, address: number, dataType: DataType, callback?: MemoryCallback<T>): T;
  export function readMemoryBE<T>(handle: number, address: number, dataType: DataType, callback?: MemoryCallback<T>): T;
  export function writeMemory<T>(handle: number, address: number, value: T, dataType: DataType): void;
  export function writeMemoryBE<T>(handle: number, address: number, value: T, dataType: DataType): void;
  
  export function readBuffer(handle: number, address: number, size: number, callback?: MemoryCallback<Buffer>): Buffer;
  export function writeBuffer(handle: number, address: number, buffer: Buffer): void;

  // Pattern scanning
  export function findPattern(
    handle: number,
    pattern: string,
    flags?: number,
    patternOffset?: number,
    addressOffset?: number
  ): number;

  // Memory management
  export function virtualAllocEx(
    handle: number,
    address: number,
    size: number,
    allocationType: number,
    protection: number,
    callback?: MemoryCallback<number>
  ): number;

  export function virtualProtectEx(
    handle: number,
    address: number,
    size: number,
    protection: number,
    callback?: MemoryCallback<number>
  ): number;

  export function getRegions(
    handle: number,
    getOffsets?: boolean,
    callback?: RegionsCallback
  ): Region[];

  export function virtualQueryEx(
    handle: number,
    address: number,
    callback?: MemoryCallback<Region>
  ): Region;

  // DLL injection
  export function injectDll(
    handle: number,
    dllPath: string,
    callback?: MemoryCallback<number>
  ): number;

  export function unloadDll(
    handle: number,
    module: Module,
    callback?: MemoryCallback<void>
  ): void;

  // File mapping
  export function openFileMapping(fileName: string): number;
  export function mapViewOfFile(
    processHandle: number,
    fileHandle: number,
    offset: number,
    viewSize: number,
    pageProtection: number
  ): number;

  // Constants
  export const PROCESS_ALL_ACCESS: number;
  export const PAGE_EXECUTE_READWRITE: number;
  export const MEM_COMMIT: number;
  export const MEM_RESERVE: number;
  export const MEM_RELEASE: number;
}
