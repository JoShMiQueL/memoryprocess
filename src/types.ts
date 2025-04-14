// Windows-specific types
export type HANDLE = number;
export type DWORD = number;
export type DWORD64 = bigint;
export type BOOL = boolean;
export type SIZE_T = number;

// Process types
export interface ProcessEntry {
  dwSize: number;
  cntUsage: number;
  th32ProcessID: number;
  th32DefaultHeapID: bigint;
  th32ModuleID: number;
  cntThreads: number;
  th32ParentProcessID: number;
  pcPriClassBase: number;
  dwFlags: number;
  szExeFile: string;
}

export interface ProcessInfo {
  handle: HANDLE;
  process: ProcessEntry;
}

// Memory types
export interface MemoryBasicInformation {
  BaseAddress: DWORD64;
  AllocationBase: DWORD64;
  AllocationProtect: DWORD;
  RegionSize: SIZE_T;
  State: DWORD;
  Protect: DWORD;
  Type: DWORD;
}

// Module types
export interface ModuleEntry {
  modBaseAddr: DWORD64;
  modBaseSize: DWORD;
  szExePath: string;
  szModule: string;
  th32ProcessID: DWORD;
}

// Memory data types
export type DataType = 
  | 'int64'
  | 'uint64'
  | 'int32'
  | 'uint32'
  | 'int'
  | 'uint'
  | 'int16'
  | 'uint16'
  | 'short'
  | 'ushort'
  | 'float'
  | 'double'
  | 'ptr'
  | 'bool'
  | 'string'
  | 'vector3'
  | 'vector4'
  | 'int64_be'
  | 'uint64_be'
  | 'int32_be'
  | 'uint32_be'
  | 'int_be'
  | 'uint_be'
  | 'int16_be'
  | 'uint16_be'
  | 'short_be'
  | 'ushort_be'
  | 'float_be'
  | 'double_be';

// Function types
export type Callback<T> = (error: Error | null, result: T) => void;

// Memory protection constants
export enum Protection {
  PAGE_NOACCESS = 0x01,
  PAGE_READONLY = 0x02,
  PAGE_READWRITE = 0x04,
  PAGE_WRITECOPY = 0x08,
  PAGE_EXECUTE = 0x10,
  PAGE_EXECUTE_READ = 0x20,
  PAGE_EXECUTE_READWRITE = 0x40,
  PAGE_EXECUTE_WRITECOPY = 0x80,
  PAGE_GUARD = 0x100,
  PAGE_NOCACHE = 0x200,
  PAGE_WRITECOMBINE = 0x400
}

// Memory allocation types
export enum AllocationType {
  MEM_COMMIT = 0x1000,
  MEM_RESERVE = 0x2000,
  MEM_RESET = 0x80000,
  MEM_TOP_DOWN = 0x100000,
  MEM_WRITE_WATCH = 0x200000,
  MEM_PHYSICAL = 0x400000,
  MEM_RESET_UNDO = 0x1000000,
  MEM_LARGE_PAGES = 0x20000000
}

// Structron types
export type BufferEncoding = 'ascii' | 'utf8' | 'utf-8' | 'utf16le' | 'ucs2' | 'ucs-2' | 'base64' | 'base64url' | 'latin1' | 'binary' | 'hex';

export interface MemoryJS {
  readMemory(handle: number, address: number, dataType: string): any;
  writeMemory(handle: number, address: number, value: any, dataType: string): void;
  readBuffer(handle: number, address: number, size: number): Buffer;
  STRING: string;
  INT: string;
  UINT32: string;
  POINTER: string;
}

export interface StructronContext {
  handle: number;
  address: number;
  buffer: Buffer;
}