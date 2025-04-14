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
  | 'byte'
  | 'ubyte'
  | 'char'
  | 'uchar'
  | 'int8'
  | 'uint8'
  | 'int16'
  | 'uint16'
  | 'short'
  | 'ushort'
  | 'long'
  | 'ulong'
  | 'int'
  | 'uint'
  | 'int32'
  | 'uint32'
  | 'int64'
  | 'uint64'
  | 'word'
  | 'dword'
  | 'float'
  | 'double'
  | 'bool'
  | 'boolean'
  | 'ptr'
  | 'pointer'
  | 'uptr'
  | 'upointer'
  | 'str'
  | 'string'
  | 'vec3'
  | 'vector3'
  | 'vec4'
  | 'vector4'
  | 'int16_be'
  | 'uint16_be'
  | 'short_be'
  | 'ushort_be'
  | 'long_be'
  | 'ulong_be'
  | 'int_be'
  | 'uint_be'
  | 'int32_be'
  | 'uint32_be'
  | 'int64_be'
  | 'uint64_be'
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
  PAGE_WRITECOMBINE = 0x400,
  PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
  PAGE_TARGETS_NO_UPDATE = 0x40000000,
  PAGE_TARGETS_INVALID = 0x40000000,
  PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000
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

// Function types for debugger
export enum FunctionType {
  T_VOID = 0x0,
  T_STRING = 0x1,
  T_CHAR = 0x2,
  T_BOOL = 0x3,
  T_INT = 0x4,
  T_DOUBLE = 0x5,
  T_FLOAT = 0x6
}

// Signature types for pattern scanning
export enum SignatureType {
  NORMAL = 0x0,
  READ = 0x1,
  SUBTRACT = 0x2
}

// Memory page types
export enum PageType {
  MEM_PRIVATE = 0x20000,
  MEM_MAPPED = 0x40000,
  MEM_IMAGE = 0x1000000
}

// Hardware debug registers
export enum DebugRegister {
  DR0 = 0x0,
  DR1 = 0x1,
  DR2 = 0x2,
  DR3 = 0x3
}

// Hardware breakpoint trigger types
export enum BreakpointTriggerType {
  TRIGGER_EXECUTE = 0x0,
  TRIGGER_ACCESS = 0x3,
  TRIGGER_WRITE = 0x1
}