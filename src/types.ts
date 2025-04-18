/** Function types */
export const FunctionTypes = {
  T_VOID: 0x0,
  T_STRING: 0x1,
  T_CHAR: 0x2,
  T_BOOL: 0x3,
  T_INT: 0x4,
  T_DOUBLE: 0x5,
  T_FLOAT: 0x6,
} as const;

/** Signature scanning flags */
export const SignatureTypes = {
  NORMAL: 0x0,
  READ: 0x1,
  SUBTRACT: 0x2,
} as const;

// Memory access flags
export const MemoryAccessFlags = {
  PAGE_NOACCESS: 0x01,
  PAGE_READONLY: 0x02,
  PAGE_READWRITE: 0x04,
  PAGE_WRITECOPY: 0x08,
  PAGE_EXECUTE: 0x10,
  PAGE_EXECUTE_READ: 0x20,
  PAGE_EXECUTE_READWRITE: 0x40,
  PAGE_EXECUTE_WRITECOPY: 0x80,
  PAGE_GUARD: 0x100,
  PAGE_NOCACHE: 0x200,
  PAGE_WRITECOMBINE: 0x400,
  PAGE_ENCLAVE_UNVALIDATED: 0x20000000,
  PAGE_TARGETS_NO_UPDATE: 0x40000000,
  PAGE_TARGETS_INVALID: 0x40000000,
  PAGE_ENCLAVE_THREAD_CONTROL: 0x80000000,
} as const;

// Memory allocation flags
export const MemoryAllocationFlags = {
  MEM_COMMIT: 0x00001000,
  MEM_RESERVE: 0x00002000,
  MEM_RESET: 0x00080000,
  MEM_TOP_DOWN: 0x00100000,
  MEM_RESET_UNDO: 0x1000000,
  MEM_LARGE_PAGES: 0x20000000,
  MEM_PHYSICAL: 0x00400000,
} as const;

// Memory page flags
export const MemoryPageFlags = {
  MEM_PRIVATE: 0x20000,
  MEM_MAPPED: 0x40000,
  MEM_IMAGE: 0x1000000,
} as const;

// Hardware debug registers
export const HardwareDebugRegisters = {
  DR0: 0x0,
  DR1: 0x1,
  DR2: 0x2,
  DR3: 0x3,
} as const;

// Breakpoint trigger types
export const BreakpointTriggerTypes = {
  TRIGGER_EXECUTE: 0x0,
  TRIGGER_ACCESS: 0x3,
  TRIGGER_WRITE: 0x1,
} as const;


export type Protection = typeof MemoryAccessFlags[keyof typeof MemoryAccessFlags];
export type PageProtection = typeof MemoryPageFlags[keyof typeof MemoryPageFlags];
export type AllocationType = typeof MemoryAllocationFlags[keyof typeof MemoryAllocationFlags];
export type BreakpointTriggerType = typeof BreakpointTriggerTypes[keyof typeof BreakpointTriggerTypes];

/**
 * Represents a process with its associated information and handle
 */
export interface Process {
  /**
   * Size of the structure, in bytes
   */
  dwSize: number;
  /**
   * Process identifier (PID)
   */
  th32ProcessID: number;
  /**
   * Number of execution threads started by the process
   */
  cntThreads: number;
  /**
   * PID of the parent process
   */
  th32ParentProcessID: number;
  /**
   * Base priority of threads created by this process
   */
  pcPriClassBase: number;
  /**
   * Path to the executable file
   */
  szExeFile: string;
  /**
   * Process handle (for read/write operations)
   */
  handle: number;
  /**
   * Base address of the process's primary module
   */
  modBaseAddr: number;
}

/**
 * Represents a module with its associated information
 */
export interface Module {
  /**
   * Base address of the module in the process's virtual address space
   */
  modBaseAddr: number;
  /**
   * Size of the module, in bytes
   */
  modBaseSize: number;
  /**
   * Full path to the module file
   */
  szExePath: string;
  /**
   * Module name (filename)
   */
  szModule: string;
  /**
   * Process identifier (PID) of the process owning this module
   */
  th32ProcessID: number;
  /**
   * Global usage count of the module
   */
  GlblcntUsage: number;
}

/**
 * Supported data types from constants.standard
 */
export type DataType =
  'byte'    | 'ubyte'    | 'char'    | 'uchar'    |
  'int8'    | 'uint8'    |
  'int16'   | 'int16_be' | 'uint16'  | 'uint16_be' |
  'short'   | 'short_be' | 'ushort'  | 'ushort_be' |
  'long'    | 'long_be'  | 'ulong'   | 'ulong_be'  |
  'int'     | 'int_be'   | 'uint'    | 'uint_be'   |
  'int32'   | 'int32_be' | 'uint32'  | 'uint32_be' |
  'int64'   | 'int64_be' | 'uint64'  | 'uint64_be' |
  'word'    | 'dword'    |
  'float'   | 'float_be' |
  'double'  | 'double_be'|
  'bool'    | 'boolean'  |
  'ptr'     | 'pointer'  | 'uptr'    | 'upointer' |
  'str'     | 'string'   |
  'vec3'    | 'vector3'  |
  'vec4'    | 'vector4';

/**
   * Maps a DataType to its corresponding JS return type
   */
export type MemoryData<T extends DataType> =
/** 64-bit integers (LE/BE) as BigInt */
T extends 'int64' | 'uint64' | 'int64_be' | 'uint64_be' ? bigint :
T extends 'string' | 'str' ? string :
T extends 'vector3' | 'vec3' ? { x: number; y: number; z: number } :
T extends 'vector4' | 'vec4' ? { x: number; y: number; z: number; w: number } :
number;