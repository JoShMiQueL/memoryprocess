export interface ProcessInfo {
  dwSize: number;
  th32ProcessID: number;
  cntThreads: number;
  th32ParentProcessID: number;
  pcPriClassBase: number;
  szExeFile: string;
  modBaseAddr: number;
  handle: number;
}

export interface ModuleInfo {
  modBaseAddr: number,
  modBaseSize: number,
  szExePath: string,
  szModule: string,
  th32ProcessID: number,
  GlblcntUsage: number
}

export type Callback<T> = (error: string | null, result: T) => void;

export type OpenProcessCallback = Callback<ProcessInfo>;
export type OpenProcessFunction = {
  (processName: string): ProcessInfo;
  (processId: number): ProcessInfo;
  (processName: string, callback: OpenProcessCallback): void;
  (processId: number, callback: OpenProcessCallback): void;
  (processName: string, callback?: OpenProcessCallback): ProcessInfo | void;
  (processId: number, callback?: OpenProcessCallback): ProcessInfo | void;
};

export type CloseProcessFunction = {
  (handle: number): void;
};

export type GetProcessesCallback = Callback<ProcessInfo[]>;
export type GetProcessesFunction = {
  (): ProcessInfo[];
  (callback: GetProcessesCallback): void;
  (callback?: GetProcessesCallback): ProcessInfo[] | void;
};

export type FindModuleCallback = Callback<ModuleInfo>;
export type FindModuleFunction = {
  (moduleName: string, processId: number): ModuleInfo;
  (moduleName: string, processId: number, callback: FindModuleCallback): void;
  (moduleName: string, processId: number, callback?: FindModuleCallback): ModuleInfo | void;
}

export type GetModulesCallback = Callback<ModuleInfo[]>;
export type GetModulesFunction = {
  (processId: number): ModuleInfo[];
  (processId: number, callback: GetModulesCallback): void;
  (processId: number, callback?: GetModulesCallback): ModuleInfo[] | void;
}

export type DataType = 
  | "int8" | "byte" | "char"
  | "uint8" | "ubyte" | "uchar"
  | "int16" | "short"
  | "uint16" | "ushort" | "word"
  | "int32" | "int" | "long"
  | "uint32" | "uint" | "ulong" | "dword"
  | "int64"
  | "uint64"
  | "float"
  | "double"
  | "ptr" | "pointer"
  | "uptr" | "upointer"
  | "bool" | "boolean"
  | "string" | "str"
  | "vector3" | "vec3"
  | "vector4" | "vec4"
  // Big-endian types
  | "int16_be" | "short_be"
  | "uint16_be" | "ushort_be"
  | "int32_be" | "int_be" | "long_be"
  | "uint32_be" | "uint_be" | "ulong_be"
  | "int64_be"
  | "uint64_be"
  | "float_be"
  | "double_be";

export interface Vector3 {
  x: number;
  y: number;
  z: number;
}

export interface Vector4 {
  w: number;
  x: number;
  y: number;
  z: number;
}

export type DataTypeToType<T extends DataType> = 
  T extends "int8" | "byte" | "char" ? number :
  T extends "uint8" | "ubyte" | "uchar" ? number :
  T extends "int16" | "short" ? number :
  T extends "uint16" | "ushort" | "word" ? number :
  T extends "int32" | "int" | "long" ? number :
  T extends "uint32" | "uint" | "ulong" | "dword" ? number :
  T extends "int64" ? bigint :
  T extends "uint64" ? bigint :
  T extends "float" ? number :
  T extends "double" ? number :
  T extends "ptr" | "pointer" ? number | bigint :
  T extends "uptr" | "upointer" ? number | bigint :
  T extends "bool" | "boolean" ? boolean :
  T extends "string" | "str" ? string :
  T extends "vector3" | "vec3" ? Vector3 :
  T extends "vector4" | "vec4" ? Vector4 :
  T extends "int16_be" | "short_be" ? number :
  T extends "uint16_be" | "ushort_be" ? number :
  T extends "int32_be" | "int_be" | "long_be" ? number :
  T extends "uint32_be" | "uint_be" | "ulong_be" ? number :
  T extends "int64_be" ? bigint :
  T extends "uint64_be" ? bigint :
  T extends "float_be" ? number :
  T extends "double_be" ? number :
  never;

export type ReadMemoryCallback<T> = (error: string, value: T) => void;
export type ReadMemoryFunction = {
  <T extends DataType>(handle: number, address: number | bigint, dataType: T): DataTypeToType<T>;
  <T extends DataType>(handle: number, address: number | bigint, dataType: T, callback: ReadMemoryCallback<DataTypeToType<T>>): void;
  <T extends DataType>(handle: number, address: number | bigint, dataType: T, callback?: ReadMemoryCallback<DataTypeToType<T>>): DataTypeToType<T> | void;
}

export type DataTypeBE = 
  | "int16_be" | "short_be"
  | "uint16_be" | "ushort_be"
  | "int32_be" | "int_be" | "long_be"
  | "uint32_be" | "uint_be" | "ulong_be"
  | "int64_be"
  | "uint64_be"
  | "float_be"
  | "double_be";

export type DataTypeToTypeBE<T extends DataTypeBE> = 
  T extends "int16_be" | "short_be" ? number :
  T extends "uint16_be" | "ushort_be" ? number :
  T extends "int32_be" | "int_be" | "long_be" ? number :
  T extends "uint32_be" | "uint_be" | "ulong_be" ? number :
  T extends "int64_be" ? bigint :
  T extends "uint64_be" ? bigint :
  T extends "float_be" ? number :
  T extends "double_be" ? number :
  never;

export type ReadMemoryBECallback<T> = (error: string, value: T) => void;
export type ReadMemoryBEFunction = {
  <T extends DataTypeBE>(handle: number, address: number | bigint, dataType: T): DataTypeToTypeBE<T>;
  <T extends DataTypeBE>(handle: number, address: number | bigint, dataType: T, callback: ReadMemoryBECallback<DataTypeToTypeBE<T>>): void;
  <T extends DataTypeBE>(handle: number, address: number | bigint, dataType: T, callback?: ReadMemoryBECallback<DataTypeToTypeBE<T>>): DataTypeToTypeBE<T> | void;
}

export type ReadBufferCallback = (error: string, buffer: Buffer) => void;
export type ReadBufferFunction = {
  (handle: number, address: number | bigint, size: number): Buffer;
  (handle: number, address: number | bigint, size: number, callback: ReadBufferCallback): void;
  (handle: number, address: number | bigint, size: number, callback?: ReadBufferCallback): Buffer | void;
}

export type DataTypeToWriteType<T extends DataType> = 
  T extends "int8" | "byte" | "char" ? number :
  T extends "uint8" | "ubyte" | "uchar" ? number :
  T extends "int16" | "short" ? number :
  T extends "uint16" | "ushort" | "word" ? number :
  T extends "int32" | "int" | "long" ? number :
  T extends "uint32" | "uint" | "ulong" | "dword" ? number :
  T extends "int64" ? bigint :
  T extends "uint64" ? bigint :
  T extends "float" ? number :
  T extends "double" ? number :
  T extends "ptr" | "pointer" ? number | bigint :
  T extends "uptr" | "upointer" ? number | bigint :
  T extends "bool" | "boolean" ? boolean :
  T extends "string" | "str" ? string :
  T extends "vector3" | "vec3" ? { x: number; y: number; z: number } :
  T extends "vector4" | "vec4" ? { w: number; x: number; y: number; z: number } :
  never;

export type WriteMemoryFunction = {
  <T extends DataType>(handle: number, address: number | bigint, value: DataTypeToWriteType<T>, dataType: T): void;
}

export type WriteBufferFunction = {
  (handle: number, address: number | bigint, buffer: Buffer): void;
}

export type FindPatternCallback = (error: string, address: number | bigint) => void;
export type FindPatternFunction = {
  (handle: number, pattern: string, flags: number, patternOffset: number): number;
  (handle: number, pattern: string, flags: number, patternOffset: number, callback: FindPatternCallback): void;
  (handle: number, pattern: string, flags: number, patternOffset: number, callback?: FindPatternCallback): number | void;
}

export enum FunctionType {
  T_STRING = 0,
  T_CHAR = 1,
  T_BOOL = 2,
  T_INT = 3,
  T_FLOAT = 4,
  T_DOUBLE = 5
}
export type FunctionArg = {
  type: FunctionType;
  value: string | number | boolean;
}
export type FunctionReturnValue = {
  returnValue: string | number | boolean;
  exitCode: number;
}
export type CallFunctionCallback = (error: string, result: FunctionReturnValue) => void;
export type CallFunctionFunction = {
  (handle: number, args: FunctionArg[], returnType: FunctionType, address: number | bigint): FunctionReturnValue;
  (handle: number, args: FunctionArg[], returnType: FunctionType, address: number | bigint, callback: CallFunctionCallback): void;
}

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

export type VirtualAllocExCallback = (error: string, address: number | bigint) => void;
export type VirtualAllocExFunction = {
  (handle: number, address: number | bigint | null, size: number, allocationType: AllocationType, protection: Protection): number;
  (handle: number, address: number | bigint | null, size: number, allocationType: AllocationType, protection: Protection, callback: VirtualAllocExCallback): void;
}

export type VirtualProtectExCallback = (error: string, oldProtection: Protection) => void;
export type VirtualProtectExFunction = {
  (handle: number, address: number | bigint, size: number, protection: Protection): number;
  (handle: number, address: number | bigint, size: number, protection: Protection, callback: VirtualProtectExCallback): void;
}

export interface MemoryRegion {
  Baseaddress: number | bigint;
  AllocationBase: number;
  AllocationProtect: Protection;
  RegionSize: number;
  State: number;
  Protect: Protection;
  Type: number;
  szExeFile?: string;
}
export type GetRegionsCallback = (error: string, regions: MemoryRegion[]) => void;
export type GetRegionsFunction = {
  (handle: number): MemoryRegion[];
  (handle: number, callback: GetRegionsCallback): void;
}

export type VirtualQueryExCallback = (error: string, region: MemoryRegion) => void;
export type VirtualQueryExFunction = {
  (handle: number, address: number | bigint): MemoryRegion;
  (handle: number, address: number | bigint, callback: VirtualQueryExCallback): void;
}

export type InjectDllCallback = (error: string, success: boolean) => void;
export type InjectDllFunction = {
  (handle: number, dllPath: string): boolean;
  (handle: number, dllPath: string, callback: InjectDllCallback): void;
}

export type UnloadDllCallback = (error: string, success: boolean) => void;
export type UnloadDllFunction = {
  (handle: number, moduleaddress: number | bigint): boolean;
  (handle: number, moduleName: string): boolean;
  (handle: number, moduleaddress: number | bigint, callback: UnloadDllCallback): void;
  (handle: number, moduleName: string, callback: UnloadDllCallback): void;
  (handle: number, moduleaddress: number | bigint, callback?: UnloadDllCallback): boolean | void;
  (handle: number, moduleName: string, callback?: UnloadDllCallback): boolean | void;
}

export interface MemoryJS {
  openProcess: OpenProcessFunction;
  closeProcess: CloseProcessFunction;
  getProcesses: GetProcessesFunction;
  findModule: FindModuleFunction;
  getModules: GetModulesFunction;
  readMemory: ReadMemoryFunction;
  readBuffer: ReadBufferFunction;
  writeMemory: WriteMemoryFunction;
  writeBuffer: WriteBufferFunction;
  findPattern: FindPatternFunction;
  callFunction: CallFunctionFunction;
  virtualAllocEx: VirtualAllocExFunction;
  virtualProtectEx: VirtualProtectExFunction;
  virtualQueryEx: VirtualQueryExFunction;
  getRegions: GetRegionsFunction;
  injectDll: InjectDllFunction;
  unloadDll: UnloadDllFunction;
  attachDebugger: (processId: number, killOnDetach: boolean) => boolean;
  detachDebugger: (processId: number) => boolean;
  awaitDebugEvent: (register: number, timeout: number) => {
    processId: number;
    threadId: number;
    exceptionCode: number;
    exceptionFlags: number;
    exceptionaddress: number | bigint;
    hardwareRegister: number;
  } | null;
  handleDebugEvent: (processId: number, threadId: number) => boolean;
  setHardwareBreakpoint: (processId: number, address: number | bigint, register: number, trigger: number, size: number) => boolean;
  removeHardwareBreakpoint: (processId: number, hardwareRegister: number) => boolean;
};