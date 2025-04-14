import fs from 'fs';
import Debugger from './src/debugger';
import { isDataTypeBE, STRUCTRON_TYPE_STRING } from './src/utils';

// Type imports
import type {
  AllocationType,
  CallFunctionCallback,
  DataType,
  DataTypeBE,
  DataTypeToType,
  DataTypeToTypeBE,
  DataTypeToWriteType,
  FindModuleCallback,
  FindPatternCallback,
  FunctionArg,
  FunctionReturnValue,
  FunctionType,
  GetModulesCallback,
  GetProcessesCallback,
  GetRegionsCallback,
  InjectDllCallback,
  MemoryJS,
  MemoryRegion,
  ModuleInfo,
  OpenProcessCallback,
  ProcessInfo,
  Protection,
  ReadBufferCallback,
  ReadMemoryBECallback,
  ReadMemoryCallback,
  UnloadDllCallback,
  VirtualAllocExCallback,
  VirtualProtectExCallback,
  VirtualQueryExCallback
} from './src/types';

const memoryjs = require('./build/Release/memoryjs.node') as MemoryJS;

/* TODO:
 * - remove callbacks from all functions and implement promise support using Napi
 * - validate argument types in JS space instead of C++
 * - refactor read/write memory functions to use buffers instead?
 * - remove `closeProcess` in favour of `closeHandle`
 * - REFACTOR IMPORTS ON ALL SRC FILES AND ORGANIZE, EXPORT ALL FROM INDEX.TS
 */

export function openProcess(processName: string): ProcessInfo;
export function openProcess(processId: number): ProcessInfo;
export function openProcess(processName: string, callback: OpenProcessCallback): void;
export function openProcess(processId: number, callback: OpenProcessCallback): void;
export function openProcess(processIdentifier: string | number, callback?: OpenProcessCallback): ProcessInfo | void {
  // Handle synchronous calls
  if (!callback) {
    if (typeof processIdentifier === 'string') {
      return memoryjs.openProcess(processIdentifier as string);
    } else {
      return memoryjs.openProcess(processIdentifier as number);
    }
  }

  // Handle asynchronous calls
  if (typeof processIdentifier === 'string') {
    return memoryjs.openProcess(processIdentifier as string, callback);
  } else {
    return memoryjs.openProcess(processIdentifier as number, callback);
  }
}

export function closeProcess(handle: number): void {
  return memoryjs.closeProcess(handle);
}

export function getProcesses(): ProcessInfo[]
export function getProcesses(callback: GetProcessesCallback): void
export function getProcesses(callback?: GetProcessesCallback): ProcessInfo[] | void {
  if (!callback) {
    return memoryjs.getProcesses();
  }

  return memoryjs.getProcesses(callback);
}

export function findModule(moduleName: string, processId: number): ModuleInfo;
export function findModule(moduleName: string, processId: number, callback: FindModuleCallback): void;
export function findModule(moduleName: string, processId: number, callback?: FindModuleCallback): ModuleInfo | void {
  if (moduleName && processId) {
    return memoryjs.findModule(moduleName, processId);
  }

  return memoryjs.findModule(moduleName, processId, callback);
}

export function getModules(processId: number): ModuleInfo[];
export function getModules(processId: number, callback: GetModulesCallback): void;
export function getModules(processId: number, callback?: GetModulesCallback): ModuleInfo[] | void {
  if (!callback) {
    return memoryjs.getModules(processId);
  }
  
  return memoryjs.getModules(processId, callback);
}

export function readMemory<T extends DataType>(handle: number, address: bigint, dataType: T): DataTypeToType<T>;
export function readMemory<T extends DataType>(handle: number, address: bigint, dataType: T, callback: ReadMemoryCallback<DataTypeToType<T>>): void;
export function readMemory<T extends DataType>(handle: number, address: bigint, dataType: T, callback?: ReadMemoryCallback<DataTypeToType<T>>): DataTypeToType<T> | void {
  if (isDataTypeBE(dataType)) {
    return readMemoryBE(handle, address, dataType, callback as any) as any;
  }

  if (!callback) {
    return memoryjs.readMemory(handle, address, dataType);
  }

  return memoryjs.readMemory(handle, address, dataType, callback);
}

export function readMemoryBE<T extends DataTypeBE>(handle: number, address: bigint, dataType: T): DataTypeToTypeBE<T>;
export function readMemoryBE<T extends DataTypeBE>(handle: number, address: bigint, dataType: T, callback: ReadMemoryBECallback<DataTypeToTypeBE<T>>): void;
export function readMemoryBE<T extends DataTypeBE>(handle: number, address: bigint, dataType: T, callback?: ReadMemoryBECallback<DataTypeToTypeBE<T>>): DataTypeToTypeBE<T> | void {
  let value = null;

  switch (dataType) {
    case 'int64_be':
      value = readBuffer(handle, address, 8).readBigInt64BE();
      break;

    case 'uint64_be':
      value = readBuffer(handle, address, 8).readBigUInt64BE();
      break;

    case 'int32_be':
    case 'int_be':
    case 'long_be':
      value = readBuffer(handle, address, 4).readInt32BE();
      break;

    case 'uint32_be':
    case 'uint_be':
    case 'ulong_be':
      value = readBuffer(handle, address, 4).readUInt32BE();
      break;

    case 'int16_be':
    case 'short_be':
      value = readBuffer(handle, address, 2).readInt16BE();
      break;

    case 'uint16_be':
    case 'ushort_be':
      value = readBuffer(handle, address, 2).readUInt16BE();
      break;

    case 'float_be':
      value = readBuffer(handle, address, 4).readFloatBE();
      break;

    case 'double_be':
      value = readBuffer(handle, address, 8).readDoubleBE();
      break;
  }

  if (!callback) {
    if (value === null) {
      throw new Error('Invalid data type argument!');
    }
    return value as DataTypeToTypeBE<T>;
  }

  callback(value === null ? 'Invalid data type argument!' : '', value as DataTypeToTypeBE<T>);
}

export function readBuffer(handle: number, address: bigint, size: number): Buffer;
export function readBuffer(handle: number, address: bigint, size: number, callback: ReadBufferCallback): void;
export function readBuffer(handle: number, address: bigint, size: number, callback?: ReadBufferCallback): Buffer | void {
  if (!callback) {
    return memoryjs.readBuffer(handle, address, size);
  }
  return memoryjs.readBuffer(handle, address, size, callback);
}

export function writeMemory<T extends DataType>(handle: number, address: bigint, value: DataTypeToWriteType<T>, dataType: T): void {
  let dataValue: any = value;
  if ((dataType === 'str' || dataType === 'string') && typeof value === 'string') {
    dataValue = value + '\0'; // add terminator
  }

  const bigintTypes = ['int64', 'int64_be', 'uint64', 'uint64_be'];
  if (bigintTypes.indexOf(dataType) != -1 && typeof value !== 'bigint') {
    throw new Error(`${dataType.toUpperCase()} expects type BigInt`);
  }

  if (isDataTypeBE(dataType)) {
    return writeMemoryBE(handle, address, dataValue, dataType);
  }

  return memoryjs.writeMemory(handle, address, dataValue, dataType);
}

export function writeMemoryBE<T extends DataTypeBE>(
  handle: number, 
  address: bigint, 
  value: DataTypeToWriteType<T>, 
  dataType: T
): void {
  let buffer: Buffer | null = null;

  switch (dataType) {
    case 'int64_be':
      if (typeof value !== 'bigint') {
        throw new Error('INT64_BE expects type BigInt');
      }
      buffer = Buffer.alloc(8);
      buffer.writeBigInt64BE(value);
      break;

    case 'uint64_be':
      if (typeof value !== 'bigint') {
        throw new Error('UINT64_BE expects type BigInt');
      }
      buffer = Buffer.alloc(8);
      buffer.writeBigUInt64BE(value);
      break;

    case 'int32_be':
    case 'int_be':
    case 'long_be':
      buffer = Buffer.alloc(4);
      buffer.writeInt32BE(value as number);
      break;

    case 'uint32_be':
    case 'uint_be':
    case 'ulong_be':
      buffer = Buffer.alloc(4);
      buffer.writeUInt32BE(value as number);
      break;

    case 'int16_be':
    case 'short_be':
      buffer = Buffer.alloc(2);
      buffer.writeInt16BE(value as number);
      break;

    case 'uint16_be':
    case 'ushort_be':
      buffer = Buffer.alloc(2);
      buffer.writeUInt16BE(value as number);
      break;

    case 'float_be':
      buffer = Buffer.alloc(4);
      buffer.writeFloatBE(value as number);
      break;

    case 'double_be':
      buffer = Buffer.alloc(8);
      buffer.writeDoubleBE(value as number);
      break;
  }

  if (buffer == null) {
    throw new Error('Invalid data type argument!');
  }

  return writeBuffer(handle, address, buffer);
}

export function writeBuffer(handle: number, address: bigint, buffer: Buffer): void {
  return memoryjs.writeBuffer(handle, address, buffer);
}

export function findPattern(handle: number, pattern: string, flags: number, patternOffset: number): bigint;
export function findPattern(handle: number, pattern: string, flags: number, patternOffset: number, callback: FindPatternCallback): void;
export function findPattern(handle: number, pattern: string, flags: number, patternOffset: number, callback?: FindPatternCallback): bigint | void {
  if (!callback) {
    return memoryjs.findPattern(handle, pattern, flags, patternOffset);
  }

  return memoryjs.findPattern(handle, pattern, flags, patternOffset, callback);
}

export function callFunction(handle: number, args: FunctionArg[], returnType: FunctionType, address: bigint): FunctionReturnValue;
export function callFunction(handle: number, args: FunctionArg[], returnType: FunctionType, address: bigint, callback: CallFunctionCallback): void;
export function callFunction(handle: number, args: FunctionArg[], returnType: FunctionType, address: bigint, callback?: CallFunctionCallback): FunctionReturnValue | void {
  if (!callback) {
    return memoryjs.callFunction(handle, args, returnType, address);
  }

  return memoryjs.callFunction(handle, args, returnType, address, callback);
}

export function virtualAllocEx(handle: number, address: bigint | null, size: number, allocationType: AllocationType, protection: Protection): bigint;
export function virtualAllocEx(handle: number, address: bigint | null, size: number, allocationType: AllocationType, protection: Protection, callback: VirtualAllocExCallback): void;
export function virtualAllocEx(handle: number, address: bigint | null, size: number, allocationType: AllocationType, protection: Protection, callback?: VirtualAllocExCallback): bigint | void {
  if (!callback) {
    return memoryjs.virtualAllocEx(handle, address, size, allocationType, protection);
  }

  return memoryjs.virtualAllocEx(handle, address, size, allocationType, protection, callback);
}

export function virtualProtectEx(handle: number, address: bigint, size: number, protection: Protection): number;
export function virtualProtectEx(handle: number, address: bigint, size: number, protection: Protection, callback: VirtualProtectExCallback): void;
export function virtualProtectEx(handle: number, address: bigint, size: number, protection: Protection, callback?: VirtualProtectExCallback): number | void {
  if (!callback) {
    return memoryjs.virtualProtectEx(handle, address, size, protection);
  }

  return memoryjs.virtualProtectEx(handle, address, size, protection, callback);
}

export function getRegions(handle: number): MemoryRegion[];
export function getRegions(handle: number, callback: GetRegionsCallback): void;
export function getRegions(handle: number, callback?: GetRegionsCallback): MemoryRegion[] | void {
  if (!callback) {
    return memoryjs.getRegions(handle);
  }

  return memoryjs.getRegions(handle, callback);
}

export function virtualQueryEx(handle: number, address: bigint): MemoryRegion;
export function virtualQueryEx(handle: number, address: bigint, callback: VirtualQueryExCallback): void;
export function virtualQueryEx(handle: number, address: bigint, callback?: VirtualQueryExCallback): MemoryRegion | void {
  if (!callback) {
    return memoryjs.virtualQueryEx(handle, address);
  }

  return memoryjs.virtualQueryEx(handle, address, callback);
}

export function injectDll(handle: number, dllPath: string): boolean;
export function injectDll(handle: number, dllPath: string, callback: InjectDllCallback): void;
export function injectDll(handle: number, dllPath: string, callback?: InjectDllCallback): boolean | void {
  if (!dllPath.endsWith('.dll')) {
    throw new Error("Given path is invalid: file is not of type 'dll'.");
  }

  if (!fs.existsSync(dllPath)) {
    throw new Error('Given path is invalid: file does not exist.');
  }

  if (!callback) {
    return memoryjs.injectDll(handle, dllPath);
  }

  return memoryjs.injectDll(handle, dllPath, callback);
}

export function unloadDll(handle: number, moduleAddress: number): boolean;
export function unloadDll(handle: number, moduleName: string): boolean;
export function unloadDll(handle: number, moduleAddress: number, callback: UnloadDllCallback): void;
export function unloadDll(handle: number, moduleName: string, callback: UnloadDllCallback): void;
export function unloadDll(handle: number, moduleAddressOrName: number | string, callback?: UnloadDllCallback): boolean | void {
  // Handle synchronous calls
  if (!callback) {
    if (typeof moduleAddressOrName === 'number') {
      return memoryjs.unloadDll(handle, moduleAddressOrName as number);
    } else {
      return memoryjs.unloadDll(handle, moduleAddressOrName as string);
    }
  }

  // Handle asynchronous calls
  if (typeof moduleAddressOrName === 'number') {
    return memoryjs.unloadDll(handle, moduleAddressOrName as number, callback);
  } else {
    return memoryjs.unloadDll(handle, moduleAddressOrName as string, callback);
  }
}

// Re-export types
export type {
  AllocationType,
  CallFunctionCallback,
  DataType,
  DataTypeBE,
  DataTypeToType,
  DataTypeToTypeBE,
  DataTypeToWriteType,
  FindModuleCallback,
  FindPatternCallback,
  FunctionArg,
  FunctionReturnValue,
  FunctionType,
  GetModulesCallback,
  GetProcessesCallback,
  GetRegionsCallback,
  InjectDllCallback,
  MemoryJS,
  MemoryRegion,
  ModuleInfo,
  OpenProcessCallback,
  ProcessInfo,
  Protection,
  ReadBufferCallback,
  ReadMemoryBECallback,
  ReadMemoryCallback,
  UnloadDllCallback,
  VirtualAllocExCallback,
  VirtualProtectExCallback,
  VirtualQueryExCallback
} from './src/types';

// Re-export utility types
export type {
  BufferEncoding,
  StructronContext,
  StructronType,
  Platform
} from './src/utils';

// Export functions and values
export {
  Debugger,
  isDataTypeBE
};

export default {
  openProcess,
  closeProcess,
  getProcesses,
  findModule,
  getModules,
  readMemory,
  readBuffer,
  writeMemory,
  writeBuffer,
  findPattern,
  callFunction,
  virtualAllocEx,
  virtualProtectEx,
  getRegions,
  virtualQueryEx,
  injectDll,
  unloadDll,
  attachDebugger: memoryjs.attachDebugger,
  detachDebugger: memoryjs.detachDebugger,
  awaitDebugEvent: memoryjs.awaitDebugEvent,
  handleDebugEvent: memoryjs.handleDebugEvent,
  setHardwareBreakpoint: memoryjs.setHardwareBreakpoint,
  removeHardwareBreakpoint: memoryjs.removeHardwareBreakpoint,
  
  STRUCTRON_TYPE_STRING
};
