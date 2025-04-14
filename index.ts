import fs from 'fs';
const memoryjs = require('./build/Release/memoryjs.node');
import Debugger from './src/debugger';
import { STRUCTRON_TYPE_STRING } from './src/utils';
import {
  HANDLE,
  StructronContext,
  BufferEncoding,
  MemoryJS,
  DWORD64,
  ProcessInfo,
  ModuleEntry,
  DataType,
  Callback,
  MemoryBasicInformation,
  Protection,
  AllocationType,
  FunctionType,
  SignatureType,
  PageType,
  DebugRegister,
  BreakpointTriggerType,
  BOOL,
  DWORD,
  SIZE_T,
  ProcessEntry
} from './src/types';

/* TODO:
 * - remove callbacks from all functions and implement promise support using Napi
 * - validate argument types in JS space instead of C++
 * - refactor read/write memory functions to use buffers instead?
 * - remove `closeProcess` in favour of `closeHandle`
 * - REFACTOR IMPORTS ON ALL SRC FILES AND ORGANIZE, EXPORT ALL FROM INDEX.TS
 */

export function openProcess(processIdentifier: string | number, callback?: Callback<ProcessInfo>): ProcessInfo {
  if (arguments.length === 1) {
    return memoryjs.openProcess(processIdentifier);
  }

  return memoryjs.openProcess(processIdentifier, callback);
}

export function closeProcess(handle: HANDLE): boolean {
  return memoryjs.closeProcess(handle);
}

export function getProcesses(callback?: Callback<ProcessInfo[]>): ProcessInfo[] {
  if (arguments.length === 0) {
    return memoryjs.getProcesses();
  }

  return memoryjs.getProcesses(callback);
}

export function findModule(moduleName: string, processId: number, callback?: Callback<ModuleEntry>): ModuleEntry {
  if (arguments.length === 2) {
    return memoryjs.findModule(moduleName, processId);
  }

  return memoryjs.findModule(moduleName, processId, callback);
}

export function getModules(processId: number, callback?: Callback<ModuleEntry[]>): ModuleEntry[] {
  if (arguments.length === 1) {
    return memoryjs.getModules(processId);
  }

  return memoryjs.getModules(processId, callback);
}

export function readMemory<T>(handle: HANDLE, address: DWORD64, dataType: DataType, callback?: Callback<T>): T {
  if (dataType.toLowerCase().endsWith('_be')) {
    return readMemoryBE(handle, address, dataType, callback);
  }

  if (arguments.length === 3) {
    return memoryjs.readMemory(handle, address, dataType.toLowerCase());
  }

  return memoryjs.readMemory(handle, address, dataType.toLowerCase(), callback);
}

export function readMemoryBE(handle: HANDLE, address: DWORD64, dataType: DataType, callback?: Callback<any>): any {
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

  if (typeof callback !== 'function') {
    if (value === null) {
      throw new Error('Invalid data type argument!');
    }

    return value;
  }

  callback(value === null ? new Error('Invalid data type argument!') : null, value);
}

export function readBuffer(handle: HANDLE, address: DWORD64, size: number, callback?: Callback<Buffer>): Buffer {
  if (arguments.length === 3) {
    return memoryjs.readBuffer(handle, address, size);
  }

  return memoryjs.readBuffer(handle, address, size, callback);
}

export function writeMemory<T>(handle: HANDLE, address: DWORD64, value: T, dataType: DataType): boolean {
  let dataValue: T | string = value;
  if ((dataType === 'str' || dataType === 'string') && typeof value === 'string') {
    dataValue = value + '\0'; // add terminator
  }

  const bigintTypes = ['int64', 'int64_be', 'uint64', 'uint64_be'];
  if (bigintTypes.indexOf(dataType) != -1 && typeof value !== 'bigint') {
    throw new Error(`${dataType.toUpperCase()} expects type BigInt`);
  }

  if (dataType.endsWith('_be')) {
    return writeMemoryBE(handle, address, dataValue, dataType);
  }

  return memoryjs.writeMemory(handle, address, dataValue, dataType.toLowerCase());
}

export function writeMemoryBE(handle: HANDLE, address: DWORD64, value: any, dataType: DataType): boolean {
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
      buffer.writeInt32BE(value);
      break;

    case 'uint32_be':
    case 'uint_be':
    case 'ulong_be':
      buffer = Buffer.alloc(4);
      buffer.writeUInt32BE(value);
      break;

    case 'int16_be':
    case 'short_be':
      buffer = Buffer.alloc(2);
      buffer.writeInt16BE(value);
      break;

    case 'uint16_be':
    case 'ushort_be':
      buffer = Buffer.alloc(2);
      buffer.writeUInt16BE(value);
      break;

    case 'float_be':
      buffer = Buffer.alloc(4);
      buffer.writeFloatBE(value);
      break;

    case 'double_be':
      buffer = Buffer.alloc(8);
      buffer.writeDoubleBE(value);
      break;
  }

  if (buffer == null) {
    throw new Error('Invalid data type argument!');
  }

  return writeBuffer(handle, address, buffer);
}

export function writeBuffer(handle: HANDLE, address: DWORD64, buffer: Buffer): boolean {
  return memoryjs.writeBuffer(handle, address, buffer);
}

export function findPattern() {
  const findPattern           = ['number', 'string', 'number', 'number'].toString();
  const findPatternByModule   = ['number', 'string', 'string', 'number', 'number'].toString();
  const findPatternByAddress  = ['number', 'number', 'string', 'number', 'number'].toString();

  const args = Array.from(arguments).map(arg => typeof arg);

  if (args.slice(0, 4).toString() === findPattern) {
    if (args.length === 4 || (args.length === 5 && args[4] === 'function')) {
      return memoryjs.findPattern(...arguments);
    }
  }

  if (args.slice(0, 5).toString() === findPatternByModule) {
    if (args.length === 5 || (args.length === 6 && args[5] === 'function')) {
      return memoryjs.findPatternByModule(...arguments);
    }
  }

  if (args.slice(0, 5).toString() === findPatternByAddress) {
    if (args.length === 5 || (args.length === 6 && args[5] === 'function')) {
      return memoryjs.findPatternByAddress(...arguments);
    }
  }

  throw new Error('invalid arguments!');
}

export function callFunction<T>(handle: HANDLE, args: any[], returnType: DataType, address: DWORD64, callback?: Callback<T>): T {
  if (arguments.length === 4) {
    return memoryjs.callFunction(handle, args, returnType, address);
  }

  return memoryjs.callFunction(handle, args, returnType, address, callback);
}

export function virtualAllocEx(handle: HANDLE, address: DWORD64, size: number, allocationType: AllocationType, protection: Protection, callback?: Callback<DWORD64>): DWORD64 {
  if (arguments.length === 5) {
    return memoryjs.virtualAllocEx(handle, address, size, allocationType, protection);
  }

  return memoryjs.virtualAllocEx(handle, address, size, allocationType, protection, callback);
}

export function virtualProtectEx(handle: HANDLE, address: DWORD64, size: number, protection: Protection, callback?: Callback<Protection>): Protection {
  if (arguments.length === 4) {
    return memoryjs.virtualProtectEx(handle, address, size, protection);
  }

  return memoryjs.virtualProtectEx(handle, address, size, protection, callback);
}

export function getRegions(handle: HANDLE, getOffsets: boolean, callback?: Callback<MemoryBasicInformation[]>): MemoryBasicInformation[] {
  if (arguments.length === 1) {
    return memoryjs.getRegions(handle);
  }

  return memoryjs.getRegions(handle, callback);
}

export function virtualQueryEx(handle: HANDLE, address: DWORD64, callback?: Callback<MemoryBasicInformation>): MemoryBasicInformation {
  if (arguments.length === 2) {
    return memoryjs.virtualQueryEx(handle, address);
  }

  return memoryjs.virtualQueryEx(handle, address, callback);
}

export function injectDll(handle: HANDLE, dllPath: string, callback?: Callback<DWORD64>): DWORD64 {
  if (!dllPath.endsWith('.dll')) {
    throw new Error("Given path is invalid: file is not of type 'dll'.");
  }

  if (!fs.existsSync(dllPath)) {
    throw new Error('Given path is invaild: file does not exist.');
  }

  if (arguments.length === 2) {
    return memoryjs.injectDll(handle, dllPath);
  }

  return memoryjs.injectDll(handle, dllPath, callback);
}

export function unloadDll(handle: HANDLE, module: ModuleEntry, callback?: Callback<boolean>): boolean {
  if (arguments.length === 2) {
    return memoryjs.unloadDll(handle, module);
  }

  return memoryjs.unloadDll(handle, module, callback);
}

export function openFileMapping(fileName: string): HANDLE {
  if (arguments.length !== 1 || typeof fileName !== 'string') {
    throw new Error('invalid arguments!');
  }

  return memoryjs.openFileMapping(fileName);
}

export function mapViewOfFile(processHandle: HANDLE, fileHandle: HANDLE, offset: DWORD64, viewSize: number, pageProtection: Protection): DWORD64 {
  const validArgs = [
    ['number', 'number'],
    ['number', 'number', 'number', 'number', 'number'],
    ['number', 'number', 'bigint', 'bigint', 'number']
  ];
  const receivedArgs = Array.from(arguments).map(arg => typeof arg);

  if (!validArgs.some(args => args.join(",") == receivedArgs.join(","))) {
    throw new Error('invalid arguments!');
  }

  if (arguments.length == 2) {
    return memoryjs.mapViewOfFile(processHandle, fileHandle, 0, 0, Protection.PAGE_READONLY);
  }

  return memoryjs.mapViewOfFile(processHandle, fileHandle, offset, viewSize, pageProtection);
}

const library = {
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
  openFileMapping,
  mapViewOfFile,
  attachDebugger: memoryjs.attachDebugger,
  detachDebugger: memoryjs.detachDebugger,
  awaitDebugEvent: memoryjs.awaitDebugEvent,
  handleDebugEvent: memoryjs.handleDebugEvent,
  setHardwareBreakpoint: memoryjs.setHardwareBreakpoint,
  removeHardwareBreakpoint: memoryjs.removeHardwareBreakpoint,
  Debugger: new Debugger(memoryjs),
};

export {
  HANDLE,
  DWORD64,
  Callback,
  Protection,
  AllocationType,
  ProcessInfo,
  ModuleEntry,
  DataType,
  Debugger,
  MemoryBasicInformation,
  BOOL,
  DWORD,
  SIZE_T,
  ProcessEntry };

export { BufferEncoding, StructronContext };

export {
  FunctionType,
  SignatureType,
  PageType,
  DebugRegister,
  BreakpointTriggerType
}

export default {
  ...library,
  STRUCTRON_TYPE_STRING
};
