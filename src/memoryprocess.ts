// @ts-ignore
const memoryprocess = require('./native.node');
import { existsSync, type PathLike } from 'fs';
import { MemoryAllocationFlags, type Protection, MemoryAccessFlags, MemoryPageFlags, type Process, type Module, type DataType, type MemoryData } from "./types"
import Debugger from './debugger';
import { STRUCTRON_TYPE_STRING } from './utils';

/* TODO:
 * - remove callbacks from all functions and implement promise support using Napi
 * - validate argument types in JS space instead of C++
 * - refactor read/write memory functions to use buffers instead?
 */

/**
 * Opens a process by name or id.
 * 
 * @param processIdentifier - The name or id of the process to open.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The handle of the opened process or undefined if the process was not found.
 */
function openProcess(processIdentifier: string | number, callback?: ((handle: number, errorMessage: string) => void) | undefined): Process {
  if (!callback) {
    return memoryprocess.openProcess(processIdentifier);
  }

  return memoryprocess.openProcess(processIdentifier, callback);
}

/**
 * Closes a handle to a process.
 * 
 * @param handle - The handle of the process to close.
 * @returns Whether the operation was successful.
 */
function closeHandle(handle: number) {
  return memoryprocess.closeHandle(handle);
}

/**
 * Retrieves a list of all processes currently running on the system.
 * 
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns An array of process objects or undefined if the operation failed.
 */
function getProcesses(callback?: ((processes: Process[], errorMessage: string) => void) | undefined) {
  if (!callback) {
    return memoryprocess.getProcesses();
  }

  return memoryprocess.getProcesses(callback);
}

/**
 * Finds a module by name within a process.
 * 
 * @param moduleName - The name of the module to find.
 * @param processId - The ID of the process to search within.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The module object or undefined if the module was not found.
 */
function findModule(moduleName: string, processId: number, callback?: ((module: Module, errorMessage: string) => void) | undefined) {
  if (!callback) {
    return memoryprocess.findModule(moduleName, processId);
  }

  return memoryprocess.findModule(moduleName, processId, callback);
}

/**
 * Retrieves a list of all modules loaded by a process.
 * 
 * @param processId - The ID of the process to search within.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns An array of module objects or undefined if the operation failed.
 */
function getModules(processId: number, callback?: ((modules: Module[], errorMessage: string) => void) | undefined) {
  if (!callback) {
    return memoryprocess.getModules(processId);
  }

  return memoryprocess.getModules(processId, callback);
}

/**
 * Reads a value from a process's memory.
 * 
 * @param handle - The handle of the process to read from.
 * @param address - The address to read from.
 * @param dataType - The data type to read.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The read value or undefined if the operation failed.
 */
function readMemory<T extends DataType>(handle: number, address: number, dataType: T, callback?: (value: MemoryData<T>, errorMessage: string) => void): MemoryData<T> | undefined {
  if (dataType.endsWith('_be')) {
    return readMemoryBE(handle, address, dataType, callback);
  }

  if (!callback) {
    return memoryprocess.readMemory(handle, address, dataType);
  }

  return memoryprocess.readMemory(handle, address, dataType, callback);
}

/**
 * Reads a value from a process's memory in big-endian format.
 * 
 * @param handle - The handle of the process to read from.
 * @param address - The address to read from.
 * @param dataType - The data type to read.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The read value or undefined if the operation failed.
 */
function readMemoryBE<T extends DataType>(handle: number, address: number, dataType: T, callback?: (value: MemoryData<T>, errorMessage: string) => void): MemoryData<T> | undefined {
  let value: number | bigint | null = null;

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

    return value as MemoryData<T>;
  }

  callback(value as MemoryData<T>, value === null ? 'Invalid data type argument!' : '');
}

/**
 * Reads a buffer of specified size from a process's memory.
 * 
 * @param handle - The handle of the process to read from.
 * @param address - The memory address to read from.
 * @param size - The number of bytes to read.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns A buffer containing the read data or undefined if the operation failed.
 */
function readBuffer(handle: number, address: number, size: number, callback?: (buffer: Buffer, errorMessage: string) => void): Buffer {
  if (arguments.length === 3) {
    return memoryprocess.readBuffer(handle, address, size);
  }

  return memoryprocess.readBuffer(handle, address, size, callback);
}

/**
 * Writes a value to a process's memory.
 * 
 * @param handle - The handle of the process to write to.
 * @param address - The address to write to.
 * @param value - The value to write.
 * @param dataType - The data type to write.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns Whether the operation was successful.
 */
function writeMemory(handle: number, address: number, value: string, dataType: 'str'|'string'): boolean;
function writeMemory<T extends Exclude<DataType,'str'|'string'>>(handle: number, address: number, value: MemoryData<T>, dataType: T): boolean;
function writeMemory(handle: number, address: number, value: any, dataType: DataType): boolean {
  let dataValue: MemoryData<DataType> = value;
  if (dataType === 'str' || dataType === 'string') {
    // ensure TS knows this branch yields a string for T = 'str'|'string'
    dataValue = ((value as string) + '\0') as MemoryData<DataType>;
  }

  const bigintTypes: DataType[] = ['int64', 'uint64', 'int64_be', 'uint64_be'];
  if (bigintTypes.includes(dataType) && typeof value !== 'bigint') {
    throw new Error(`${dataType.toUpperCase()} expects type BigInt`);
  }

  if (dataType.endsWith('_be')) {
    // dataValue narrowed to numeric types in BE branch
    writeMemoryBE(handle, address, dataValue as number | bigint, dataType);
    return true;
  }

  return memoryprocess.writeMemory(handle, address, dataValue, dataType);
}

/**
 * Writes a value to a process's memory in big-endian format.
 * 
 * @param handle - The handle of the process to write to.
 * @param address - The address to write to.
 * @param value - The value to write.
 * @param dataType - The data type to write.
 * @returns Whether the operation was successful.
 */
function writeMemoryBE(handle: number, address: number, value: number | bigint, dataType: DataType): boolean {
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

  writeBuffer(handle, address, buffer as Buffer);
  return true;
}

/**
 * Writes a buffer of specified size to a process's memory.
 * 
 * @param handle - The handle of the process to write to.
 * @param address - The memory address to write to.
 * @param buffer - The buffer containing the data to write.
 * @returns Whether the operation was successful.
 */
function writeBuffer(handle: number, address: number, buffer: Buffer<ArrayBufferLike>) {
  return memoryprocess.writeBuffer(handle, address, buffer);
}

// TODO: Implement pattern scanning functionality with various overloads to match the C++ implementation
function findPattern(...args: any[]): any {
  const pattern           = ['number', 'string', 'number', 'number'].toString();
  const patternByModule   = ['number', 'string', 'string', 'number', 'number'].toString();
  const patternByAddress  = ['number', 'number', 'string', 'number', 'number'].toString();

  const types = args.map(arg => typeof arg);

  if (types.slice(0, 4).toString() === pattern) {
    if (types.length === 4 || (types.length === 5 && types[4] === 'function')) {
      // @ts-ignore
      return memoryprocess.findPattern(...args);
    }
  }

  if (types.slice(0, 5).toString() === patternByModule) {
    if (types.length === 5 || (types.length === 6 && types[5] === 'function')) {
      // @ts-ignore
      return memoryprocess.findPatternByModule(...args);
    }
  }

  if (types.slice(0, 5).toString() === patternByAddress) {
    if (types.length === 5 || (types.length === 6 && types[5] === 'function')) {
      // @ts-ignore
      return memoryprocess.findPatternByAddress(...args);
    }
  }

  throw new Error('invalid arguments!');
}

/**
 * Calls a function in a process's memory.
 * 
 * @param handle - The handle of the process to call the function in.
 * @param args - The arguments to pass to the function.
 * @param returnType - The return type of the function.
 * @param address - The address of the function to call.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The return value of the function or undefined if the operation failed.
 */
function callFunction(handle: number, args: any[], returnType: number, address: number, callback: ((errorMessage: string, info: { returnValue: any; exitCode: number; }) => void) | undefined) {
  if (arguments.length === 4) {
    return memoryprocess.callFunction(handle, args, returnType, address);
  }

  return memoryprocess.callFunction(handle, args, returnType, address, callback);
}

/**
 * Allocates memory in a process's virtual address space.
 * 
 * @param handle - The handle of the process to allocate memory in.
 * @param address - The address to allocate memory at. If null, the memory will be allocated at the next available address.
 * @param size - The size of the memory block to allocate.
 * @param allocationType - The type of memory allocation to use.
 * @param protection - The memory protection to apply.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The base address of the allocated memory or undefined if the operation failed.
 */
function virtualAllocEx(
  handle: number,
  address: number | null,
  size: number,
  allocationType: keyof typeof MemoryAllocationFlags,
  protection: keyof typeof MemoryAccessFlags,
  callback?: (errorMessage: string, baseAddress: number) => void
) {
  const allocCode = MemoryAllocationFlags[allocationType];
  const protCode  = MemoryAccessFlags[protection];
  if (arguments.length === 5) {
    return memoryprocess.virtualAllocEx(handle, address, size, allocCode, protCode);
  }
  return memoryprocess.virtualAllocEx(handle, address, size, allocCode, protCode, callback!);
}

/**
 * Changes the protection of a region of memory in a process's virtual address space.
 * 
 * @param handle - The handle of the process to change the memory protection in.
 * @param address - The starting address of the memory region.
 * @param size - The size of the memory region.
 * @param protection - The new memory protection to apply.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The old memory protection or undefined if the operation failed.
 */
function virtualProtectEx(
  handle: number,
  address: number,
  size: number,
  protection: keyof typeof MemoryAccessFlags,
  callback?: (errorMessage: string, oldProtection: Protection) => void
) {
  const protCode = MemoryAccessFlags[protection];
  
  if (arguments.length === 4) {
    return memoryprocess.virtualProtectEx(handle, address, size, protCode);
  }
  return memoryprocess.virtualProtectEx(handle, address, size, protCode, callback!);
}

/**
 * Maps a view of a file into the virtual address space of a process.
 * 
 * @param handle - The handle of the process to map the file into.
 * @param fileHandle - The handle of the file to map.
 * @param offset - The offset within the file to map.
 * @param viewSize - The size of the view to map.
 * @param pageProtection - The memory protection to apply.
 * @returns The base address of the mapped view or undefined if the operation failed.
 */
function mapViewOfFile(
  handle: number,
  fileHandle: number,
  offset: number,
  viewSize: number,
  pageProtection: keyof typeof MemoryPageFlags
) {
  const pageCode = MemoryPageFlags[pageProtection];
  if (arguments.length === 2) {
    return memoryprocess.mapViewOfFile(handle, fileHandle, 0, 0, pageCode);
  }
  return memoryprocess.mapViewOfFile(handle, fileHandle, offset, viewSize, pageCode);
}

/**
 * Retrieves a list of memory regions in a process's virtual address space.
 * 
 * @param handle - The handle of the process to retrieve memory regions from.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns An array of memory regions or undefined if the operation failed.
 */
function getRegions(handle: number, callback: ((regions: any[], errorMessage: string) => void) | undefined) {
  if (arguments.length === 1) {
    return memoryprocess.getRegions(handle);
  }

  return memoryprocess.getRegions(handle, callback);
}

/**
 * Retrieves information about a specific memory region in a process's virtual address space.

 * @param handle - The handle of the process to retrieve memory region information from.
 * @param address - The starting address of the memory region.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The memory region information or undefined if the operation failed.
 */
function virtualQueryEx(handle: number, address: number, callback: ((region: any, errorMessage: string) => void) | undefined) {
  if (arguments.length === 2) {
    return memoryprocess.virtualQueryEx(handle, address);
  }

  return memoryprocess.virtualQueryEx(handle, address, callback);
}

/**
 * Injects a DLL into a process.

 * @param handle - The handle of the process to inject the DLL into.
 * @param dllPath - The path to the DLL to inject.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns Whether the operation was successful.
 */
function injectDll(handle: number, dllPath: PathLike, callback: ((errorMessage: string, success: boolean) => void) | undefined) {
  if (!dllPath.toString().endsWith('.dll')) {
    throw new Error("Given path is invalid: file is not of type 'dll'.");
  }

  if (existsSync(dllPath)) {
    throw new Error('Given path is invaild: file does not exist.');
  }

  if (arguments.length === 2) {
    return memoryprocess.injectDll(handle, dllPath.toString());
  }

  return memoryprocess.injectDll(handle, dllPath.toString(), callback);
}

/**
 * Unloads a DLL from a process.
 * 
 * @param handle - The handle of the process to unload the DLL from.
  * @param module - The module to unload.
  * @param callback - Optional callback function to handle the result asynchronously.
  * @returns Whether the operation was successful.
  */
function unloadDll(handle: number, module: string | number, callback: ((errorMessage: string, success: boolean) => void) | undefined) {
  if (arguments.length === 2) {
    return memoryprocess.unloadDll(handle, module);
  }

  return memoryprocess.unloadDll(handle, module, callback);
}

/**
 * Opens a file mapping object.
 * 
 * @param fileName - The name of the file to open.
 * @returns The handle of the opened file mapping object or undefined if the operation failed.
 */
function openFileMapping(fileName: string) {
  if (arguments.length !== 1 || typeof fileName !== 'string') {
    throw new Error('invalid arguments!');
  }

  return memoryprocess.openFileMapping(fileName);
}

const library = {
  openProcess,
  closeHandle,
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
  attachDebugger: memoryprocess.attachDebugger,
  detachDebugger: memoryprocess.detachDebugger,
  awaitDebugEvent: memoryprocess.awaitDebugEvent,
  handleDebugEvent: memoryprocess.handleDebugEvent,
  setHardwareBreakpoint: memoryprocess.setHardwareBreakpoint,
  removeHardwareBreakpoint: memoryprocess.removeHardwareBreakpoint,
  Debugger: new Debugger(memoryprocess),
};

export default {
  ...library,
  STRUCTRON_TYPE_STRING: STRUCTRON_TYPE_STRING(library),
};
