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
 * - add support for more data types
 */

/**
 * Opens a process by name or id.
 * 
 * @param processIdentifier - The name or id of the process to open.
 * @param callback - Optional callback function to handle the result asynchronously.
 * @returns The handle of the opened process or undefined if the process was not found.
 */
function openProcess(processIdentifier: string | number, callback?: ((handle: number, errorMessage: string) => void) | undefined): Process {
  if (processIdentifier === null || processIdentifier === undefined) {
    throw new Error('Invalid process identifier: cannot be null or undefined.');
  }
  if (typeof processIdentifier === 'string' && processIdentifier.trim() === '') {
    throw new Error('Invalid process identifier: cannot be an empty string.');
  }
  if (typeof processIdentifier === 'number' && processIdentifier < 0) {
    // Assuming process IDs are non-negative. Some systems might use -1 for special cases, adjust if needed.
    throw new Error('Invalid process identifier: process ID cannot be negative.');
  }

  if (!callback) {
    return memoryprocess.openProcess(processIdentifier);
  }

  return memoryprocess.openProcess(processIdentifier, callback);
}

/**
 * Scans a specific region of memory in a process for a given pattern.
 * The pattern can include wildcards (e.g., "??").
 *
 * @param handle - The handle of the process.
 * @param baseAddress - The starting address of the memory region to scan. Can be a number or BigInt.
 * @param scanSize - The size of the memory region to scan. Can be a number or BigInt.
 * @param pattern - The pattern string to search for (e.g., "AB ?? CD EF").
 * @param flags - Optional flags for the scan (e.g., ST_READ, ST_SUBTRACT from native layer). Defaults to 0.
 * @param patternOffset - Optional offset to add to the found pattern's address. Defaults to 0.
 * @returns The memory address where the pattern was found, or 0 (or BigInt(0)) if not found.
 * @throws Will throw an error if input validation fails or if the native call fails.
 */
function findPatternInRegion(
  handle: number,
  baseAddress: number | bigint,
  scanSize: number | bigint,
  pattern: string,
  flags: number = 0,
  patternOffset: number = 0
): number | bigint {
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if ((typeof baseAddress !== 'number' && typeof baseAddress !== 'bigint') || baseAddress < 0) {
    throw new Error('Invalid baseAddress: must be a non-negative number or BigInt.');
  }
  if (baseAddress == 0) { // Using == to catch 0 and 0n
    throw new Error('Invalid baseAddress: cannot be zero.');
  }
  if ((typeof scanSize !== 'number' && typeof scanSize !== 'bigint') || scanSize <= 0) { // Using <= to catch 0 and 0n for scanSize
    throw new Error('Invalid scanSize: must be a positive number or BigInt.');
  }
  if (typeof pattern !== 'string' || pattern.trim() === '') {
    throw new Error('Invalid pattern: must be a non-empty string.');
  }
  if (typeof flags !== 'number' || flags < 0) {
    throw new Error('Invalid flags: must be a non-negative number.');
  }
  if (typeof patternOffset !== 'number') { // Offset can be 0 or positive or negative
    throw new Error('Invalid patternOffset: must be a number.');
  }

  // The N-API function is expected to handle BigInts correctly for address/size/return value
  return memoryprocess.findPatternInRegion(handle, baseAddress, scanSize, pattern, flags, patternOffset);
}


/**
 * Closes a handle to a process.
 * 
 * @param handle - The handle of the process to close.
 * @returns Whether the operation was successful.
 */
function closeHandle(handle: number) {
  if (typeof handle !== 'number' || handle < 0) {
    // Assuming handles are non-negative. Adjust if 0 or other values have special meaning.
    throw new Error('Invalid handle: must be a non-negative number.');
  }
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
  if (moduleName === null || moduleName === undefined || typeof moduleName !== 'string' || moduleName.trim() === '') {
    throw new Error('Invalid module name: cannot be null, undefined, or an empty string.');
  }
  if (typeof processId !== 'number' || processId < 0) {
    throw new Error('Invalid processId: must be a non-negative number.');
  }

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
  if (typeof processId !== 'number' || processId < 0) {
    throw new Error('Invalid processId: must be a non-negative number.');
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof dataType !== 'string' || !dataType) {
    throw new Error('Invalid dataType: must be a non-empty string.');
  }
  // TODO: Add check against a list of valid DataTypes if available

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof dataType !== 'string' || !dataType.endsWith('_be')) {
    throw new Error('Invalid dataType: must be a non-empty string ending with "_be".');
  }
  // TODO: Add check against a list of valid DataTypes if available

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof size !== 'number' || size <= 0) {
    // Size should be positive. Zero-size reads might be valid in some contexts but typically not.
    throw new Error('Invalid size: must be a positive number.');
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof dataType !== 'string' || !dataType) {
    throw new Error('Invalid dataType: must be a non-empty string.');
  }
  // TODO: Add check against a list of valid DataTypes if available

  let dataValue: MemoryData<DataType> = value;
  if (dataType === 'str' || dataType === 'string') {
    if (typeof value !== 'string') {
      throw new Error(`Invalid value for dataType '${dataType}': expected a string.`);
    }
    // ensure TS knows this branch yields a string for T = 'str'|'string'
    dataValue = ((value as string) + '\0') as MemoryData<DataType>;
  }

  const bigintTypes: DataType[] = ['int64', 'uint64', 'int64_be', 'uint64_be'];
  if (bigintTypes.includes(dataType)) {
    if (typeof value !== 'bigint') {
      throw new Error(`Invalid value for dataType '${dataType}': expected a BigInt.`);
    }
  } else if (dataType !== 'str' && dataType !== 'string') { // For other numeric types
    if (typeof value !== 'number') {
      // This check might be too broad if some other specific types expect e.g. boolean
      // For now, assuming non-bigint, non-string types are numeric.
      // throw new Error(`Invalid value for dataType '${dataType}': expected a number.`);
    }
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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof dataType !== 'string' || !dataType.endsWith('_be')) {
    throw new Error('Invalid dataType: must be a non-empty string ending with "_be".');
  }
  // TODO: Add check against a list of valid DataTypes if available

  let buffer: Buffer | null = null;

  switch (dataType) {
    case 'int64_be':
      if (typeof value !== 'bigint') {
        // This specific check is redundant due to the check in writeMemory, but good for standalone use.
        throw new Error('INT64_BE expects type BigInt');
      }
      buffer = Buffer.alloc(8);
      buffer.writeBigInt64BE(value);
      break;

    case 'uint64_be':
      if (typeof value !== 'bigint') {
        // This specific check is redundant due to the check in writeMemory, but good for standalone use.
        throw new Error('UINT64_BE expects type BigInt');
      }
      buffer = Buffer.alloc(8);
      buffer.writeBigUInt64BE(value);
      break;

    case 'int32_be':
    case 'int_be':
    case 'long_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(4);
      buffer.writeInt32BE(value as number);
      break;

    case 'uint32_be':
    case 'uint_be':
    case 'ulong_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(4);
      buffer.writeUInt32BE(value as number);
      break;

    case 'int16_be':
    case 'short_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(2);
      buffer.writeInt16BE(value as number);
      break;

    case 'uint16_be':
    case 'ushort_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(2);
      buffer.writeUInt16BE(value as number);
      break;

    case 'float_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(4);
      buffer.writeFloatBE(value as number);
      break;

    case 'double_be':
      if (typeof value !== 'number') throw new Error(`${dataType} expects type number`);
      buffer = Buffer.alloc(8);
      buffer.writeDoubleBE(value as number);
      break;
    default:
      // This case should ideally not be reached if dataType is validated against a known list.
      throw new Error(`Unsupported data type for writeMemoryBE: ${dataType}`);
  }

  // buffer null check already exists
  if (buffer == null) {
    // This implies an invalid dataType was passed that didn't match any case,
    // or a new BE type was added to DataType without updating writeMemoryBE.
    throw new Error('Internal error: Buffer not allocated for writeMemoryBE, possibly invalid data type.');
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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (!(buffer instanceof Buffer)) {
    throw new Error('Invalid buffer: argument must be a Buffer instance.');
  }
  return memoryprocess.writeBuffer(handle, address, buffer);
}

// TODO: Implement pattern scanning functionality with various overloads to match the C++ implementation
function findPattern(...args: any[]): any {
  const pattern           = ['number', 'string', 'number', 'number'].toString(); // handle, pattern, protection, patternOffset
  const patternByModule   = ['number', 'string', 'string', 'number', 'number'].toString(); // handle, moduleName, pattern, protection, patternOffset
  const patternByAddress  = ['number', 'number', 'string', 'number', 'number'].toString(); // handle, address, pattern, protection, patternOffset

  const types = args.map(arg => typeof arg);

  // Validate common handle argument
  if (typeof args[0] !== 'number' || args[0] < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }

  if (types.slice(0, 4).toString() === pattern) {
    if (types.length === 4 || (types.length === 5 && types[4] === 'function')) {
      // args[0] is handle - already checked
      // args[1] is pattern string
      if (typeof args[1] !== 'string' || !args[1]) throw new Error('Pattern string cannot be empty.');
      // args[2] is protection (number) - could add range check if known
      if (typeof args[2] !== 'number') throw new Error('Protection must be a number.');
      // args[3] is patternOffset (number) - could add range check if known (e.g. non-negative)
      if (typeof args[3] !== 'number') throw new Error('Pattern offset must be a number.');
      // @ts-ignore
      return memoryprocess.findPattern(...args);
    }
  }

  if (types.slice(0, 5).toString() === patternByModule) {
    if (types.length === 5 || (types.length === 6 && types[5] === 'function')) {
      // args[0] is handle - already checked
      // args[1] is moduleName string
      if (typeof args[1] !== 'string' || !args[1]) throw new Error('Module name cannot be empty.');
      // args[2] is pattern string
      if (typeof args[2] !== 'string' || !args[2]) throw new Error('Pattern string cannot be empty.');
      // args[3] is protection (number)
      if (typeof args[3] !== 'number') throw new Error('Protection must be a number.');
      // args[4] is patternOffset (number)
      if (typeof args[4] !== 'number') throw new Error('Pattern offset must be a number.');
      // @ts-ignore
      return memoryprocess.findPatternByModule(...args);
    }
  }

  if (types.slice(0, 5).toString() === patternByAddress) {
    if (types.length === 5 || (types.length === 6 && types[5] === 'function')) {
      // args[0] is handle - already checked
      // args[1] is address (number)
      if (typeof args[1] !== 'number' || args[1] < 0) throw new Error('Invalid address: must be a non-negative number.');
      // args[2] is pattern string
      if (typeof args[2] !== 'string' || !args[2]) throw new Error('Pattern string cannot be empty.');
      // args[3] is protection (number)
      if (typeof args[3] !== 'number') throw new Error('Protection must be a number.');
      // args[4] is patternOffset (number)
      if (typeof args[4] !== 'number') throw new Error('Pattern offset must be a number.');
      // @ts-ignore
      return memoryprocess.findPatternByAddress(...args);
    }
  }

  throw new Error('Invalid arguments for findPattern: No matching signature found or argument count mismatch.');
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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (!Array.isArray(args)) {
    throw new Error('Invalid args: must be an array.');
  }
  if (typeof returnType !== 'number') {
    // Assuming returnType is an enum represented by numbers.
    throw new Error('Invalid returnType: must be a number.');
  }
  if (typeof address !== 'number' || address <= 0) {
    // Function addresses are typically positive, non-zero.
    throw new Error('Invalid address: must be a positive number.');
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (address !== null && (typeof address !== 'number' || address < 0)) {
    throw new Error('Invalid address: must be null or a non-negative number.');
  }
  if (typeof size !== 'number' || size <= 0) {
    throw new Error('Invalid size: must be a positive number.');
  }
  if (!MemoryAllocationFlags.hasOwnProperty(allocationType)) {
    throw new Error(`Invalid allocationType: '${allocationType}'. Must be a key of MemoryAllocationFlags.`);
  }
  if (!MemoryAccessFlags.hasOwnProperty(protection)) {
    throw new Error(`Invalid protection: '${protection}'. Must be a key of MemoryAccessFlags.`);
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }
  if (typeof size !== 'number' || size <= 0) {
    throw new Error('Invalid size: must be a positive number.');
  }
  if (!MemoryAccessFlags.hasOwnProperty(protection)) {
    throw new Error(`Invalid protection: '${protection}'. Must be a key of MemoryAccessFlags.`);
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof fileHandle !== 'number' || fileHandle < 0) {
    // Assuming file handles are also non-negative, adjust if OS specific values are different
    throw new Error('Invalid fileHandle: must be a non-negative number.');
  }
  if (typeof offset !== 'number' || offset < 0) {
    throw new Error('Invalid offset: must be a non-negative number.');
  }
  if (typeof viewSize !== 'number' || viewSize < 0) {
    // A viewSize of 0 might be valid to map the entire file, so using '< 0'
    throw new Error('Invalid viewSize: must be a non-negative number.');
  }
  if (!MemoryPageFlags.hasOwnProperty(pageProtection)) {
    throw new Error(`Invalid pageProtection: '${pageProtection}'. Must be a key of MemoryPageFlags.`);
  }

  const pageCode = MemoryPageFlags[pageProtection];
  if (arguments.length === 2) { // This condition seems problematic given 5 declared args.
                               // Assuming it's meant to provide defaults if offset, viewSize are not passed.
                               // However, TS won't allow calling with 2 args if 5 are declared without defaults.
                               // For validation, we assume all declared args are passed.
                               // If this function is truly callable with 2 args, its signature needs adjustment.
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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (typeof address !== 'number' || address < 0) {
    throw new Error('Invalid address: must be a non-negative number.');
  }

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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (!dllPath || typeof dllPath.toString !== 'function') {
    throw new Error('Invalid dllPath: must be a PathLike object (e.g., string).');
  }

  const dllPathStr = dllPath.toString();
  if (!dllPathStr.endsWith('.dll')) {
    throw new Error("Invalid dllPath: file is not of type '.dll'. Path: " + dllPathStr);
  }

  // Corrected logic: throw error if file DOES NOT exist
  if (!existsSync(dllPath)) {
    throw new Error('Invalid dllPath: file does not exist. Path: ' + dllPathStr);
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
  if (typeof handle !== 'number' || handle < 0) {
    throw new Error('Invalid handle: must be a non-negative number.');
  }
  if (module === null || module === undefined) {
    throw new Error('Invalid module: cannot be null or undefined.');
  }
  if (typeof module === 'string' && module.trim() === '') {
    throw new Error('Invalid module: module name cannot be an empty string.');
  }
  if (typeof module === 'number' && module < 0) {
    // Assuming module base addresses or IDs are non-negative
    throw new Error('Invalid module: module identifier cannot be negative if a number.');
  }


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
  if (typeof fileName !== 'string' || fileName.trim() === '') {
    throw new Error('Invalid fileName: must be a non-empty string.');
  }
  // arguments.length check is implicitly handled by TypeScript signature if no optional args

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
  findPatternInRegion, // Added new function
  attachDebugger: memoryprocess.attachDebugger,
  detachDebugger: memoryprocess.detachDebugger,
  awaitDebugEvent: memoryprocess.awaitDebugEvent,
  handleDebugEvent: memoryprocess.handleDebugEvent,
  setHardwareBreakpoint: memoryprocess.setHardwareBreakpoint,
  removeHardwareBreakpoint: memoryprocess.removeHardwareBreakpoint,
  Debugger: new Debugger(memoryprocess),
};

/**
 * Retrieves a list of threads running in the specified process.
 *
 * @param processId - The identifier of the process.
 * @returns An array of ThreadEntry objects, each describing a thread.
 * @throws Will throw an error if the processId is invalid or if the native call fails.
 */
function getThreads(processId: number): ThreadEntry[] {
  if (typeof processId !== 'number' || processId <= 0) {
    // Process IDs are typically positive integers. 0 might refer to System Idle Process
    // but module::getThreads already handles 0 as an error.
    throw new Error('Invalid processId: must be a positive number.');
  }
  // The N-API function getThreadsApi is expected to be synchronous if no callback is passed.
  // If it were designed to always expect a callback, this TS wrapper would need to change
  // to return a Promise or accept a callback itself.
  return memoryprocess.getThreads(processId);
}

export default {
  ...library,
  getThreads, // Add getThreads to the default export
  STRUCTRON_TYPE_STRING: STRUCTRON_TYPE_STRING(library),
};
