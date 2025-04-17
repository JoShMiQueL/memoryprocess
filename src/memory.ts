import { dlopen } from "bun:ffi";

// Dynamically resolve the path to the DLL relative to the built file
const libPath = import.meta.resolve("./memoryprocess.dll");

const { symbols } = dlopen(libPath, {
  readMemory: {
    args: ["uint64_t", "uint64_t", "cstring"],
    returns: "int",
  },
  writeMemory: {
    args: ["uint64_t", "uint64_t", "cstring", "ptr"],
    returns: "void",
  },
})

/** Represents the valid data types for memory operations. */
export type MemoryDataType = 
  | "byte" | "int8" | "char" // 8-bit signed
  | "ubyte" | "uint8" | "uchar" // 8-bit unsigned
  | "short" | "int16" // 16-bit signed
  | "ushort" | "uint16" | "word" // 16-bit unsigned
  | "int" | "int32" | "long" // 32-bit signed
  | "uint" | "uint32" | "ulong" | "dword" // 32-bit unsigned
  | "float" // 32-bit float
  | "double" // 64-bit float
  | "longlong" | "int64" // 64-bit signed (Note: JS Number limitations apply)
  | "ulonglong" | "uint64" // 64-bit unsigned (Note: JS Number limitations apply)
  | "bool"
  | "string" | "str"; // Null-terminated string

/** Represents the possible value types corresponding to MemoryDataType. */
export type MemoryValueType = number | string | boolean;

/**
 * Reads memory from a process.
 * @param handle - The handle to the process.
 * @param address - The address to read from.
 * @param dataType - The data type to read.
 * @returns The value read from memory.
 */
export function readMemory(handle: number, address: number, dataType: MemoryDataType): number {
  const dataTypeBuffer = Buffer.from(dataType + "\0")
  const result = symbols.readMemory(handle, address, dataTypeBuffer)
  return result
}

/**
 * Writes memory to a process.
 * @param handle - The handle to the process.
 * @param address - The address to write to.
 * @param dataType - The data type to write.
 * @param value - The value to write. Should be `number` for numeric types, `boolean` for bool, and `string` for string.
 */
export function writeMemory(
  handle: number,
  address: number,
  dataType: MemoryDataType,
  value: MemoryValueType,
): void {
  const dataTypeBuffer = Buffer.from(dataType + "\0")
  
  let valueBuffer: Buffer;

  // Create buffer with correct binary representation based on dataType
  // This needs to handle all types supported by the C++ function
  if (dataType === "int" || dataType === "int32" || dataType === "long") {
      valueBuffer = Buffer.alloc(4);
      valueBuffer.writeInt32LE(value as number, 0);
  } else if (dataType === "uint" || dataType === "uint32" || dataType === "ulong" || dataType === "dword") {
      valueBuffer = Buffer.alloc(4);
      valueBuffer.writeUInt32LE(value as number, 0);
  } else if (dataType === "short" || dataType === "int16") {
      valueBuffer = Buffer.alloc(2);
      valueBuffer.writeInt16LE(value as number, 0);
  } else if (dataType === "ushort" || dataType === "uint16" || dataType === "word") {
      valueBuffer = Buffer.alloc(2);
      valueBuffer.writeUInt16LE(value as number, 0);
  } else if (dataType === "byte" || dataType === "int8" || dataType === "char") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeInt8(value as number, 0);
  } else if (dataType === "ubyte" || dataType === "uint8" || dataType === "uchar") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeUInt8(value as number, 0);
  } else if (dataType === "float") {
      valueBuffer = Buffer.alloc(4);
      valueBuffer.writeFloatLE(value as number, 0);
  } else if (dataType === "double") {
      valueBuffer = Buffer.alloc(8);
      valueBuffer.writeDoubleLE(value as number, 0);
  } else if (dataType === "longlong" || dataType === "int64") {
      valueBuffer = Buffer.alloc(8);
      valueBuffer.writeBigInt64LE(BigInt(value), 0);
  } else if (dataType === "ulonglong" || dataType === "uint64") {
       valueBuffer = Buffer.alloc(8);
       valueBuffer.writeBigUInt64LE(BigInt(value), 0);
  } else if (dataType === "bool") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeUInt8(value ? 1 : 0, 0);
  } else if (dataType === "string" || dataType === "str") {
      // Ensure null termination for C++ side
      valueBuffer = Buffer.from((value as string) + "\0", "utf8");
  } else if (dataType === "ptr" || dataType === "pointer") {
      valueBuffer = Buffer.alloc(8); // Assuming 64-bit pointers
      valueBuffer.writeBigUInt64LE(BigInt(value), 0);
  } else if (dataType === "uptr" || dataType === "upointer") {
      valueBuffer = Buffer.alloc(8); // Assuming 64-bit pointers
      valueBuffer.writeBigUInt64LE(BigInt(value), 0);
  } 
  // TODO: Add Vector3/Vector4 handling if needed
  else {
      throw new Error(`Unsupported data type for writeMemory: ${dataType}`);
  }

  symbols.writeMemory(handle, address, dataTypeBuffer, valueBuffer)
}