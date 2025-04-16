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

/**
 * Reads memory from a process.
 * @param handle - The handle to the process.
 * @param address - The memory address to read from.
 * @param dataType - The data type to read. // TODO: Define specific types for dataType
 * @returns The read value.
 */
export function readMemory(handle: number, address: number, dataType: string): number {
  const dataTypeBuffer = Buffer.from(dataType + "\0")
  const result = symbols.readMemory(handle, address, dataTypeBuffer)
  return result
}

/**
 * Writes memory to a process.
 * @param handle - The handle to the process.
 * @param address - The memory address to write to.
 * @param dataType - The data type to write. // TODO: Define specific types for dataType
 * @param value - The value to write. // TODO: Define specific types for value based on dataType
 */
export function writeMemory(handle: number, address: number, dataType: string, value: any): void {
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
  } else if (dataType === "char" || dataType === "int8" || dataType === "byte") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeInt8(value as number, 0);
  } else if (dataType === "uchar" || dataType === "uint8" || dataType === "ubyte") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeUInt8(value as number, 0);
  } else if (dataType === "float") {
      valueBuffer = Buffer.alloc(4);
      valueBuffer.writeFloatLE(value as number, 0);
  } else if (dataType === "double") {
      valueBuffer = Buffer.alloc(8);
      valueBuffer.writeDoubleLE(value as number, 0);
  } else if (dataType === "int64") {
      valueBuffer = Buffer.alloc(8);
      valueBuffer.writeBigInt64LE(BigInt(value), 0);
  } else if (dataType === "uint64") {
       valueBuffer = Buffer.alloc(8);
       valueBuffer.writeBigUInt64LE(BigInt(value), 0);
  } else if (dataType === "string" || dataType === "str") {
      // Ensure null termination for C++ side
      valueBuffer = Buffer.from((value as string) + "\0", "utf8");
  } else if (dataType === "bool" || dataType === "boolean") {
      valueBuffer = Buffer.alloc(1);
      valueBuffer.writeUInt8(value ? 1 : 0, 0);
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