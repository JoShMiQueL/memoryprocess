import { dlopen } from "bun:ffi";

// Dynamically resolve the path to the DLL relative to the built file
const libPath = import.meta.resolve("./memoryprocess.dll");

export interface ProcessObject {
  dwSize: number;
  th32ProcessID: number;
  cntThreads: number;
  th32ParentProcessID: number;
  pcPriClassBase: number;
  szExeFile: string;
  handle: number;
  modBaseAddr: number;
}

const { symbols } = dlopen(libPath, {
  openProcess: {
    args: ["cstring"],
    returns: "cstring",
  },
  closeProcess: {
    args: ["int"],
    returns: "void",
  },
})

/**
 * Opens a process by name.
 * @param processName - The name of the process to open.
 * @returns The opened process object.
 */
export function openProcess(processName: string): ProcessObject {
  const processNameBuffer = Buffer.from(processName + "\0")
  const processCString = symbols.openProcess(processNameBuffer)
  const process = JSON.parse(processCString.toString()) as ProcessObject
  return process
}

/**
 * Closes a process handle.
 * @param handle - The handle to the process to close.
 */
export function closeProcess(handle: number): void {
  try {
    if (symbols.closeProcess) {
      symbols.closeProcess(handle);
    } else {
      console.error("closeProcess FFI symbol not found.");
    }
  } catch (e) {
    console.error(`Error closing handle ${handle}:`, e);
  }
}