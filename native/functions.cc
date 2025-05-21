#include <windows.h>
#include <TlHelp32.h>
#include "functions.h"

char functions::readChar(HANDLE hProcess, DWORD64 address) {
  if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
    // Error: Invalid process handle. Cannot indicate error directly with char return type.
    // Consider logging or changing function signature (e.g., return bool, pass char by reference).
    return '\0'; // Return null char as an indicator, though ambiguous.
  }
  if (address == 0) {
    // Error: Null address.
    return '\0';
  }

  char value = '\0'; // Initialize to a default
  SIZE_T bytesRead = 0;
  if (!ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(char), &bytesRead) || bytesRead != sizeof(char)) {
    // Error: ReadProcessMemory failed or did not read expected number of bytes.
    // Consider logging GetLastError().
    return '\0'; // Return null char as an indicator.
  }
  return value;
}

LPVOID functions::reserveString(HANDLE hProcess, const char* value, SIZE_T size) {
  if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
    // Error: Invalid process handle.
    return nullptr;
  }
  if (value == nullptr) {
    // Error: Null string value provided.
    return nullptr;
  }
  if (size == 0) {
    // Error: Size cannot be zero for allocation.
    return nullptr;
  }

  LPVOID memoryAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (memoryAddress == NULL) {
    // Error: VirtualAllocEx failed. Consider logging GetLastError().
    return nullptr;
  }

  SIZE_T bytesWritten = 0;
  if (!WriteProcessMemory(hProcess, memoryAddress, value, size, &bytesWritten) || bytesWritten != size) {
    // Error: WriteProcessMemory failed or did not write expected number of bytes.
    // Consider logging GetLastError().
    // Free the allocated memory if write fails to prevent leaks.
    VirtualFreeEx(hProcess, memoryAddress, 0, MEM_RELEASE);
    return nullptr;
  }
  return memoryAddress;
 }
