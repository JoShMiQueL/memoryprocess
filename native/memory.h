#pragma once
#ifndef MEMORY_H
#define MEMORY_H
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>

class memory {
public:
  memory();
  ~memory();
  std::vector<MEMORY_BASIC_INFORMATION> getRegions(HANDLE hProcess);

  template <class dataType>
  dataType readMemory(HANDLE hProcess, DWORD64 address) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0) {
      // Consider logging error or using a mechanism to report failure.
      return dataType(); // Return default-constructed value on error.
    }
    dataType cRead{}; // Value initialize
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &cRead, sizeof(dataType), &bytesRead) || bytesRead != sizeof(dataType)) {
      // Consider logging GetLastError().
      return dataType(); // Return default-constructed value on error.
    }
    return cRead;
  }

  BOOL readBuffer(HANDLE hProcess, DWORD64 address, SIZE_T size, char* dstBuffer) { // Changed to char*
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0 || dstBuffer == nullptr || size == 0) {
      return FALSE;
    }
    SIZE_T bytesRead = 0;
    // ReadProcessMemory returns 0 on failure.
    return ReadProcessMemory(hProcess, (LPCVOID)address, (LPVOID)dstBuffer, size, &bytesRead) && (bytesRead == size);
  }

  char readChar(HANDLE hProcess, DWORD64 address) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0) {
      return '\0'; // Ambiguous error indicator
    }
    char value = '\0';
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(char), &bytesRead) || bytesRead != sizeof(char)) {
      return '\0'; // Ambiguous error indicator
    }
    return value;
	}

  BOOL readString(HANDLE hProcess, DWORD64 address, std::string* pString) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0 || pString == nullptr) {
      return FALSE;
    }

    pString->clear();
    const int BATCH_SIZE = 256; // Keep const
    // Use std::vector for automatic memory management and safety.
    std::vector<char> batch_buffer(BATCH_SIZE);
    DWORD64 current_address = address;

    for (int i = 0; i < 4096; ++i) { // Limit iterations to prevent infinite loops (e.g. MAX_STRING_READ_ITERATIONS)
      SIZE_T bytesRead = 0;
      // ReadProcessMemory directly into std::vector's data buffer
      if (!ReadProcessMemory(hProcess, (LPCVOID)current_address, batch_buffer.data(), BATCH_SIZE, &bytesRead) || bytesRead == 0) {
        // If ReadProcessMemory fails or reads 0 bytes, it might be end of readable memory or an error.
        // If something was already read into pString, it might be a partial success.
        return !pString->empty(); // Return true if we managed to read something.
      }

      for (size_t j = 0; j < bytesRead; ++j) {
        if (batch_buffer[j] == '\0') {
          pString->append(batch_buffer.data(), j); // Append the part of buffer before null terminator
          return TRUE; // Found null terminator
        }
      }
      pString->append(batch_buffer.data(), bytesRead); // Append full batch if no null terminator found
      current_address += bytesRead;

      // If less than BATCH_SIZE was read, it implies end of readable data or last segment.
      if (bytesRead < BATCH_SIZE) {
        // This could mean the string ended exactly at the boundary without a null terminator
        // or we hit unreadable memory. If no null terminator was found, this string is unterminated.
        // The current logic will return FALSE after the loop if no null terminator is ever found.
        // For very long strings without null terminators, this might be an issue.
        // Let's consider it success if anything was read and we hit end of readable memory.
        return !pString->empty();
      }
    }
    // If loop finishes, it means string is too long or unterminated within reasonable limits.
    return FALSE; // Or true if partial read is acceptable: !pString->empty();
  }


  template <class dataType>
  BOOL writeMemory(HANDLE hProcess, DWORD64 address, dataType value) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0) {
      return FALSE;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(dataType), &bytesWritten) || bytesWritten != sizeof(dataType)) {
      // Consider logging GetLastError().
      return FALSE;
    }
    return TRUE;
  }

  // This overload is for writing raw buffers/structs where size is explicitly given.
  // 'value' here is treated as a pointer if T is a pointer, or address of 'value' if T is not a pointer.
  template <class dataType>
  BOOL writeMemory(HANDLE hProcess, DWORD64 address, dataType value, SIZE_T size) {
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0 || size == 0) {
      return FALSE;
    }

    void* bufferPtr;
    if (std::is_pointer<dataType>::value) {
      bufferPtr = (void*)value;
      if (bufferPtr == nullptr) return FALSE; // Null pointer passed
    } else {
      bufferPtr = &value;
    }

    SIZE_T bytesWritten = 0;
	  if (!WriteProcessMemory(hProcess, (LPVOID)address, bufferPtr, size, &bytesWritten) || bytesWritten != size) {
      // Consider logging GetLastError().
      return FALSE;
    }
    return TRUE;
  }


  // Overload for writing char* (C-style strings or raw byte arrays)
  BOOL writeMemory(HANDLE hProcess, DWORD64 address, const char* value, SIZE_T size) { // Changed to const char*
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE || address == 0 || value == nullptr || size == 0) {
      return FALSE;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, value, size, &bytesWritten) || bytesWritten != size) {
      // Consider logging GetLastError().
      return FALSE;
    }
    return TRUE;
  }
};
#endif
// #pragma once // Duplicate pragma once removed