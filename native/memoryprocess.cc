#include "process.h"
#include "module.h"
#include "memory.h"
#include <cstdint>

process proc;
memory memory;

extern "C" {
  __declspec(dllexport) const char* openProcess(const char* processName) {
    const char* errorMessage = nullptr;
    auto result = proc.openProcess(processName, &errorMessage);
    
    static char buffer[1024];
    snprintf(buffer, sizeof(buffer),
        "{\"dwSize\":%lu,\"th32ProcessID\":%lu,\"cntThreads\":%lu,\"th32ParentProcessID\":%lu,"
        "\"pcPriClassBase\":%ld,\"szExeFile\":\"%s\",\"handle\":%llu,\"modBaseAddr\":%llu}",
        result.process.dwSize,
        result.process.th32ProcessID,
        result.process.cntThreads,
        result.process.th32ParentProcessID,
        result.process.pcPriClassBase,
        result.process.szExeFile,
        (unsigned long long)result.handle,
        (unsigned long long)module::getBaseAddress(result.process.szExeFile, result.process.th32ProcessID)
    );
    
    return buffer;
  }

  // Vector3 and Vector4 structures for memory reading
  struct Vector3 {
    float x, y, z;
  };

  struct Vector4 {
    float w, x, y, z;
  };

  __declspec(dllexport) int readMemory(unsigned long long handle, unsigned long long address, const char* dataType) {
    // For simple numeric types, we'll return the value directly
    // For complex types, we'll need to handle them differently in the JS side
    
    // Cast handle to HANDLE (void*) safely using intptr_t as an intermediate type
    HANDLE hProcess = (HANDLE)(intptr_t)handle;
    DWORD64 memAddress = (DWORD64)address;
    
    if (!strcmp(dataType, "int8") || !strcmp(dataType, "byte") || !strcmp(dataType, "char")) {
      return (int)memory.readMemory<int8_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "uint8") || !strcmp(dataType, "ubyte") || !strcmp(dataType, "uchar")) {
      return (int)memory.readMemory<uint8_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "int16") || !strcmp(dataType, "short")) {
      return (int)memory.readMemory<int16_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "uint16") || !strcmp(dataType, "ushort") || !strcmp(dataType, "word")) {
      return (int)memory.readMemory<uint16_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "int32") || !strcmp(dataType, "int") || !strcmp(dataType, "long")) {
      return memory.readMemory<int32_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "uint32") || !strcmp(dataType, "uint") || !strcmp(dataType, "ulong") || !strcmp(dataType, "dword")) {
      return (int)memory.readMemory<uint32_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "int64") || !strcmp(dataType, "long long")) {
      return memory.readMemory<int64_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "uint64") || !strcmp(dataType, "ulong long")) {
      return (int)memory.readMemory<uint64_t>(hProcess, memAddress);
    
    } else if (!strcmp(dataType, "bool") || !strcmp(dataType, "boolean")) {
      return memory.readMemory<bool>(hProcess, memAddress) ? 1 : 0;
    
    } else if (!strcmp(dataType, "float")) {
      // For float, we'll reinterpret the bits as an int
      float result = memory.readMemory<float>(hProcess, memAddress);
      return *(int*)&result;
    
    } else {
      // For unsupported types in this simple implementation, return 0
      // More complex types would need special handling on the JS side
      return 0;
    }
  }

  __declspec(dllexport) void writeMemory(HANDLE handle, DWORD64 address, const char* dataType, const void* valuePtr) {
    // This function assumes valuePtr points to data of the type specified by dataType.
    // The caller is responsible for ensuring type correctness and memory validity.

    if (!strcmp(dataType, "int8") || !strcmp(dataType, "byte") || !strcmp(dataType, "char")) {
      memory.writeMemory<int8_t>(handle, address, *(static_cast<const int8_t*>(valuePtr)));
    } else if (!strcmp(dataType, "uint8") || !strcmp(dataType, "ubyte") || !strcmp(dataType, "uchar")) {
      memory.writeMemory<uint8_t>(handle, address, *(static_cast<const uint8_t*>(valuePtr)));
    } else if (!strcmp(dataType, "int16") || !strcmp(dataType, "short")) {
      memory.writeMemory<int16_t>(handle, address, *(static_cast<const int16_t*>(valuePtr)));
    } else if (!strcmp(dataType, "uint16") || !strcmp(dataType, "ushort") || !strcmp(dataType, "word")) {
      memory.writeMemory<uint16_t>(handle, address, *(static_cast<const uint16_t*>(valuePtr)));
    } else if (!strcmp(dataType, "int32") || !strcmp(dataType, "int") || !strcmp(dataType, "long")) {
      memory.writeMemory<int32_t>(handle, address, *(static_cast<const int32_t*>(valuePtr)));
    } else if (!strcmp(dataType, "uint32") || !strcmp(dataType, "uint") || !strcmp(dataType, "ulong") || !strcmp(dataType, "dword")) {
      memory.writeMemory<uint32_t>(handle, address, *(static_cast<const uint32_t*>(valuePtr)));
    } else if (!strcmp(dataType, "int64")) {
      memory.writeMemory<int64_t>(handle, address, *(static_cast<const int64_t*>(valuePtr)));
    } else if (!strcmp(dataType, "uint64")) {
      memory.writeMemory<uint64_t>(handle, address, *(static_cast<const uint64_t*>(valuePtr)));
    } else if (!strcmp(dataType, "float")) {
      memory.writeMemory<float>(handle, address, *(static_cast<const float*>(valuePtr)));
    } else if (!strcmp(dataType, "double")) {
      memory.writeMemory<double>(handle, address, *(static_cast<const double*>(valuePtr)));
    } else if (!strcmp(dataType, "ptr") || !strcmp(dataType, "pointer")) {
      memory.writeMemory<intptr_t>(handle, address, *(static_cast<const intptr_t*>(valuePtr)));
    } else if (!strcmp(dataType, "uptr") || !strcmp(dataType, "upointer")) {
      memory.writeMemory<uintptr_t>(handle, address, *(static_cast<const uintptr_t*>(valuePtr)));
    } else if (!strcmp(dataType, "bool") || !strcmp(dataType, "boolean")) {
      memory.writeMemory<bool>(handle, address, *(static_cast<const bool*>(valuePtr)));
    } else if (!strcmp(dataType, "string") || !strcmp(dataType, "str")) {
      // Assumes valuePtr points to a null-terminated C-style string.
      // Writes the string content including the null terminator.
      const char* strValue = static_cast<const char*>(valuePtr);
      memory.writeMemory(handle, address, strValue, strlen(strValue) + 1);
    } else if (!strcmp(dataType, "vector3") || !strcmp(dataType, "vec3")) {
      memory.writeMemory<Vector3>(handle, address, *(static_cast<const Vector3*>(valuePtr)));
    } else if (!strcmp(dataType, "vector4") || !strcmp(dataType, "vec4")) {
      memory.writeMemory<Vector4>(handle, address, *(static_cast<const Vector4*>(valuePtr)));
    } else {
      // Optional: Add error handling for unexpected data type if needed,
      // e.g., throw std::runtime_error or return a bool status.
      // For now, it does nothing for unknown types.
    }
  }

  __declspec(dllexport) void closeProcess(HANDLE hProcess) {
    process proc;
    proc.closeProcess(hProcess);
  }
}