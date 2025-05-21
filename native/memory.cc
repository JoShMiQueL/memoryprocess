#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include "memory.h"

memory::memory() {}
memory::~memory() {}

std::vector<MEMORY_BASIC_INFORMATION> memory::getRegions(HANDLE hProcess) {
  std::vector<MEMORY_BASIC_INFORMATION> regions;

  // Check if the process handle is valid.
  // INVALID_HANDLE_VALUE is typically -1, NULL is 0.
  // A process handle should be a positive value.
  if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
    // Cannot set an error message here as the function signature doesn't support it.
    // Returning an empty vector indicates no regions found or an error.
    return regions; 
  }

  MEMORY_BASIC_INFORMATION region;
  DWORD64 address = 0; // Start scanning from address 0

  // Loop through memory regions
  // VirtualQueryEx returns the number of bytes written to the buffer (sizeof(region)) on success
  // It returns 0 on failure.
  while (VirtualQueryEx(hProcess, (LPVOID)address, &region, sizeof(region)) == sizeof(region)) {
    regions.push_back(region);
    
    // Check for overflow before adding to address
    if (address + region.RegionSize < address) {
        // Overflow occurred, stop scanning to prevent infinite loop or incorrect access
        break;
    }
    address += region.RegionSize;
  }

  return regions;
}