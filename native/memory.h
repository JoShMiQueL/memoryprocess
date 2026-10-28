#pragma once
#include <napi.h>
#include <windows.h>
#include <cstdint>
#include <vector>

namespace mp {

// Read `size` bytes from `address` in `proc`. Returns bytes actually read.
// Throws LastError on hard failure (0 bytes && error != PARTIAL).
std::vector<std::uint8_t> ReadBytes(HANDLE proc, std::uintptr_t address, std::size_t size);
bool WriteBytes(HANDLE proc, std::uintptr_t address, const std::uint8_t* data, std::size_t size);

// Typed helpers
template <typename T>
T ReadValue(HANDLE proc, std::uintptr_t address) {
  T out{};
  SIZE_T read = 0;
  if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(address), &out, sizeof(T), &read) || read != sizeof(T)) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "ReadProcessMemory");
  }
  return out;
}

template <typename T>
bool WriteValue(HANDLE proc, std::uintptr_t address, const T& value) {
  SIZE_T written = 0;
  return WriteProcessMemory(proc, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &written) && written == sizeof(T);
}

} // namespace mp
