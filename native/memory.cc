#include "memory.h"
#include <system_error>

namespace mp {

std::vector<std::uint8_t> ReadBytes(HANDLE proc, std::uintptr_t address, std::size_t size) {
  std::vector<std::uint8_t> buf(size);
  SIZE_T read = 0;
  if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(address), buf.data(), size, &read)) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "ReadProcessMemory");
  }
  buf.resize(read);
  return buf;
}

bool WriteBytes(HANDLE proc, std::uintptr_t address, const std::uint8_t* data, std::size_t size) {
  SIZE_T written = 0;
  return WriteProcessMemory(proc, reinterpret_cast<LPVOID>(address), data, size, &written) && written == size;
}

} // namespace mp
