#pragma once
#include <napi.h>
#include <windows.h>
#include <string>
#include <vector>

namespace mp {

struct ModuleInfo {
  std::uintptr_t base;
  std::uint32_t size;
  std::string path;
};

struct RegionInfo {
  std::uintptr_t baseAddress;
  std::size_t size;
  std::uint32_t protection;
  std::uint32_t type;
};

struct ProcInfo {
  std::uint32_t pid;
  std::string name;
};

// Open a process by pid. Returns handle or throws via SetLastError mapping.
HANDLE OpenByPid(DWORD pid, DWORD access);
// Resolve a process name (e.g. "notepad.exe") to pid. 0 if not found.
DWORD PidFromName(const std::string& name);
std::vector<ProcInfo> ListProcesses();
std::vector<ModuleInfo> GetModules(HANDLE proc, DWORD pid);
ModuleInfo GetModule(HANDLE proc, DWORD pid, const std::string& name);
std::vector<RegionInfo> GetRegions(HANDLE proc);

} // namespace mp
