#include "process.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <system_error>

namespace mp {

static DWORD LastErr() { return GetLastError(); }

HANDLE OpenByPid(DWORD pid, DWORD access) {
  HANDLE h = OpenProcess(access, FALSE, pid);
  if (!h) throw std::system_error(static_cast<int>(LastErr()), std::system_category(), "OpenProcess");
  return h;
}

DWORD PidFromName(const std::string& name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  // case-insensitive wide compare
  std::wstring want(name.begin(), name.end());
  for (wchar_t& c : want) c = towlower(c);
  DWORD found = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      std::wstring cur(pe.szExeFile);
      for (wchar_t& c : cur) c = towlower(c);
      if (cur == want) { found = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found;
}

std::vector<ProcInfo> ListProcesses() {
  std::vector<ProcInfo> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return out;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      char name[MAX_PATH];
      size_t n = 0;
      wcstombs_s(&n, name, pe.szExeFile, sizeof(name) - 1);
      out.push_back({ pe.th32ProcessID, std::string(name) });
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return out;
}

std::vector<ModuleInfo> GetModules(HANDLE proc, DWORD /*pid*/) {
  std::vector<ModuleInfo> out;
  HMODULE mods[1024];
  DWORD needed = 0;
  if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return out;
  DWORD count = needed / sizeof(HMODULE);
  for (DWORD i = 0; i < count; i++) {
    MODULEINFO mi{};
    if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) continue;
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameExW(proc, mods[i], path, MAX_PATH)) continue;
    char utf8[MAX_PATH * 2];
    size_t n = 0;
    wcstombs_s(&n, utf8, path, sizeof(utf8) - 1);
    // base filename
    std::string p(utf8);
    out.push_back({ reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll), static_cast<std::uint32_t>(mi.SizeOfImage), p });
  }
  return out;
}

ModuleInfo GetModule(HANDLE proc, DWORD pid, const std::string& name) {
  auto mods = GetModules(proc, pid);
  std::string want = name;
  for (auto& c : want) c = static_cast<char>(tolower(c));
  for (auto& m : mods) {
    std::string base = m.path.substr(m.path.find_last_of("\\/") + 1);
    for (auto& c : base) c = static_cast<char>(tolower(c));
    if (base == want) return m;
  }
  return {};
}

std::vector<RegionInfo> GetRegions(HANDLE proc) {
  std::vector<RegionInfo> out;
  MEMORY_BASIC_INFORMATION mbi{};
  std::uintptr_t addr = 0;
  const std::uintptr_t max = 0x7FFFFFFFFFFFULL;
  while (addr < max && VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
    if (mbi.State == MEM_COMMIT) {
      out.push_back({ reinterpret_cast<std::uintptr_t>(mbi.BaseAddress),
                      static_cast<std::size_t>(mbi.RegionSize),
                      static_cast<std::uint32_t>(mbi.Protect),
                      static_cast<std::uint32_t>(mbi.Type) });
    }
    addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (mbi.RegionSize == 0) break;
  }
  return out;
}

} // namespace mp
