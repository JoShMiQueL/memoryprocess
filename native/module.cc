#include "module.h"
#include "memory.h"
#include <system_error>
#include <tlhelp32.h>
extern "C" {
#include "hde/hde64.h"
}

namespace mp {

static Napi::Object ErrToJs(Napi::Env env, const std::system_error& e) {
  auto obj = Napi::Object::New(env);
  obj.Set("code", Napi::Number::New(env, e.code().value()));
  obj.Set("message", Napi::String::New(env, e.what()));
  obj.Set("win32", Napi::Boolean::New(env, true));
  return obj;
}

Napi::Value OpenProcessSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) { Napi::TypeError::New(env, "expected (nameOrPid[, access])").ThrowAsJavaScriptException(); return env.Null(); }

  // Least-privilege default: VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION
  DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
  if (info.Length() > 1 && info[1].IsNumber()) access = info[1].As<Napi::Number>().Uint32Value();

  DWORD pid = 0;
  if (info[0].IsNumber()) {
    pid = info[0].As<Napi::Number>().Uint32Value();
  } else if (info[0].IsString()) {
    pid = PidFromName(info[0].As<Napi::String>().Utf8Value());
    if (!pid) {
      auto e = Napi::Error::New(env, "ProcessNotFound");
      e.Set("code", "PROCESS_NOT_FOUND");
      e.ThrowAsJavaScriptException();
      return env.Null();
    }
  } else {
    Napi::TypeError::New(env, "nameOrPid must be string|number").ThrowAsJavaScriptException();
    return env.Null();
  }

  try {
    HANDLE h = OpenByPid(pid, access);
    auto res = Napi::Object::New(env);
    res.Set("handle", Napi::Number::New(env, static_cast<double>(reinterpret_cast<std::uintptr_t>(h))));
    res.Set("pid", Napi::Number::New(env, pid));
    return res;
  } catch (const std::system_error& e) {
    auto err = Napi::Error::New(env, e.what());
    err.Set("code", e.code().value() == 5 ? "ACCESS_DENIED" : "OPEN_FAILED");
    err.Set("win32code", Napi::Number::New(env, static_cast<double>(e.code().value())));
    err.ThrowAsJavaScriptException();
    return env.Null();
  }
}

Napi::Value CloseHandleSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected handle").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  return Napi::Boolean::New(env, CloseHandle(h) != 0);
}

Napi::Value ListProcessesSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto list = ListProcesses();
  auto arr = Napi::Array::New(env, list.size());
  for (size_t i = 0; i < list.size(); i++) {
    auto o = Napi::Object::New(env);
    o.Set("pid", Napi::Number::New(env, static_cast<double>(list[i].pid)));
    o.Set("name", list[i].name);
    arr.Set(i, o);
  }
  return arr;
}

Napi::Value GetModulesSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) { Napi::TypeError::New(env, "expected (handle,pid)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  DWORD pid = info[1].As<Napi::Number>().Uint32Value();
  auto mods = GetModules(h, pid);
  auto arr = Napi::Array::New(env, mods.size());
  for (size_t i = 0; i < mods.size(); i++) {
    auto o = Napi::Object::New(env);
    o.Set("base", Napi::Number::New(env, static_cast<double>(mods[i].base)));
    o.Set("size", Napi::Number::New(env, static_cast<double>(mods[i].size)));
    o.Set("path", mods[i].path);
    arr.Set(i, o);
  }
  return arr;
}

Napi::Value GetRegionsSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected handle").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto regs = GetRegions(h);
  auto arr = Napi::Array::New(env, regs.size());
  for (size_t i = 0; i < regs.size(); i++) {
    auto o = Napi::Object::New(env);
    o.Set("baseAddress", Napi::Number::New(env, static_cast<double>(regs[i].baseAddress)));
    o.Set("size", Napi::Number::New(env, static_cast<double>(regs[i].size)));
    o.Set("protection", Napi::Number::New(env, static_cast<double>(regs[i].protection)));
    o.Set("type", Napi::Number::New(env, static_cast<double>(regs[i].type)));
    arr.Set(i, o);
  }
  return arr;
}

Napi::Value ReadBufferSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,size)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  auto size = static_cast<std::size_t>(info[2].As<Napi::Number>().DoubleValue());
  try {
    auto bytes = ReadBytes(h, addr, size);
    return Napi::Buffer<std::uint8_t>::Copy(env, bytes.data(), bytes.size());
  } catch (const std::system_error& e) {
    auto err = Napi::Error::New(env, e.what());
    err.Set("code", "READ_FAILED");
    err.Set("win32code", Napi::Number::New(env, static_cast<double>(e.code().value())));
    err.ThrowAsJavaScriptException();
    return env.Null();
  }
}

Napi::Value WriteBufferSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,buffer)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  if (!info[2].IsBuffer()) { Napi::TypeError::New(env, "value must be a Buffer").ThrowAsJavaScriptException(); return env.Null(); }
  auto buf = info[2].As<Napi::Buffer<std::uint8_t>>();
  bool ok = WriteBytes(h, addr, buf.Data(), buf.Length());
  return Napi::Boolean::New(env, ok);
}

// ---------- v2 Tier-1/2 ----------

Napi::Value AllocMemorySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,size,protection)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto size = static_cast<SIZE_T>(info[1].As<Napi::Number>().DoubleValue());
  DWORD prot = info[2].As<Napi::Number>().Uint32Value();
  LPVOID p = VirtualAllocEx(h, nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
  if (!p) { auto e = Napi::Error::New(env, "VirtualAllocEx failed"); e.Set("code", "ALLOC_FAILED"); e.Set("win32code", Napi::Number::New(env, (double)GetLastError())); e.ThrowAsJavaScriptException(); return env.Null(); }
  return Napi::BigInt::New(env, reinterpret_cast<std::uint64_t>(p));
}

Napi::Value FreeMemorySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) { Napi::TypeError::New(env, "expected (handle,address)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  return Napi::Boolean::New(env, VirtualFreeEx(h, reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE) != 0);
}

Napi::Value ProtectMemorySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,size,prot)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  auto size = static_cast<SIZE_T>(info[2].As<Napi::Number>().DoubleValue());
  DWORD prot = info[3].As<Napi::Number>().Uint32Value();
  DWORD old = 0;
  if (!VirtualProtectEx(h, reinterpret_cast<LPVOID>(addr), size, prot, &old)) {
    auto e = Napi::Error::New(env, "VirtualProtectEx failed"); e.Set("code", "PROTECT_FAILED"); e.Set("win32code", Napi::Number::New(env, (double)GetLastError())); e.ThrowAsJavaScriptException(); return env.Null();
  }
  return Napi::Number::New(env, static_cast<double>(old));
}

Napi::Value IsWow64Sync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected handle").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  BOOL w = FALSE;
  IsWow64Process(h, &w);
  return Napi::Boolean::New(env, w != 0);
}

Napi::Value ListThreadsSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected pid").ThrowAsJavaScriptException(); return env.Null(); }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return env.Null();
  std::vector<DWORD> tids;
  THREADENTRY32 te{}; te.dwSize = sizeof(te);
  if (Thread32First(snap, &te)) {
    do { if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID); } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  auto arr = Napi::Array::New(env, tids.size());
  for (size_t i = 0; i < tids.size(); i++) arr.Set(i, Napi::Number::New(env, tids[i]));
  return arr;
}

Napi::Value SuspendThreadSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected tid").ThrowAsJavaScriptException(); return env.Null(); }
  DWORD tid = info[0].As<Napi::Number>().Uint32Value();
  HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
  if (!t) return Napi::Boolean::New(env, false);
  DWORD r = SuspendThread(t);
  CloseHandle(t);
  return Napi::Boolean::New(env, r != (DWORD)-1);
}

Napi::Value ResumeThreadSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) { Napi::TypeError::New(env, "expected tid").ThrowAsJavaScriptException(); return env.Null(); }
  DWORD tid = info[0].As<Napi::Number>().Uint32Value();
  HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
  if (!t) return Napi::Boolean::New(env, false);
  DWORD r = ResumeThread(t);
  CloseHandle(t);
  return Napi::Boolean::New(env, r != (DWORD)-1);
}

// readValue(handle, address, type) where type in:
// "int32","uint32","int64","uint64","float","double","pointer"
Napi::Value ReadValueSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,type)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  std::string type = info[2].As<Napi::String>().Utf8Value();
  try {
    if (type == "int32") return Napi::Number::New(env, ReadValue<std::int32_t>(h, addr));
    if (type == "uint32") return Napi::Number::New(env, ReadValue<std::uint32_t>(h, addr));
    if (type == "int64") return Napi::BigInt::New(env, ReadValue<std::int64_t>(h, addr));
    if (type == "uint64") return Napi::BigInt::New(env, ReadValue<std::uint64_t>(h, addr));
    if (type == "float") return Napi::Number::New(env, ReadValue<float>(h, addr));
    if (type == "double") return Napi::Number::New(env, ReadValue<double>(h, addr));
    if (type == "pointer") return Napi::BigInt::New(env, static_cast<std::uint64_t>(ReadValue<std::uintptr_t>(h, addr)));
    Napi::TypeError::New(env, "unknown type " + type).ThrowAsJavaScriptException();
    return env.Null();
  } catch (const std::system_error& e) {
    auto err = Napi::Error::New(env, e.what());
    err.Set("code", "READ_FAILED");
    err.Set("win32code", Napi::Number::New(env, static_cast<double>(e.code().value())));
    err.ThrowAsJavaScriptException();
    return env.Null();
  }
}

Napi::Value WriteValueSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4) { Napi::TypeError::New(env, "expected (handle,address,type,value)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  std::string type = info[2].As<Napi::String>().Utf8Value();
  bool ok = false;
  try {
    if (type == "int32") ok = WriteValue<std::int32_t>(h, addr, info[3].As<Napi::Number>().Int32Value());
    else if (type == "uint32") ok = WriteValue<std::uint32_t>(h, addr, info[3].As<Napi::Number>().Uint32Value());
    else if (type == "float") ok = WriteValue<float>(h, addr, info[3].As<Napi::Number>().FloatValue());
    else if (type == "double") ok = WriteValue<double>(h, addr, info[3].As<Napi::Number>().DoubleValue());
    else if (type == "int64") { bool ls; ok = WriteValue<std::int64_t>(h, addr, info[3].As<Napi::BigInt>().Int64Value(&ls)); }
    else if (type == "uint64") { bool ls; ok = WriteValue<std::uint64_t>(h, addr, info[3].As<Napi::BigInt>().Uint64Value(&ls)); }
    else if (type == "pointer") { bool ls; ok = WriteValue<std::uintptr_t>(h, addr, static_cast<std::uintptr_t>(info[3].As<Napi::BigInt>().Uint64Value(&ls))); }
    else { Napi::TypeError::New(env, "unknown type " + type).ThrowAsJavaScriptException(); return env.Null(); }
    return Napi::Boolean::New(env, ok);
  } catch (...) {
    auto err = Napi::Error::New(env, "WriteProcessMemory failed");
    err.Set("code", "WRITE_FAILED");
    err.ThrowAsJavaScriptException();
    return env.Null();
  }
}

// ---------- v2 final batch ----------

// readSafe(handle, address, size) -> Buffer
// Walks regions via VirtualQueryEx; reads committed+readable spans, zero-fills
// gaps/unreadable spans. Only throws if the handle is invalid for VirtualQueryEx.
Napi::Value ReadSafeSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,size)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  auto size = static_cast<std::size_t>(info[2].As<Napi::Number>().DoubleValue());

  std::vector<std::uint8_t> out(size, 0);
  const std::uintptr_t end = addr + size;
  const std::uintptr_t kMax = 0x7FFFFFFFFFFFULL;
  std::uintptr_t cur = addr;

  while (cur < end && cur <= kMax) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi))) {
      DWORD e = GetLastError();
      // ERROR_INVALID_HANDLE / ERROR_ACCESS_DENIED => handle problem: throw.
      // Anything else (invalid address etc.) => leave zeros, we're done.
      if (e == ERROR_INVALID_HANDLE || e == ERROR_ACCESS_DENIED) {
        auto err = Napi::Error::New(env, "VirtualQueryEx failed");
        err.Set("code", "READ_FAILED");
        err.Set("win32code", Napi::Number::New(env, static_cast<double>(e)));
        err.ThrowAsJavaScriptException();
        return env.Null();
      }
      break;
    }

    std::uintptr_t rBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
    std::uintptr_t rEnd = rBase + mbi.RegionSize;
    if (mbi.RegionSize == 0) break;
    if (rEnd > cur && rBase < end) { // overlap
      std::uintptr_t lo = rBase > cur ? rBase : cur;
      std::uintptr_t hi = rEnd < end ? rEnd : end;
      bool readable = (mbi.State == MEM_COMMIT) &&
                      !(mbi.Protect & PAGE_NOACCESS) &&
                      !(mbi.Protect & PAGE_GUARD);
      if (readable) {
        SIZE_T got = 0;
        ReadProcessMemory(h, reinterpret_cast<LPCVOID>(lo),
                          out.data() + (lo - addr), hi - lo, &got);
        // short/failed reads leave those bytes zeroed
      }
    }
    cur = rEnd;
  }
  return Napi::Buffer<std::uint8_t>::Copy(env, out.data(), out.size());
}

// flushInstructions(handle, address, size) -> boolean  (FlushInstructionCache)
Napi::Value FlushInstructionsSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,address,size)").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  auto size = static_cast<SIZE_T>(info[2].As<Napi::Number>().DoubleValue());
  return Napi::Boolean::New(env,
    FlushInstructionCache(h, reinterpret_cast<LPCVOID>(addr), size) != 0);
}

static void ThrowInject(Napi::Env env, const char* what, DWORD code) {
  auto err = Napi::Error::New(env, what);
  err.Set("code", "INJECT_FAILED");
  err.Set("win32code", Napi::Number::New(env, static_cast<double>(code)));
  err.ThrowAsJavaScriptException();
}

// injectDll(pid, dllPath) -> boolean
Napi::Value InjectDllSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString()) {
    Napi::TypeError::New(env, "expected (pid, dllPath)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  std::string path = info[1].As<Napi::String>().Utf8Value();
  const DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
  HANDLE h = OpenProcess(access, FALSE, pid);
  if (!h) { ThrowInject(env, "OpenProcess failed", GetLastError()); return env.Null(); }

  bool ok = false;
  do {
    LPVOID remote = VirtualAllocEx(h, nullptr, path.size() + 1,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { DWORD e = GetLastError(); ThrowInject(env, "VirtualAllocEx failed", e); break; }
    SIZE_T w = 0;
    if (!WriteProcessMemory(h, remote, path.c_str(), path.size() + 1, &w)) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "WriteProcessMemory failed", e); break;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLib = k32 ? GetProcAddress(k32, "LoadLibraryA") : nullptr;
    if (!loadLib) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "LoadLibraryA resolution failed", e); break;
    }
    HANDLE t = CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib), remote, 0, nullptr);
    if (!t) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "CreateRemoteThread failed", e); break;
    }
    WaitForSingleObject(t, 10000);
    CloseHandle(t);
    VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    ok = true;
  } while (0);
  CloseHandle(h);
  if (!ok) return env.Null(); // exception already thrown
  return Napi::Boolean::New(env, true);
}

// ejectDll(pid, moduleBase) -> boolean
Napi::Value EjectDllSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid, moduleBase)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  auto base = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  const DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
  HANDLE h = OpenProcess(access, FALSE, pid);
  if (!h) { ThrowInject(env, "OpenProcess failed", GetLastError()); return env.Null(); }

  bool ok = false;
  do {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC freeLib = k32 ? GetProcAddress(k32, "FreeLibrary") : nullptr;
    if (!freeLib) { ThrowInject(env, "FreeLibrary resolution failed", GetLastError()); break; }
    HANDLE t = CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLib),
        reinterpret_cast<LPVOID>(base), 0, nullptr);
    if (!t) { ThrowInject(env, "CreateRemoteThread failed", GetLastError()); break; }
    WaitForSingleObject(t, 10000);
    CloseHandle(t);
    ok = true;
  } while (0);
  CloseHandle(h);
  if (!ok) return env.Null();
  return Napi::Boolean::New(env, true);
}

// ---------- v2 Tier-3 ----------

// queryAddress(handle, address) -> { baseAddress, allocationBase, size,
//   protection, state, type } | null
Napi::Value QueryAddressSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "expected (handle,address)").ThrowAsJavaScriptException();
    return env.Null();
  }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  MEMORY_BASIC_INFORMATION mbi{};
  if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
    return env.Null();
  if (mbi.State == MEM_FREE) return env.Null(); // unmapped
  auto o = Napi::Object::New(env);
  o.Set("baseAddress", Napi::Number::New(env, static_cast<double>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress))));
  o.Set("allocationBase", Napi::Number::New(env, static_cast<double>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase))));
  o.Set("size", Napi::Number::New(env, static_cast<double>(mbi.RegionSize)));
  o.Set("protection", Napi::Number::New(env, static_cast<double>(mbi.Protect)));
  o.Set("state", Napi::Number::New(env, static_cast<double>(mbi.State)));
  o.Set("type", Napi::Number::New(env, static_cast<double>(mbi.Type)));
  return o;
}

static bool GetFullContext(DWORD tid, CONTEXT& ctx) {
  HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
  if (!t) {
    // Some systems require SET_CONTEXT rights for debug registers read too;
    // retry with ALL access on failure.
    t = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!t) return false;
  }
  ZeroMemory(&ctx, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_ALL | CONTEXT_DEBUG_REGISTERS;
  BOOL ok = GetThreadContext(t, &ctx);
  CloseHandle(t);
  return ok != 0;
}

// getThreadContext(tid) -> { rip,rsp,rbp,dr0,dr1,dr2,dr3,dr7,eflags } | null
// NOTE: caller is expected to have suspended the thread first.
Napi::Value GetThreadContextSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (tid)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD tid = info[0].As<Napi::Number>().Uint32Value();
  CONTEXT ctx{};
  if (!GetFullContext(tid, ctx)) return env.Null();
  auto o = Napi::Object::New(env);
  o.Set("rip", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Rip)));
  o.Set("rsp", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Rsp)));
  o.Set("rbp", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Rbp)));
  o.Set("dr0", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr0)));
  o.Set("dr1", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr1)));
  o.Set("dr2", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr2)));
  o.Set("dr3", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr3)));
  o.Set("dr7", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr7)));
  o.Set("eflags", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.EFlags)));
  return o;
}

static bool JsToU64(const Napi::Value& v, std::uint64_t& out) {
  if (v.IsBigInt()) { bool ls; out = v.As<Napi::BigInt>().Uint64Value(&ls); return true; }
  if (v.IsNumber()) { out = static_cast<std::uint64_t>(v.As<Napi::Number>().DoubleValue()); return true; }
  return false;
}

// setThreadContext(tid, { rip?, rsp?, dr0?, dr1?, dr2?, dr3?, dr7? }) -> boolean
// Reads the current context, patches provided fields, writes it back.
Napi::Value SetThreadContextSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsObject()) {
    Napi::TypeError::New(env, "expected (tid, ctx)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD tid = info[0].As<Napi::Number>().Uint32Value();
  auto patch = info[1].As<Napi::Object>();

  CONTEXT ctx{};
  if (!GetFullContext(tid, ctx)) return Napi::Boolean::New(env, false);

  std::uint64_t v;
  auto set = [&](const char* name, std::uint64_t& field) {
    if (patch.Has(name) && JsToU64(patch.Get(name), v)) field = v;
  };
  set("rip", *reinterpret_cast<std::uint64_t*>(&ctx.Rip));
  set("rsp", *reinterpret_cast<std::uint64_t*>(&ctx.Rsp));
  set("rbp", *reinterpret_cast<std::uint64_t*>(&ctx.Rbp));
  set("dr0", *reinterpret_cast<std::uint64_t*>(&ctx.Dr0));
  set("dr1", *reinterpret_cast<std::uint64_t*>(&ctx.Dr1));
  set("dr2", *reinterpret_cast<std::uint64_t*>(&ctx.Dr2));
  set("dr3", *reinterpret_cast<std::uint64_t*>(&ctx.Dr3));
  set("dr7", *reinterpret_cast<std::uint64_t*>(&ctx.Dr7));
  std::uint64_t efl = ctx.EFlags;
  if (patch.Has("eflags") && JsToU64(patch.Get("eflags"), v)) ctx.EFlags = static_cast<DWORD>(v);
  (void)efl;

  HANDLE t = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
  if (!t) {
    t = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!t) return Napi::Boolean::New(env, false);
  }
  ctx.ContextFlags = CONTEXT_ALL | CONTEXT_DEBUG_REGISTERS;
  BOOL ok = SetThreadContext(t, &ctx);
  CloseHandle(t);
  return Napi::Boolean::New(env, ok != 0);
}

// callRemote(pid, fnAddress, param, timeoutMs?) -> exitCode | null
Napi::Value CallRemoteSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid, fnAddress, param[, timeoutMs])").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  std::uint64_t fn = 0, param = 0;
  if (!JsToU64(info[1], fn) || !JsToU64(info[2], param)) {
    Napi::TypeError::New(env, "fnAddress and param must be number|bigint").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD timeout = 10000;
  if (info.Length() > 3 && info[3].IsNumber())
    timeout = info[3].As<Napi::Number>().Uint32Value();

  HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!h) return env.Null();
  HANDLE t = CreateRemoteThread(h, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<std::uintptr_t>(fn)),
      reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(param)), 0, nullptr);
  if (!t) { CloseHandle(h); return env.Null(); }
  DWORD wr = WaitForSingleObject(t, timeout);
  DWORD code = 0;
  bool ok = (wr == WAIT_OBJECT_0) && GetExitCodeThread(t, &code);
  CloseHandle(t);
  CloseHandle(h);
  if (!ok) return env.Null();
  return Napi::Number::New(env, static_cast<double>(code));
}

// ---------- v2 disasm (HDE64 length decode) ----------

// disasmInstructions(handle, address, count) -> [{offset, length}]
// Reads up to count*16 bytes (capped 4096) once via ReadBytes, then walks
// the buffer with hde64_disasm returning per-instruction offsets+lengths.
Napi::Value DisasmInstructionsSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsNumber() || !info[2].IsNumber()) {
    Napi::TypeError::New(env, "expected (handle, address, count)").ThrowAsJavaScriptException();
    return env.Null();
  }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  auto count = static_cast<std::size_t>(info[2].As<Napi::Number>().DoubleValue());
  if (count == 0) return Napi::Array::New(env, 0);

  std::size_t readSize = count * 16;   // max x64 instruction length is 15
  if (readSize > 4096) readSize = 4096;

  std::vector<std::uint8_t> buf;
  try {
    buf = ReadBytes(h, addr, readSize);
  } catch (const std::system_error& e) {
    auto err = Napi::Error::New(env, e.what());
    err.Set("code", "READ_FAILED");
    err.Set("win32code", Napi::Number::New(env, static_cast<double>(e.code().value())));
    err.ThrowAsJavaScriptException();
    return env.Null();
  }

  auto arr = Napi::Array::New(env);
  std::size_t off = 0, n = 0;
  while (off < buf.size() && n < count) {
    hde64s hs{};
    unsigned int len = hde64_disasm(buf.data() + off, &hs);
    if (len == 0 || (hs.flags & F_ERROR)) break;
    if (off + len > buf.size()) break;   // truncated tail instruction
    auto o = Napi::Object::New(env);
    o.Set("offset", Napi::Number::New(env, static_cast<double>(off)));
    o.Set("length", Napi::Number::New(env, static_cast<double>(len)));
    arr.Set(n, o);
    off += len;
    n++;
  }
  return arr;
}

} // namespace mp
