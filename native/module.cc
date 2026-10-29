#include "module.h"
#include "memory.h"
#include <system_error>
#include <tlhelp32.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
extern "C" {
#include "hde/hde64.h"
}

namespace mp {

// Max bytes a single read call may materialize — guards against negative /
// non-finite / absurd `size` values blowing up std::vector across the N-API
// boundary (a length_error crossing N-API aborts the process).
static const double MAX_READ_BYTES = 512.0 * 1024.0 * 1024.0;

// NOTE: handles and addresses cross N-API as doubles — above 2^53 they would
// silently round. Harmless today (canonical user-space VA < 2^48, real HANDLE
// values are small) but don't feed pointers >2^53 through these bindings.

static bool CheckSize(Napi::Env env, double size) {
  if (!std::isfinite(size) || size < 0 || size > MAX_READ_BYTES) {
    Napi::RangeError::New(env, "size must be a finite number between 0 and 512MB")
        .ThrowAsJavaScriptException();
    return false;
  }
  return true;
}

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
  double sizeD = info[2].As<Napi::Number>().DoubleValue();
  if (!CheckSize(env, sizeD)) return env.Null();
  auto size = static_cast<std::size_t>(sizeD);
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

// allocMemory(handle, size, protection[, nearAddress]) -> bigint
// `nearAddress` is passed to VirtualAllocEx as lpAddress — a hint used to land
// trampoline stubs within rel32 range (±2GB) of a hook site.
Napi::Value AllocMemorySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) { Napi::TypeError::New(env, "expected (handle,size,protection[,nearAddress])").ThrowAsJavaScriptException(); return env.Null(); }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto size = static_cast<SIZE_T>(info[1].As<Napi::Number>().DoubleValue());
  DWORD prot = info[2].As<Napi::Number>().Uint32Value();
  LPVOID hint = nullptr;
  if (info.Length() > 3 && info[3].IsNumber())
    hint = reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(info[3].As<Napi::Number>().DoubleValue()));
  LPVOID p = VirtualAllocEx(h, hint, size, MEM_COMMIT | MEM_RESERVE, prot);
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
  if (snap == INVALID_HANDLE_VALUE) return Napi::Array::New(env, 0); // callers expect number[], never null
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
  // QA4-C3: suspending OUR OWN thread from a sync binding freezes the JS
  // engine mid-call — it can never reach resumeThread (unrecoverable
  // deadlock). Refuse silently (false) so suspendAll() on the caller's own
  // pid skips the calling thread instead of hanging.
  if (tid == GetCurrentThreadId()) return Napi::Boolean::New(env, false);
  HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
  if (!t) return Napi::Boolean::New(env, false);
  DWORD r = SuspendThread(t);
  CloseHandle(t);
  return Napi::Boolean::New(env, r != (DWORD)-1);
}

// currentThreadId() -> number
// Exported so the TS suspendAll() can skip the calling thread explicitly.
Napi::Value CurrentThreadIdSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, static_cast<double>(GetCurrentThreadId()));
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
  double sizeD = info[2].As<Napi::Number>().DoubleValue();
  if (!CheckSize(env, sizeD)) return env.Null();
  auto size = static_cast<std::size_t>(sizeD);

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

// writeProtectedMemory(handle, address, buffer[, protection]) -> boolean
// QA4-M1: the old TS flow did protect(addr,len)->oldProt(first page only)->
// write->protect(addr,len,oldProt) — a write spanning a protection boundary
// restored EVERY page in the span to the first page's old protection,
// silently changing protections on the second region. This native
// implementation walks VirtualQueryEx over the write span, records each
// region's real old protection, unprotects the whole span, writes, then
// restores each region individually. Single-region writes keep identical
// behavior. Restore failures are reported via the `restored` flag — a
// restored=false result means part of the span is left at `protection`.
Napi::Value WriteProtectedMemorySync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "expected (handle,address,buffer[,protection])")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  if (!info[2].IsBuffer()) {
    Napi::TypeError::New(env, "value must be a Buffer").ThrowAsJavaScriptException();
    return env.Null();
  }
  auto buf = info[2].As<Napi::Buffer<std::uint8_t>>();
  DWORD newProt = PAGE_EXECUTE_READWRITE;
  if (info.Length() > 3 && info[3].IsNumber())
    newProt = info[3].As<Napi::Number>().Uint32Value();
  if (buf.Length() == 0) {
    // Nothing to do — return the same result shape as a real write.
    auto o = Napi::Object::New(env);
    o.Set("ok", Napi::Boolean::New(env, true));
    o.Set("restored", Napi::Boolean::New(env, true));
    o.Set("protected", Napi::Boolean::New(env, true));
    return o;
  }

  // QA4-M1: record per-region old protection across the whole write span
  // BEFORE unprotecting — VirtualProtectEx only reports the first page's
  // old value, so the query walk is the only correct source.
  struct RegionSnap { std::uintptr_t base; std::uintptr_t end; DWORD oldProt; };
  std::vector<RegionSnap> regions;
  const std::uintptr_t end = addr + buf.Length();
  {
    std::uintptr_t cur = addr;
    while (cur < end) {
      MEMORY_BASIC_INFORMATION mbi{};
      if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) ||
          mbi.State != MEM_COMMIT || mbi.RegionSize == 0) {
        auto e = Napi::Error::New(env, "VirtualQueryEx failed or region not committed");
        e.Set("code", "PROTECT_FAILED");
        e.Set("win32code", Napi::Number::New(env, (double)GetLastError()));
        e.ThrowAsJavaScriptException();
        return env.Null();
      }
      std::uintptr_t rBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
      std::uintptr_t rEnd = rBase + mbi.RegionSize;
      regions.push_back({ rBase < cur ? cur : rBase,
                          rEnd > end ? end : rEnd, mbi.Protect });
      cur = rEnd;
    }
  }

  // Unprotect each region span (VirtualProtectEx clamps to whole pages, which
  // is fine — only pages intersecting [addr,end) are touched).
  bool allProtected = true;
  for (const auto& r : regions) {
    DWORD old = 0;
    if (!VirtualProtectEx(h, reinterpret_cast<LPVOID>(r.base), r.end - r.base,
                          newProt, &old)) {
      allProtected = false; // continue — best effort
    }
  }

  SIZE_T written = 0;
  const bool wrote = WriteProcessMemory(
      h, reinterpret_cast<LPVOID>(addr), buf.Data(), buf.Length(), &written) &&
      written == buf.Length();

  // Restore each region to ITS recorded protection (not the first page's).
  bool allRestored = true;
  for (const auto& r : regions) {
    DWORD old = 0;
    if (!VirtualProtectEx(h, reinterpret_cast<LPVOID>(r.base), r.end - r.base,
                          r.oldProt, &old)) {
      allRestored = false;
    }
  }
  FlushInstructionCache(h, reinterpret_cast<LPCVOID>(addr), buf.Length());

  auto o = Napi::Object::New(env);
  o.Set("ok", Napi::Boolean::New(env, wrote));
  o.Set("restored", Napi::Boolean::New(env, allRestored));
  o.Set("protected", Napi::Boolean::New(env, allProtected));
  return o;
}

static void ThrowInject(Napi::Env env, const char* what, DWORD code) {
  auto err = Napi::Error::New(env, what);
  err.Set("code", "INJECT_FAILED");
  err.Set("win32code", Napi::Number::New(env, static_cast<double>(code)));
  err.ThrowAsJavaScriptException();
}

// injectDll(pid, dllPath) -> boolean
// QA4-M2: dllPath must be ABSOLUTE. A relative name resolves against the
// TARGET's cwd + DLL search order — a DLL-planting primitive when that cwd is
// attacker-writable. Reject anything that isn't `X:\...` or a `\\` UNC path.
// QA4-M2 also: the path is written UTF-16LE and LoadLibraryW is used — the
// old LoadLibraryA path mangled non-ANSI filenames per the target's codepage.
static bool IsAbsolutePath(const std::string& p) {
  if (p.size() >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
      p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
    return true;                                    // X:\...
  if (p.size() >= 2 && p[0] == '\\' && p[1] == '\\')
    return true;                                    // \\server\share or \\?\...
  return false;
}

Napi::Value InjectDllSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString()) {
    Napi::TypeError::New(env, "expected (pid, dllPath)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  std::string path = info[1].As<Napi::String>().Utf8Value();
  if (!IsAbsolutePath(path)) {
    ThrowInject(env, "dllPath must be an absolute path (X:\\... or \\\\UNC)", ERROR_INVALID_NAME);
    return env.Null();
  }
  if (path.size() > 32767) {
    ThrowInject(env, "dllPath exceeds maximum NT path length (32767)", ERROR_FILENAME_EXCED_RANGE);
    return env.Null();
  }
  // Optional 3rd arg: remote-thread wait timeout (bounded — a negative or
  // huge value would wrap DWORD into an ~infinite sync wait, QA4-H1).
  DWORD waitMs = 10000;
  if (info.Length() > 2 && info[2].IsNumber()) {
    double t = info[2].As<Napi::Number>().DoubleValue();
    if (!std::isfinite(t) || t < 0 || t > 60000) {
      Napi::RangeError::New(env, "timeoutMs must be a finite number in [0, 60000]")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    waitMs = static_cast<DWORD>(t);
  }
  // UTF-8 -> UTF-16LE for LoadLibraryW.
  std::wstring wpath;
  {
    int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (n <= 0) { ThrowInject(env, "dllPath is not valid UTF-8", ERROR_NO_UNICODE_TRANSLATION); return env.Null(); }
    wpath.assign(static_cast<size_t>(n) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), n);
  }
  const DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
  HANDLE h = OpenProcess(access, FALSE, pid);
  if (!h) { ThrowInject(env, "OpenProcess failed", GetLastError()); return env.Null(); }

  // WoW64 targets load a 32-bit kernel32 at a different base — LoadLibraryW
  // resolved in *our* (x64) process would be the wrong address. Refuse rather
  // than silently corrupting the target.
  {
    BOOL wow = FALSE;
    IsWow64Process(h, &wow);
    if (wow) {
      CloseHandle(h);
      ThrowInject(env, "injectDll does not support WoW64 (32-bit) targets", ERROR_NOT_SUPPORTED);
      return env.Null();
    }
  }

  bool ok = false;
  do {
    const SIZE_T wbytes = (wpath.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(h, nullptr, wbytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { DWORD e = GetLastError(); ThrowInject(env, "VirtualAllocEx failed", e); break; }
    SIZE_T w = 0;
    if (!WriteProcessMemory(h, remote, wpath.c_str(), wbytes, &w)) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "WriteProcessMemory failed", e); break;
    }
    // NOTE: kernel32 is loaded at the same base in every x64 process, so this
    // locally-resolved LoadLibraryW address is valid in the target. This holds
    // because kernel32 is a KnownDll mapped at a shared ASLR base.
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = k32 ? GetProcAddress(k32, "LoadLibraryW") : nullptr;
    if (!loadLib) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "LoadLibraryW resolution failed", e); break;
    }
    HANDLE t = CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib), remote, 0, nullptr);
    if (!t) {
      DWORD e = GetLastError();
      VirtualFreeEx(h, remote, 0, MEM_RELEASE);
      ThrowInject(env, "CreateRemoteThread failed", e); break;
    }
    DWORD wr = WaitForSingleObject(t, waitMs);
    if (wr != WAIT_OBJECT_0) {
      // QA4-C1: do NOT TerminateThread here. TerminateThread is asynchronous
      // and killing a thread inside LoadLibraryW can leave the target's
      // loader lock permanently held — every subsequent LoadLibrary /
      // thread-creation in the victim deadlocks. Instead we close our handle
      // and deliberately LEAK the small path buffer so a late-finishing
      // thread never reads freed memory. Bounded leak ≤64KB; a wedged target
      // is worse.
      CloseHandle(t);
      ThrowInject(env, "LoadLibraryW remote thread timed out (leaked path buffer; target not terminated to avoid loader-lock deadlock)",
                  wr == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
      break;
    }
    DWORD exitCode = 0;
    GetExitCodeThread(t, &exitCode);
    CloseHandle(t);
    VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    // LoadLibraryW returns the module HMODULE as the thread exit code; 0 means
    // the DLL failed to load (not found, bad bitness, missing dependency).
    if (exitCode == 0) {
      ThrowInject(env, "LoadLibraryW returned NULL in target", ERROR_MOD_NOT_FOUND);
      break;
    }
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

  // QA4-C4: same WoW64 guard as injectDll — our 64-bit FreeLibrary address is
  // meaningless inside a 32-bit target's address space; the remote thread
  // would execute a wild pointer.
  {
    BOOL wow = FALSE;
    IsWow64Process(h, &wow);
    if (wow) {
      CloseHandle(h);
      ThrowInject(env, "ejectDll does not support WoW64 (32-bit) targets", ERROR_NOT_SUPPORTED);
      return env.Null();
    }
  }

  bool ok = false;
  do {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC freeLib = k32 ? GetProcAddress(k32, "FreeLibrary") : nullptr;
    if (!freeLib) { ThrowInject(env, "FreeLibrary resolution failed", GetLastError()); break; }
    HANDLE t = CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLib),
        reinterpret_cast<LPVOID>(base), 0, nullptr);
    if (!t) { ThrowInject(env, "CreateRemoteThread failed", GetLastError()); break; }
    DWORD wr = WaitForSingleObject(t, 10000);
    if (wr != WAIT_OBJECT_0) {
      // QA4-C1: never TerminateThread inside FreeLibrary — the remote thread
      // can hold the loader lock; killing it wedges the target permanently.
      // Just close our handle and report the timeout.
      CloseHandle(t);
      ThrowInject(env, "FreeLibrary remote thread timed out (target thread left running to avoid loader-lock deadlock)",
                  wr == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
      break;
    }
    // QA4-C4: FreeLibrary returns BOOL as the thread exit code — verify it.
    // Without this check, ejecting kernel32/main.exe/garbage bases reported
    // success while nothing (or worse, the wrong thing) happened.
    DWORD exitCode = 0;
    GetExitCodeThread(t, &exitCode);
    CloseHandle(t);
    if (exitCode == 0) {
      ThrowInject(env, "FreeLibrary returned FALSE in target (bad/foreign module base or refcount pinned)",
                  ERROR_MOD_NOT_FOUND);
      break;
    }
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

// getThreadContext(tid) -> { rip,rsp,rbp,dr0..dr3,dr6,dr7,eflags } | null
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
  o.Set("dr6", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr6)));
  o.Set("dr7", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.Dr7)));
  o.Set("eflags", Napi::BigInt::New(env, static_cast<std::uint64_t>(ctx.EFlags)));
  return o;
}

static bool JsToU64(const Napi::Value& v, std::uint64_t& out) {
  if (v.IsBigInt()) { bool ls; out = v.As<Napi::BigInt>().Uint64Value(&ls); return true; }
  if (v.IsNumber()) { out = static_cast<std::uint64_t>(v.As<Napi::Number>().DoubleValue()); return true; }
  return false;
}

// setThreadContext(tid, { rip?, rsp?, rbp?, dr0?..dr3?, dr6?, dr7?, eflags? }) -> boolean
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
  set("dr6", *reinterpret_cast<std::uint64_t*>(&ctx.Dr6));
  set("dr7", *reinterpret_cast<std::uint64_t*>(&ctx.Dr7));
  if (patch.Has("eflags") && JsToU64(patch.Get("eflags"), v)) ctx.EFlags = static_cast<DWORD>(v);

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
  if (info.Length() > 3 && info[3].IsNumber()) {
    // QA4-H1: Uint32Value() on -1 wraps to 0xFFFFFFFF = INFINITE — a sync
    // binding that never returns bricks the whole JS process. Clamp to a
    // bounded range; negative/non-finite values are a caller bug.
    double t = info[3].As<Napi::Number>().DoubleValue();
    if (!std::isfinite(t) || t < 0 || t > 60000) {
      Napi::RangeError::New(env, "timeoutMs must be a finite number in [0, 60000]")
          .ThrowAsJavaScriptException();
      return env.Null();
    }
    timeout = static_cast<DWORD>(t);
  }

  HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!h) return env.Null();
  HANDLE t = CreateRemoteThread(h, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<std::uintptr_t>(fn)),
      reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(param)), 0, nullptr);
  if (!t) { CloseHandle(h); return env.Null(); }
  DWORD wr = WaitForSingleObject(t, timeout);
  DWORD code = 0;
  // QA4-C1: TerminateThread is asynchronous — it only *requests* termination.
  // Returning immediately after TerminateThread lets the caller (execShellcode
  // finally-block, injectDll) free memory the zombie thread may still be
  // executing in. Wait for the thread object itself to be signaled (max 2s)
  // so a timeout-return really means the thread is dead. NOTE: terminating a
  // thread that was mid-LoadLibrary can still leave the target's loader lock
  // held — an inherent TerminateThread hazard; callers needing guaranteed
  // non-wedging behavior should prefer a longer timeout over termination.
  if (wr != WAIT_OBJECT_0) {
    TerminateThread(t, 0);
    WaitForSingleObject(t, 2000);
    CloseHandle(t);
    CloseHandle(h);
    return env.Null();
  }
  bool ok = GetExitCodeThread(t, &code) != 0;
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
  if (count > 256) count = 256; // 256*15 ≈ 4KB window; also prevents count*16 wraparound

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
    // hde64_disasm takes no length and may read up to 15 bytes for one
    // instruction — feeding it buf.data()+off directly walks past the end of
    // the allocation on a truncated tail. Decode from a 16-byte padded stack
    // scratch instead; the trailing zeros make a truncated insn fail cleanly.
    std::uint8_t scratch[16] = {};
    const std::size_t avail = buf.size() - off;
    std::memcpy(scratch, buf.data() + off, avail < sizeof(scratch) ? avail : sizeof(scratch));
    hde64s hs{};
    unsigned int len = hde64_disasm(scratch, &hs);
    if (len == 0 || (hs.flags & F_ERROR)) break;
    if (off + len > buf.size()) break;   // truncated tail instruction
    auto o = Napi::Object::New(env);
    o.Set("offset", Napi::Number::New(env, static_cast<double>(off)));
    o.Set("length", Napi::Number::New(env, static_cast<double>(len)));
    // QA4-C2: expose position-dependence so callers (hook) can refuse to copy
    // the instruction to a differently-based trampoline. F_RELATIVE covers
    // rel8/16/32 branch+call immediates (E8/E9/EB, 70-7F, 0F 8x, E0-E3, xbegin).
    // A ModRM mod=00 rm=101 encoding is RIP-relative ([rip+disp32]).
    const bool ripRel = (hs.flags & F_MODRM) && hs.modrm_mod == 0 &&
                        hs.modrm_rm == 5;
    o.Set("relative",
          Napi::Boolean::New(env, (hs.flags & F_RELATIVE) != 0 || ripRel));
    arr.Set(n, o);
    off += len;
    n++;
  }
  return arr;
}

// hookSteal(handle, address[, minBytes][, stubAddr]) -> { length, bytes:Buffer }
//
// MinHook-style relocation: steals whole instructions until >= minBytes are
// covered, then rewrites position-relative operands so the stolen bytes are
// correct when executed from `stubAddr` (which must be within rel32 range of
// `address` — the caller's #allocNear guarantees this):
//  - rel32 branch/call (E8/E9/0F8x, xbegin): rel32 rewritten in place, OR
//    copied verbatim when the target is INSIDE the stolen window (MinHook's
//    "internal jump" rule — distances are preserved by the copy).
//  - RIP-relative ModRM (mod=00 rm=101): disp32 rewritten in place so it
//    still reaches the original absolute target.
//  - rel8/rel16 branches incl. LOOP/JECXZ (E0-E3): verbatim if internal —
//    the operand is position-independent within the window — otherwise
//    REFUSED (rel8 can't be widened to a same-length rewrite; MinHook
//    refuses LOOP/JECXZ-external too).
// Without `stubAddr` every position-relative instruction is refused
// (HOOK_RELOCATE) — the old verify-only behavior for raw inspection calls.
// Throws HOOK_STEAL when <minBytes of decodable instructions exist, or
// HOOK_RELOCATE naming the offending opcode/offset. Returns the stolen bytes
// so the caller doesn't need a second remote read.
Napi::Value HookStealSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "expected (handle, address[, minBytes][, stubAddr])")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  HANDLE h = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(info[0].As<Napi::Number>().DoubleValue()));
  auto addr = static_cast<std::uintptr_t>(info[1].As<Napi::Number>().DoubleValue());
  std::size_t minBytes = 5;
  std::uintptr_t stub = 0;
  // Accepted arg shapes:
  //   hookSteal(h, a, 5)               — minBytes number
  //   hookSteal(h, a, 5, stub)         — minBytes + stubAddr (number|bigint)
  //   hookSteal(h, a, {minBytes, stubAddr}) — options object
  if (info.Length() > 2) {
    if (info[2].IsNumber()) {
      double m = info[2].As<Napi::Number>().DoubleValue();
      if (std::isfinite(m) && m >= 1 && m <= 64) minBytes = static_cast<std::size_t>(m);
      if (info.Length() > 3) {
        std::uint64_t s = 0;
        if (JsToU64(info[3], s)) stub = static_cast<std::uintptr_t>(s);
      }
    } else if (info[2].IsObject() && !info[2].IsNull()) {
      auto opts = info[2].As<Napi::Object>();
      auto mb = opts.Get("minBytes");
      if (mb.IsNumber()) {
        double m = mb.As<Napi::Number>().DoubleValue();
        if (std::isfinite(m) && m >= 1 && m <= 64) minBytes = static_cast<std::size_t>(m);
      }
      auto sa = opts.Get("stubAddr");
      if (!sa.IsUndefined()) {
        std::uint64_t s = 0;
        if (JsToU64(sa, s)) stub = static_cast<std::uintptr_t>(s);
      }
    }
  }
  // An instruction beginning <15 bytes before minBytes can overshoot past it —
  // read minBytes+15 so no valid tail instruction truncates.
  std::vector<std::uint8_t> buf;
  try {
    buf = ReadBytes(h, addr, minBytes + 15);
  } catch (const std::system_error& e) {
    auto err = Napi::Error::New(env, e.what());
    err.Set("code", "READ_FAILED");
    err.Set("win32code", Napi::Number::New(env, static_cast<double>(e.code().value())));
    err.ThrowAsJavaScriptException();
    return env.Null();
  }

  auto throwAt = [&](const char* code, const std::string& msg) {
    auto err = Napi::Error::New(env, msg);
    err.Set("code", code);
    err.ThrowAsJavaScriptException();
  };

  // Pass 1: decode — collect each instruction's decode state for relocation.
  struct StolenInsn {
    std::size_t off;         // offset within buf
    unsigned len;
    std::uint32_t flags;
    std::uint8_t opcode, opcode2;
    bool ripRel;             // RIP-relative ModRM operand (mod=00 rm=101)
    std::size_t immOff;      // offset of immediate field (valid if immSize>0)
    unsigned immSize;        // immediate field size in bytes
    std::size_t dispOff;     // offset of displacement field (valid if dispSize>0)
    unsigned dispSize;       // displacement field size in bytes
  };
  std::vector<StolenInsn> insns;
  std::size_t off = 0;
  while (off < minBytes && off < buf.size()) {
    std::uint8_t scratch[16] = {};
    const std::size_t avail = buf.size() - off;
    std::memcpy(scratch, buf.data() + off, avail < sizeof(scratch) ? avail : sizeof(scratch));
    hde64s hs{};
    unsigned int len = hde64_disasm(scratch, &hs);
    if (len == 0 || (hs.flags & F_ERROR)) {
      char msg[128];
      std::snprintf(msg, sizeof(msg),
                    "hookSteal: undecodable instruction at +%zu — refusing to steal", off);
      throwAt("HOOK_STEAL", msg);
      return env.Null();
    }
    if (off + len > buf.size()) {
      char msg[128];
      std::snprintf(msg, sizeof(msg),
                    "hookSteal: truncated instruction at +%zu — cannot cover %zu bytes", off, minBytes);
      throwAt("HOOK_STEAL", msg);
      return env.Null();
    }
    StolenInsn si{};
    si.off = off;
    si.len = len;
    si.flags = hs.flags;
    si.opcode = hs.opcode;
    si.opcode2 = hs.opcode2;
    si.ripRel = (hs.flags & F_MODRM) && hs.modrm_mod == 0 && hs.modrm_rm == 5;
    // Field sizes: the immediate/disp land at the tail of the instruction.
    // imm is the LAST field; disp precedes it — MinHook's offset math:
    //   disp field = len - immSize - dispSize  (same as len-((flags&0x3C)>>2)-4)
    si.immSize = (hs.flags & F_IMM64) ? 8 :
                 (hs.flags & F_IMM32) ? 4 :
                 (hs.flags & F_IMM16) ? 2 :
                 (hs.flags & F_IMM8)  ? 1 : 0;
    si.dispSize = (hs.flags & F_DISP32) ? 4 :
                  (hs.flags & F_DISP16) ? 2 :
                  (hs.flags & F_DISP8)  ? 1 : 0;
    si.immOff = si.immSize ? off + len - si.immSize : 0;
    si.dispOff = si.dispSize ? off + len - si.immSize - si.dispSize : 0;
    insns.push_back(si);
    off += len;
  }
  if (off < minBytes) {
    char msg[128];
    std::snprintf(msg, sizeof(msg),
                  "hookSteal: only %zu decodable bytes at 0x%llX — need >= %zu",
                  off, static_cast<unsigned long long>(addr), minBytes);
    throwAt("HOOK_STEAL", msg);
    return env.Null();
  }
  const std::size_t stolenLen = off;

  // Pass 2: relocate — rewrite position-relative operands in the copied
  // bytes. `bytes` becomes the relocated copy (what the caller writes to the
  // stub); `original` keeps the pristine bytes for unhook.
  std::vector<std::uint8_t> original(buf.begin(), buf.begin() + stolenLen);
  for (const StolenInsn& si : insns) {
    if (!(si.flags & F_RELATIVE) && !si.ripRel) continue;

    const char* which = (si.flags & F_RELATIVE) ? "relative branch/call"
                                                : "RIP-relative operand";
    auto refuse = [&](const char* detail) {
      char msg[192];
      std::snprintf(msg, sizeof(msg),
                    "hookSteal: stolen instruction at +%zu (opcode %02X%s) is %s: %s",
                    si.off, si.opcode2 ? si.opcode2 : si.opcode,
                    si.opcode2 ? " (0F map)" : "", which, detail);
      throwAt("HOOK_RELOCATE", msg);
      return env.Null();
    };

    if (stub == 0) {
      return refuse("pass stubAddr to enable relocation (copying it verbatim "
                    "would produce a wild jump/read)");
    }

    // Immediate-carried relative branches/calls (E8/E9/EB, 70-7F, 0F8x, E0-E3,
    // xbegin C7 F8): the rel field IS the immediate.
    if (si.flags & F_RELATIVE) {
      if (si.immSize == 0) continue;
      // Old absolute branch target.
      std::int64_t oldRel = 0;
      std::memcpy(&oldRel, buf.data() + si.immOff, si.immSize);
      switch (si.immSize) {  // sign-extend
        case 1: oldRel = static_cast<std::int8_t>(oldRel); break;
        case 2: oldRel = static_cast<std::int16_t>(oldRel); break;
        case 4: oldRel = static_cast<std::int32_t>(oldRel); break;
      }
      const std::uintptr_t oldTarget =
          static_cast<std::uintptr_t>(addr + si.off + si.len + oldRel);
      // Internal jump: target lands inside the stolen window. The copy
      // preserves the operand→target distance — leave the bytes verbatim.
      if (oldTarget >= addr && oldTarget < addr + stolenLen) continue;
      if (si.immSize != 4) {
        return refuse("rel8/rel16 external target cannot be widened in place "
                      "(MinHook refuses LOOP/JECXZ-external too) — hook a "
                      "different instruction-aligned site");
      }
      const std::int64_t newRel =
          static_cast<std::int64_t>(oldTarget) -
          (static_cast<std::int64_t>(stub) + si.off + si.len);
      if (newRel < INT32_MIN || newRel > INT32_MAX) {
        return refuse("rel32 rewrite lands out of ±2GB range from the stub — "
                      "allocate the stub nearer to the branch target");
      }
      const std::int32_t r32 = static_cast<std::int32_t>(newRel);
      std::memcpy(buf.data() + si.immOff, &r32, 4);
      continue;
    }

    // RIP-relative ModRM memory operand: the disp32 field is the position-
    // dependent part — rewrite it to reach the same absolute address.
    if (si.ripRel) {
      if (si.dispSize != 4) continue;  // mod=00 rm=101 always disp32
      std::int32_t d32 = 0;
      std::memcpy(&d32, buf.data() + si.dispOff, 4);
      const std::uintptr_t oldTarget =
          static_cast<std::uintptr_t>(addr + si.off + si.len + d32);
      if (oldTarget >= addr && oldTarget < addr + stolenLen) continue; // internal
      const std::int64_t newDisp =
          static_cast<std::int64_t>(oldTarget) -
          (static_cast<std::int64_t>(stub) + si.off + si.len);
      if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
        return refuse("disp32 rewrite lands out of ±2GB range from the stub — "
                      "allocate the stub nearer to the operand target");
      }
      const std::int32_t n32 = static_cast<std::int32_t>(newDisp);
      std::memcpy(buf.data() + si.dispOff, &n32, 4);
      continue;
    }
  }

  auto o = Napi::Object::New(env);
  o.Set("length", Napi::Number::New(env, static_cast<double>(stolenLen)));
  o.Set("bytes", Napi::Buffer<std::uint8_t>::Copy(env, buf.data(), stolenLen));
  o.Set("original",
        Napi::Buffer<std::uint8_t>::Copy(env, original.data(), stolenLen));
  return o;
}

// ---------- v2.1 additions ----------

// suspendProcess(pid) / resumeProcess(pid) via undocumented-but-stable
// NtSuspendProcess / NtResumeProcess exported by ntdll. Atomic whole-process
// suspend — strictly better than per-thread suspendAll (no TOCTOU where a
// new thread spawns mid-enumeration).
static Napi::Value NtSuspendResume(const Napi::CallbackInfo& info, bool suspend) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid)").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  // QA4-C3: suspending OUR OWN process freezes the JS engine — even though
  // NtSuspendProcess skips the calling thread, every other thread (including
  // any that would resume us) is suspended and the object can never reach
  // resumeProcess(). Suspend on self-pid is an unrecoverable deadlock; refuse
  // with a clear error. Resume on self-pid is harmless — it just clears
  // suspend counts on our own threads.
  if (suspend && pid == GetCurrentProcessId()) {
    auto err = Napi::Error::New(env,
        "refusing to suspend the calling process (self-suspend deadlock)");
    err.Set("code", "SELF_SUSPEND");
    err.ThrowAsJavaScriptException();
    return env.Null();
  }
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return Napi::Boolean::New(env, false);
  using NtProcFn = LONG (NTAPI*)(HANDLE);
  FARPROC fp = GetProcAddress(ntdll, suspend ? "NtSuspendProcess" : "NtResumeProcess");
  if (!fp) return Napi::Boolean::New(env, false);
  HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!h) return Napi::Boolean::New(env, false);
  LONG status = reinterpret_cast<NtProcFn>(fp)(h);
  CloseHandle(h);
  return Napi::Boolean::New(env, status == 0 /* STATUS_SUCCESS */);
}

Napi::Value SuspendProcessSync(const Napi::CallbackInfo& info) { return NtSuspendResume(info, true); }
Napi::Value ResumeProcessSync(const Napi::CallbackInfo& info) { return NtSuspendResume(info, false); }

// enableDebugPrivilege() -> boolean
// Grants the CALLING process SeDebugPrivilege so it can open
// protected/system processes. No target handle needed.
Napi::Value EnableDebugPrivilegeSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  HANDLE tok = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
    return Napi::Boolean::New(env, false);
  LUID luid{};
  bool ok = LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid) != 0;
  if (ok) {
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0 &&
         GetLastError() == ERROR_SUCCESS;
  }
  CloseHandle(tok);
  return Napi::Boolean::New(env, ok);
}

// WaitForExitWorker: WaitForSingleObject on the (dup'd) process handle, then
// GetExitCodeProcess. Resolve(exitCode) or resolve(null) on timeout.
class WaitExitWorker : public Napi::AsyncWorker {
public:
  WaitExitWorker(Napi::Env env, Napi::Promise::Deferred deferred, DWORD pid, DWORD timeoutMs)
      : Napi::AsyncWorker(env), deferred_(deferred), pid_(pid), timeout_(timeoutMs) {}
  ~WaitExitWorker() override { if (h_) CloseHandle(h_); }

  void Execute() override {
    h_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid_);
    if (!h_) { SetError("OpenProcess failed"); return; }
    DWORD wr = WaitForSingleObject(h_, timeout_);
    if (wr == WAIT_OBJECT_0) {
      DWORD code = 0;
      if (GetExitCodeProcess(h_, &code)) { exited_ = true; exitCode_ = code; }
    }
    // WAIT_TIMEOUT / WAIT_FAILED -> exited_ stays false -> resolve null
  }
  void OnOK() override {
    if (exited_) deferred_.Resolve(Napi::Number::New(Env(), static_cast<double>(exitCode_)));
    else deferred_.Resolve(Env().Null());
  }
  void OnError(const Napi::Error& e) override { deferred_.Reject(e.Value()); }
private:
  Napi::Promise::Deferred deferred_;
  DWORD pid_, timeout_;
  HANDLE h_ = nullptr;
  bool exited_ = false;
  DWORD exitCode_ = 0;
};

// waitForExit(pid, timeoutMs) -> Promise<exitCode | null>
Napi::Value WaitForExitAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid[, timeoutMs])").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  DWORD timeout = INFINITE;
  if (info.Length() > 1 && info[1].IsNumber()) {
    double t = info[1].As<Napi::Number>().DoubleValue();
    // QA4-H1: a negative timeout would wrap DWORD and become a ~49-day
    // blocking wait. Reject negatives/NaN; Infinity stays INFINITE by design.
    if (!std::isfinite(t)) {
      if (std::isinf(t) && t > 0) { timeout = INFINITE; }
      else {
        Napi::RangeError::New(env, "timeoutMs must be >= 0 (Infinity allowed)")
            .ThrowAsJavaScriptException();
        return env.Null();
      }
    } else if (t < 0) {
      Napi::RangeError::New(env, "timeoutMs must be >= 0 (Infinity allowed)")
          .ThrowAsJavaScriptException();
      return env.Null();
    } else if (t > 0xFFFFFFFE) timeout = INFINITE;
    else timeout = static_cast<DWORD>(t);
  }
  auto deferred = Napi::Promise::Deferred::New(env);
  auto promise = deferred.Promise();
  auto* w = new WaitExitWorker(env, std::move(deferred), pid, timeout);
  w->Queue();
  return promise;
}

// ---------- findWhatWrites (DebugActiveProcess + HW write breakpoints) ----------

// Hardware breakpoints only deliver their #DB exception to a debugger attached
// to the TARGET — setting Dr regs without a debug loop just crashes the victim
// with an unhandled EXCEPTION_SINGLE_STEP. So the CE "find what writes" flow
// must own a real debugger session: DebugActiveProcess -> arm RW=01 data
// breakpoints on every thread -> pump WaitForDebugEvent collecting
// EXCEPTION_SINGLE_STEP hits -> restore Dr regs, ContinueDebugEvent, detach.
//
// NOTE on `rip`: a data breakpoint is a *trap* — it fires AFTER the write, so
// the reported address is the instruction FOLLOWING the write, not the writer
// itself. CE shows the same caveat; disassemble backwards to find the store.

#ifndef DBG_CONTINUE
#define DBG_CONTINUE 0x00010002L
#endif
#ifndef DBG_EXCEPTION_NOT_HANDLED
#define DBG_EXCEPTION_NOT_HANDLED 0x80010001L
#endif

namespace {

struct FwwHit {
  std::uint64_t rip = 0;
  DWORD tid = 0;
  CONTEXT ctx{};
};

struct ArmedThread {
  DWORD tid = 0;
  int slot = -1;
  std::uint64_t origDr = 0;
  std::uint64_t origDr7 = 0;
};

// LEN encoding for Dr7: 00=1B, 01=2B, 11=4B, 10=8B (validated 1|2|4|8 by TS).
static std::uint64_t LenBits(unsigned size) {
  switch (size) {
    case 1: return 0;
    case 2: return 1;
    case 8: return 2;
    default: return 3; // 4
  }
}

// Arm a RW=01 (data write) breakpoint on the first free Dr slot of `hThread`.
// `hThread` may be a handle from CREATE_THREAD/CREATE_PROCESS debug events or
// OpenThread; it must allow GET/SET_CONTEXT and SUSPEND_RESUME. Suspend+resume
// is balanced (net-zero suspend count) so threads already suspended by the
// debug attach stay suspended and running threads stay running.
// Returns slot (0-3) on success and fills origDr/origDr7 for restore; -1 on
// failure.
static int ArmWriteBp(HANDLE hThread, std::uint64_t addr, unsigned size,
                      std::uint64_t& origDr, std::uint64_t& origDr7) {
  if (SuspendThread(hThread) == (DWORD)-1) return -1;
  int slot = -1;
  do {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) break;
    std::uint64_t dr7 = ctx.Dr7;
    for (int s = 0; s < 4; s++) {
      if ((dr7 & (0x3ull << (s * 2))) == 0) { slot = s; break; } // L+G clear
    }
    if (slot < 0) break;
    origDr7 = dr7;
    origDr = (&ctx.Dr0)[slot];
    const std::uint64_t shift = 16ull + slot * 4;
    dr7 &= ~(0xfull << shift);          // clear RW+LEN
    dr7 |= (0x1ull | (LenBits(size) << 2)) << shift; // RW=01 write, LEN=size
    dr7 |= 1ull << (slot * 2);          // local enable L{slot}
    ctx.Dr7 = dr7;
    (&ctx.Dr0)[slot] = addr;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(hThread, &ctx)) { slot = -1; break; }
  } while (0);
  ResumeThread(hThread);
  return slot;
}

static void DisarmBp(HANDLE hThread, int slot, std::uint64_t origDr,
                     std::uint64_t origDr7) {
  if (SuspendThread(hThread) == (DWORD)-1) return;
  CONTEXT ctx{};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(hThread, &ctx)) {
    ctx.Dr7 = origDr7;
    (&ctx.Dr0)[slot] = origDr;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(hThread, &ctx);
  }
  ResumeThread(hThread);
}

class FindWhatWritesWorker : public Napi::AsyncWorker {
public:
  FindWhatWritesWorker(Napi::Env env, Napi::Promise::Deferred deferred,
                       DWORD pid, std::uint64_t addr, unsigned size,
                       DWORD timeoutMs, unsigned maxHits)
      : Napi::AsyncWorker(env), deferred_(deferred), pid_(pid), addr_(addr),
        size_(size), timeoutMs_(timeoutMs), maxHits_(maxHits) {}

  ~FindWhatWritesWorker() override {
    for (HANDLE h : openHandles_) CloseHandle(h);
  }

  // Attach is best-effort: callers may need enableDebugPrivilege() first for
  // protected targets. DebugSetProcessKillOnExit(false) keeps the debuggee
  // alive when our process exits while still attached.
  void Execute() override {
    // Detach completion is asynchronous on Windows — a fresh
    // DebugActiveProcess immediately after DebugActiveProcessStop can return
    // ERROR_ACCESS_DENIED while the kernel tears down the debug port. Retry
    // for up to ~500ms so back-to-back findWhatWrites calls work.
    DWORD err = 0;
    bool ok = false;
    for (int i = 0; i < 50 && !ok; i++) {
      ok = DebugActiveProcess(pid_) != 0;
      if (!ok) { err = GetLastError(); Sleep(10); }
    }
    if (!ok) {
      SetError("DebugActiveProcess failed (win32 " + std::to_string(err) + ")");
      return;
    }
    attached_ = true;
    DebugSetProcessKillOnExit(FALSE);

    // QA4-M3 (lifecycle): wrap all post-attach phases so ANY C++ exception
    // (bad_alloc under a flooding target, length_error in hits_/armed_
    // growth) still runs disarm+drain+Stop. Without this the debuggee is
    // left attached with armed Dr7 breakpoints and suspended threads — the
    // next write to the watched addr would fire an unhandled #DB and kill it.
    try {
      RunPhases();
    } catch (const std::exception& e) {
      CleanupDebuggee();
      SetError(std::string("findWhatWrites failed: ") + e.what());
      return;
    } catch (...) {
      CleanupDebuggee();
      SetError("findWhatWrites failed: unknown exception");
      return;
    }
    CleanupDebuggee();
  }

  void RunPhases() {
    const ULONGLONG armDeadline = GetTickCount64() + 500;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs_;

    // Phase 1: collect the attach-time event burst (CREATE_PROCESS,
    // LOAD_DLLs, CREATE_THREAD per existing thread, initial breakpoint) and
    // arm each reported thread. Threads reported by CREATE_THREAD are already
    // debug-suspended at this point; our suspend/resume pair is balanced so
    // the bp is on before they can run. Hits are collected here too — a thread
    // armed+continued early in this loop can fire while we drain the rest.
    int quietWaits = 0;
    while (quietWaits < 3 && GetTickCount64() < armDeadline &&
           hits_.size() < maxHits_ && !exited_) {
      DEBUG_EVENT ev{};
      if (!WaitForDebugEvent(&ev, 20)) { quietWaits++; continue; }
      quietWaits = 0;
      ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, HandleEvent(ev));
    }
    // Fallback: arm anything the event burst missed (rare — attach reports
    // every thread, but belt-and-suspenders for filtered/racy cases).
    ArmSnapshotThreads();

    // Phase 2: collect hits until timeout / maxHits / process exit.
    while (!exited_ && hits_.size() < maxHits_ && GetTickCount64() < deadline) {
      const ULONGLONG left = deadline - GetTickCount64();
      DEBUG_EVENT ev{};
      if (!WaitForDebugEvent(&ev, left > 25 ? 25 : (DWORD)left)) continue;
      ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, HandleEvent(ev));
    }
  }

  // Phase 3: disarm every armed thread (restoring ORIGINAL Dr regs — the
  // target may legitimately use its own hw breakpoints), drain pending
  // events, disarm any stragglers hit mid-disarm, drain again, detach.
  // Everything runs on this thread — DebugActiveProcess/Continue/DebugStop
  // are debugger-thread-bound. Idempotent: runs only while attached_ and is
  // invoked from every Execute() exit path (normal + exception).
  void CleanupDebuggee() {
    if (!attached_) return;
    auto disarmAll = [this]() {
      for (auto& at : armed_) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                  THREAD_SUSPEND_RESUME,
                              FALSE, at.tid);
        if (!t) continue;
        DisarmBp(t, at.slot, at.origDr, at.origDr7);
        CloseHandle(t);
      }
    };
    auto drain = [this]() {
      DEBUG_EVENT ev{};
      for (int i = 0; i < 64 && WaitForDebugEvent(&ev, 2); i++) {
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
            ev.u.CreateProcessInfo.hFile)
          CloseHandle(ev.u.CreateProcessInfo.hFile);
        if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile)
          CloseHandle(ev.u.LoadDll.hFile);
        // A queued single-step is our bp firing mid-disarm — swallow it
        // (DBG_CONTINUE). A queued genuine exception gets NOT_HANDLED so it
        // reaches the debuggee's SEH as it would without us.
        DWORD disp = DBG_CONTINUE;
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            ev.u.Exception.ExceptionRecord.ExceptionCode !=
                EXCEPTION_SINGLE_STEP &&
            ev.u.Exception.ExceptionRecord.ExceptionCode !=
                EXCEPTION_BREAKPOINT)
          disp = DBG_EXCEPTION_NOT_HANDLED;
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disp);
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
      }
    };
    disarmAll();
    drain();      // flush pending bp hits + resume stopped threads
    disarmAll();  // threads stopped on a queued event during pass 1 skipped
                  // SetThreadContext — disarm them now that they're resumed
    drain();      // release the last stopped threads, empty the port
    DebugActiveProcessStop(pid_);
    attached_ = false;
  }

  void OnOK() override {
    Napi::Env env = Env();
    auto arr = Napi::Array::New(env, hits_.size());
    for (size_t i = 0; i < hits_.size(); i++) {
      auto o = Napi::Object::New(env);
      const FwwHit& h = hits_[i];
      o.Set("rip", Napi::BigInt::New(env, h.rip));
      o.Set("tid", Napi::Number::New(env, static_cast<double>(h.tid)));
      auto c = Napi::Object::New(env);
      c.Set("rip", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Rip)));
      c.Set("rsp", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Rsp)));
      c.Set("rbp", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Rbp)));
      c.Set("dr0", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr0)));
      c.Set("dr1", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr1)));
      c.Set("dr2", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr2)));
      c.Set("dr3", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr3)));
      c.Set("dr6", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr6)));
      c.Set("dr7", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.Dr7)));
      c.Set("eflags", Napi::BigInt::New(env, static_cast<std::uint64_t>(h.ctx.EFlags)));
      o.Set("threadContext", c);
      arr.Set(i, o);
    }
    deferred_.Resolve(arr);
  }

  void OnError(const Napi::Error& e) override {
    deferred_.Reject(e.Value());
  }

private:
  // Returns the ContinueDebugEvent disposition for `ev`; also feeds side
  // effects (arming, hit collection, handle tracking).
  DWORD HandleEvent(const DEBUG_EVENT& ev) {
    switch (ev.dwDebugEventCode) {
      case EXCEPTION_DEBUG_EVENT: {
        const auto& er = ev.u.Exception.ExceptionRecord;
        if (er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
          return HandleSingleStep(ev);
        }
        // The attach-time int3 (and any target int3) is debugger-handled.
        if (er.ExceptionCode == EXCEPTION_BREAKPOINT) return DBG_CONTINUE;
        // Everything else belongs to the debuggee's SEH chain.
        return DBG_EXCEPTION_NOT_HANDLED;
      }
      case CREATE_THREAD_DEBUG_EVENT: {
        const DWORD tid = ev.dwThreadId;
        // QA4-m4: hThread here is system-owned (unlike CREATE_PROCESS's hFile
        // which the debugger must close). Microsoft's debug samples and docs
        // never close it — the system cleans it up on EXIT_THREAD. Verified:
        // do NOT close; closing could later collide with a recycled handle
        // value the debugger also sees. Disarm uses OpenThread-by-tid anyway.
        HANDLE t = ev.u.CreateThread.hThread;
        ArmOnHandle(tid, t);
        return DBG_CONTINUE;
      }
      case CREATE_PROCESS_DEBUG_EVENT: {
        if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
        ArmOnHandle(ev.dwThreadId, ev.u.CreateProcessInfo.hThread);
        return DBG_CONTINUE;
      }
      case LOAD_DLL_DEBUG_EVENT: {
        if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        return DBG_CONTINUE;
      }
      case EXIT_THREAD_DEBUG_EVENT:
        // If it was armed there's nothing to restore — the thread is gone.
        return DBG_CONTINUE;
      case EXIT_PROCESS_DEBUG_EVENT:
        exited_ = true;
        return DBG_CONTINUE;
      case RIP_EVENT:
      case OUTPUT_DEBUG_STRING_EVENT:
      case UNLOAD_DLL_DEBUG_EVENT:
      default:
        return DBG_CONTINUE;
    }
  }

  DWORD HandleSingleStep(const DEBUG_EVENT& ev) {
    const DWORD tid = ev.dwThreadId;
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return DBG_EXCEPTION_NOT_HANDLED;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_ALL | CONTEXT_DEBUG_REGISTERS;
    bool ours = false;
    if (GetThreadContext(t, &ctx)) {
      int slot = -1;
      for (const auto& at : armed_)
        if (at.tid == tid) { slot = at.slot; break; }
      if (slot >= 0 && (ctx.Dr6 & (1ull << slot))) ours = true;
      if (ours) {
        FwwHit h;
        h.rip = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(
                ev.u.Exception.ExceptionRecord.ExceptionAddress));
        h.tid = tid;
        h.ctx = ctx;
        hits_.push_back(h);
        ctx.Dr6 = 0; // acknowledge so a stale B bit can't false-trigger
        SetThreadContext(t, &ctx);
      }
    }
    CloseHandle(t);
    // Ours -> swallowed; foreign single-steps (e.g. target's own TF use) go
    // back unhandled so we don't silently swallow them.
    return ours ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
  }

  void ArmOnHandle(DWORD tid, HANDLE hThread) {
    if (!hThread) return;
    for (const auto& at : armed_)
      if (at.tid == tid) return; // already armed
    ArmedThread at;
    at.tid = tid;
    at.slot = ArmWriteBp(hThread, addr_, size_, at.origDr, at.origDr7);
    if (at.slot >= 0) armed_.push_back(at);
  }

  // Arm threads the event burst didn't report (Toolhelp fallback).
  void ArmSnapshotThreads() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
      do {
        if (te.th32OwnerProcessID != pid_) continue;
        bool armed = false;
        for (const auto& at : armed_)
          if (at.tid == te.th32ThreadID) { armed = true; break; }
        if (armed) continue;
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                  THREAD_SUSPEND_RESUME,
                              FALSE, te.th32ThreadID);
        if (!t) continue;
        ArmedThread at;
        at.tid = te.th32ThreadID;
        at.slot = ArmWriteBp(t, addr_, size_, at.origDr, at.origDr7);
        if (at.slot >= 0) { armed_.push_back(at); openHandles_.push_back(t); }
        else CloseHandle(t);
      } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
  }

  Napi::Promise::Deferred deferred_;
  DWORD pid_;
  std::uint64_t addr_;
  unsigned size_;
  DWORD timeoutMs_;
  unsigned maxHits_;
  bool attached_ = false;
  bool exited_ = false;
  std::vector<ArmedThread> armed_;
  std::vector<FwwHit> hits_;
  // Toolhelp-armed threads keep their handle so phase 3 could disarm via the
  // SAME handle if needed; closed in dtor.
  std::vector<HANDLE> openHandles_;
};

} // anonymous namespace

// findWhatWrites(pid, address, size, timeoutMs, maxHits) ->
//   Promise<{rip, tid, threadContext}[]>
Napi::Value FindWhatWritesAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "expected (pid, address[, size, timeoutMs, maxHits])")
        .ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD pid = info[0].As<Napi::Number>().Uint32Value();
  std::uint64_t addr = 0;
  if (!JsToU64(info[1], addr)) {
    Napi::TypeError::New(env, "address must be number|bigint").ThrowAsJavaScriptException();
    return env.Null();
  }
  unsigned size = 4;
  if (info.Length() > 2 && info[2].IsNumber())
    size = info[2].As<Napi::Number>().Uint32Value();
  if (size != 1 && size != 2 && size != 4 && size != 8) {
    Napi::RangeError::New(env, "size must be 1|2|4|8").ThrowAsJavaScriptException();
    return env.Null();
  }
  DWORD timeout = 1000;
  if (info.Length() > 3 && info[3].IsNumber()) {
    double t = info[3].As<Napi::Number>().DoubleValue();
    if (std::isfinite(t) && t > 0 && t <= 60000) timeout = static_cast<DWORD>(t);
  }
  unsigned maxHits = 32;
  if (info.Length() > 4 && info[4].IsNumber()) {
    double m = info[4].As<Napi::Number>().DoubleValue();
    if (std::isfinite(m) && m >= 1) maxHits = m > 1024 ? 1024u : static_cast<unsigned>(m);
  }

  // QA4-H7: CONTEXT/Dr registers use the x64 struct — on a WoW64 (32-bit)
  // target Get/SetThreadContext operate on WOW64_CONTEXT and the arm would
  // silently corrupt the debuggee or never fire. Refuse up front (same
  // pattern as injectDll).
  {
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (ph) {
      BOOL wow = FALSE;
      IsWow64Process(ph, &wow);
      CloseHandle(ph);
      if (wow) {
        Napi::Error::New(env,
            "findWhatWrites does not support WoW64 (32-bit) targets")
            .ThrowAsJavaScriptException();
        return env.Null();
      }
    }
  }

  auto deferred = Napi::Promise::Deferred::New(env);
  auto promise = deferred.Promise();
  auto* w = new FindWhatWritesWorker(env, std::move(deferred), pid, addr, size,
                                     timeout, maxHits);
  w->Queue();
  return promise;
}

} // namespace mp
