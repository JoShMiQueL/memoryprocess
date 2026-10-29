#include <napi.h>
#include "module.h"

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("openProcess", Napi::Function::New(env, mp::OpenProcessSync));
  exports.Set("closeHandle", Napi::Function::New(env, mp::CloseHandleSync));
  exports.Set("listProcesses", Napi::Function::New(env, mp::ListProcessesSync));
  exports.Set("getModules", Napi::Function::New(env, mp::GetModulesSync));
  exports.Set("getRegions", Napi::Function::New(env, mp::GetRegionsSync));
  exports.Set("readValue", Napi::Function::New(env, mp::ReadValueSync));
  exports.Set("writeValue", Napi::Function::New(env, mp::WriteValueSync));
  exports.Set("readBuffer", Napi::Function::New(env, mp::ReadBufferSync));
  exports.Set("writeBuffer", Napi::Function::New(env, mp::WriteBufferSync));
  exports.Set("scan", Napi::Function::New(env, mp::ScanAsync));
  exports.Set("allocMemory", Napi::Function::New(env, mp::AllocMemorySync));
  exports.Set("freeMemory", Napi::Function::New(env, mp::FreeMemorySync));
  exports.Set("protectMemory", Napi::Function::New(env, mp::ProtectMemorySync));
  exports.Set("isWow64", Napi::Function::New(env, mp::IsWow64Sync));
  exports.Set("listThreads", Napi::Function::New(env, mp::ListThreadsSync));
  exports.Set("suspendThread", Napi::Function::New(env, mp::SuspendThreadSync));
  exports.Set("resumeThread", Napi::Function::New(env, mp::ResumeThreadSync));
  exports.Set("readSafe", Napi::Function::New(env, mp::ReadSafeSync));
  exports.Set("flushInstructions", Napi::Function::New(env, mp::FlushInstructionsSync));
  exports.Set("injectDll", Napi::Function::New(env, mp::InjectDllSync));
  exports.Set("ejectDll", Napi::Function::New(env, mp::EjectDllSync));
  exports.Set("queryAddress", Napi::Function::New(env, mp::QueryAddressSync));
  exports.Set("getThreadContext", Napi::Function::New(env, mp::GetThreadContextSync));
  exports.Set("setThreadContext", Napi::Function::New(env, mp::SetThreadContextSync));
  exports.Set("callRemote", Napi::Function::New(env, mp::CallRemoteSync));
  exports.Set("disasmInstructions", Napi::Function::New(env, mp::DisasmInstructionsSync));
  exports.Set("scanValue", Napi::Function::New(env, mp::ScanValueAsync));
  exports.Set("suspendProcess", Napi::Function::New(env, mp::SuspendProcessSync));
  exports.Set("resumeProcess", Napi::Function::New(env, mp::ResumeProcessSync));
  exports.Set("enableDebugPrivilege", Napi::Function::New(env, mp::EnableDebugPrivilegeSync));
  exports.Set("waitForExit", Napi::Function::New(env, mp::WaitForExitAsync));
  exports.Set("findWhatWrites", Napi::Function::New(env, mp::FindWhatWritesAsync));
  exports.Set("hookSteal", Napi::Function::New(env, mp::HookStealSync));
  exports.Set("writeProtectedMemory", Napi::Function::New(env, mp::WriteProtectedMemorySync));
  exports.Set("currentThreadId", Napi::Function::New(env, mp::CurrentThreadIdSync));
  return exports;
}

NODE_API_MODULE(memoryprocess, Init)
