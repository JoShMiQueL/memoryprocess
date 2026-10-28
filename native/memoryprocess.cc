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
  exports.Set("scan", Napi::Function::New(env, mp::ScanAsync));
  return exports;
}

NODE_API_MODULE(memoryprocess, Init)
