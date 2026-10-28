#pragma once
#include <napi.h>
#include "process.h"

namespace mp {

Napi::Value OpenProcessSync(const Napi::CallbackInfo& info);
Napi::Value CloseHandleSync(const Napi::CallbackInfo& info);
Napi::Value ListProcessesSync(const Napi::CallbackInfo& info);
Napi::Value GetModulesSync(const Napi::CallbackInfo& info);
Napi::Value GetRegionsSync(const Napi::CallbackInfo& info);
Napi::Value ReadValueSync(const Napi::CallbackInfo& info);
Napi::Value WriteValueSync(const Napi::CallbackInfo& info);
Napi::Value ReadBufferSync(const Napi::CallbackInfo& info);
Napi::Value ScanAsync(const Napi::CallbackInfo& info);

} // namespace mp
