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
Napi::Value WriteBufferSync(const Napi::CallbackInfo& info);
Napi::Value ScanAsync(const Napi::CallbackInfo& info);

// v2 Tier-1/2 additions
Napi::Value AllocMemorySync(const Napi::CallbackInfo& info);      // VirtualAllocEx
Napi::Value FreeMemorySync(const Napi::CallbackInfo& info);       // VirtualFreeEx
Napi::Value ProtectMemorySync(const Napi::CallbackInfo& info);    // VirtualProtectEx
Napi::Value IsWow64Sync(const Napi::CallbackInfo& info);          // IsWow64Process
Napi::Value ListThreadsSync(const Napi::CallbackInfo& info);      // TH32CS_SNAPTHREAD
Napi::Value SuspendThreadSync(const Napi::CallbackInfo& info);    // OpenThread+SuspendThread
Napi::Value ResumeThreadSync(const Napi::CallbackInfo& info);     // OpenThread+ResumeThread

// v2 final-batch additions
Napi::Value ReadSafeSync(const Napi::CallbackInfo& info);         // VirtualQueryEx walk + zero-fill
Napi::Value FlushInstructionsSync(const Napi::CallbackInfo& info);// FlushInstructionCache
Napi::Value InjectDllSync(const Napi::CallbackInfo& info);        // LoadLibraryA remote thread
Napi::Value EjectDllSync(const Napi::CallbackInfo& info);         // FreeLibrary remote thread

// v2 Tier-3 additions
Napi::Value QueryAddressSync(const Napi::CallbackInfo& info);     // single VirtualQueryEx
Napi::Value GetThreadContextSync(const Napi::CallbackInfo& info); // GetThreadContext (CONTEXT_ALL|DEBUG)
Napi::Value SetThreadContextSync(const Napi::CallbackInfo& info); // patch fields + SetThreadContext
Napi::Value CallRemoteSync(const Napi::CallbackInfo& info);       // CreateRemoteThread + wait

} // namespace mp
