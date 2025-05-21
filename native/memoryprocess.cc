#include <windows.h>
#include <psapi.h>
#include <napi.h>
#include <string>
#include "module.h"
#include "process.h"
#include "memoryprocess.h"
#include "memory.h"
#include "pattern.h"
#include "functions.h"
#include "dll.h"
#include "debugger.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "onecore.lib")


process Process;
// module Module;
memory Memory;
pattern Pattern;
// functions Functions;

struct Vector3 {
  float x, y, z;
};

struct Vector4 {
  float w, x, y, z;
};

Napi::Value openProcess(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1 && args.Length() != 2) {
    Napi::Error::New(env, "requires 1 argument, or 2 arguments if a callback is being used").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsString() && !args[0].IsNumber()) {
    Napi::Error::New(env, "first argument must be a string or a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 2 && !args[1].IsFunction()) {
    Napi::Error::New(env, "second argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Define error message that may be set by the function that opens the process
  const char* errorMessage = "";

  process::Pair pair;

  if (args[0].IsString()) {
    std::string processNameStr = args[0].As<Napi::String>().Utf8Value();
    if (processNameStr.empty()) {
      Napi::Error::New(env, "Process name cannot be empty.").ThrowAsJavaScriptException();
      return env.Null();
    }
    pair = Process.openProcess(processNameStr.c_str(), &errorMessage);

    // In case it failed to open, let's keep retrying
    // while(!strcmp(process.szExeFile, "")) {
    //   process = Process.openProcess((char*) *(processName), &errorMessage);
    // };
  }

  if (args[0].IsNumber()) {
    uint32_t processId = args[0].As<Napi::Number>().Uint32Value();
    // Typically, process IDs are positive. 0 can be the System Idle Process.
    // Depending on desired behavior, a check for processId == 0 could be added.
    // For now, allowing 0 as it might be a valid target for some information retrieval.
    // However, OpenProcess might fail for it with PROCESS_ALL_ACCESS.
    // Let's add a check if it's negative, though Uint32Value should prevent this.
    // More importantly, a very large number from JS might wrap around if not handled carefully.
    // Napi::Number gives double, then Uint32Value casts. This is generally safe.
    if (processId == 0 && args[0].As<Napi::Number>().DoubleValue() != 0) { // Check if it was negative before Uint32Value
        Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    // A specific check for 0 if it's truly invalid for openProcess context.
    // For now, we'll rely on the underlying openProcess to fail if 0 is not appropriate.

    pair = Process.openProcess(processId, &errorMessage);

    // In case it failed to open, let's keep retrying
    // while(!strcmp(process.szExeFile, "")) {
    //   process = Process.openProcess(info[0].As<Napi::Number>().Uint32Value(), &errorMessage);
    // };
  }

  // If an error message was returned from the function that opens the process, throw the error.
  // Only throw an error if there is no callback (if there's a callback, the error is passed there).
  if (strcmp(errorMessage, "") && args.Length() != 2) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Create a v8 Object (JSON) to store the process information
  Napi::Object processInfo = Napi::Object::New(env);

  processInfo.Set(Napi::String::New(env, "dwSize"), Napi::Value::From(env, (int)pair.process.dwSize));
  processInfo.Set(Napi::String::New(env, "th32ProcessID"), Napi::Value::From(env, (int)pair.process.th32ProcessID));
  processInfo.Set(Napi::String::New(env, "cntThreads"), Napi::Value::From(env, (int)pair.process.cntThreads));
  processInfo.Set(Napi::String::New(env, "th32ParentProcessID"), Napi::Value::From(env, (int)pair.process.th32ParentProcessID));
  processInfo.Set(Napi::String::New(env, "pcPriClassBase"), Napi::Value::From(env, (int)pair.process.pcPriClassBase));
  processInfo.Set(Napi::String::New(env, "szExeFile"), Napi::String::New(env, pair.process.szExeFile));
  processInfo.Set(Napi::String::New(env, "handle"), Napi::Value::From(env, (uintptr_t)pair.handle));

  DWORD64 base = module::getBaseAddress(pair.process.szExeFile, pair.process.th32ProcessID);
  processInfo.Set(Napi::String::New(env, "modBaseAddr"), Napi::Value::From(env, (uintptr_t)base));

  // openProcess can either take one argument or can take
  // two arguments for asychronous use (second argument is the callback)
  if (args.Length() == 2) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[1].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), processInfo });
    return env.Null();
  } else {
    // return JSON
    return processInfo;
  }
}

Napi::Value closeHandle(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1) {
    Napi::Error::New(env, "Requires 1 argument: handle (number).").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extract the handle value.
  // Handles are pointer types. On Windows, they can be small integers or pointers.
  // Casting from Int64Value is generally okay.
  // A more robust system might involve not exposing raw handles directly or using napi_external.
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();

  // Optional: Check if the handle is NULL, though CloseHandle itself handles this.
  // if (handle == NULL) {
  //   Napi::Error::New(env, "Handle cannot be NULL.").ThrowAsJavaScriptException();
  //   return env.Null();
  // }

  BOOL success = CloseHandle(handle);
  // CloseHandle returns 0 on failure. GetLastError() can provide more details.
  if (!success) {
    // Optionally, you could create an error with GetLastError() information.
    // For now, just returning false as per original logic for failure.
  }
  return Napi::Boolean::New(env, success);
}

Napi::Value getProcesses(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() > 1) {
    Napi::Error::New(env, "requires either 0 arguments or 1 argument if a callback is being used").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 1 && !args[0].IsFunction()) {
    Napi::Error::New(env, "first argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Define error message that may be set by the function that gets the processes
  const char* errorMessage = "";

  std::vector<PROCESSENTRY32> processEntries = Process.getProcesses(&errorMessage);

  // If an error message was returned from the function that gets the processes, throw the error.
  // Only throw an error if there is no callback (if there's a callback, the error is passed there).
  if (strcmp(errorMessage, "") && args.Length() != 1) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Creates v8 array with the size being that of the processEntries vector processes is an array of JavaScript objects
  Napi::Array processes = Napi::Array::New(env, processEntries.size());

  // Loop over all processes found
  for (std::vector<PROCESSENTRY32>::size_type i = 0; i != processEntries.size(); i++) {
    // Create a v8 object to store the current process' information
    Napi::Object process = Napi::Object::New(env);

    process.Set(Napi::String::New(env, "cntThreads"), Napi::Value::From(env, (int)processEntries[i].cntThreads));
    process.Set(Napi::String::New(env, "szExeFile"), Napi::String::New(env, processEntries[i].szExeFile));
    process.Set(Napi::String::New(env, "th32ProcessID"), Napi::Value::From(env, (int)processEntries[i].th32ProcessID));
    process.Set(Napi::String::New(env, "th32ParentProcessID"), Napi::Value::From(env, (int)processEntries[i].th32ParentProcessID));
    process.Set(Napi::String::New(env, "pcPriClassBase"), Napi::Value::From(env, (int)processEntries[i].pcPriClassBase));

    // Push the object to the array
    processes.Set(i, process);
  }

  /* getProcesses can either take no arguments or one argument
     one argument is for asychronous use (the callback) */
  if (args.Length() == 1) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[0].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), processes });
    return env.Null();
  } else {
    // return JSON
    return processes;
  }
}

Napi::Value getModules(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1 && args.Length() != 2) {
    Napi::Error::New(env, "requires 1 argument, or 2 arguments if a callback is being used").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "first argument must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 2 && !args[1].IsFunction()) {
    Napi::Error::New(env, "first argument must be a number, second argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Define error message that may be set by the function that gets the modules
  const char* errorMessage = "";

  int32_t processId = args[0].As<Napi::Number>().Int32Value();
  if (processId < 0) {
    Napi::Error::New(env, "Process ID must be a non-negative number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::vector<MODULEENTRY32> moduleEntries = module::getModules(processId, &errorMessage);

  // If an error message was returned from the function getting the modules, throw the error.
  // Only throw an error if there is no callback (if there's a callback, the error is passed there).
  if (strcmp(errorMessage, "") && args.Length() != 2) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Creates v8 array with the size being that of the moduleEntries vector
  // modules is an array of JavaScript objects
  Napi::Array modules = Napi::Array::New(env, moduleEntries.size());

  // Loop over all modules found
  for (std::vector<MODULEENTRY32>::size_type i = 0; i != moduleEntries.size(); i++) {
    //  Create a v8 object to store the current module's information
    Napi::Object module = Napi::Object::New(env);

    module.Set(Napi::String::New(env, "modBaseAddr"), Napi::Value::From(env, (uintptr_t)moduleEntries[i].modBaseAddr));
    module.Set(Napi::String::New(env, "modBaseSize"), Napi::Value::From(env, (int)moduleEntries[i].modBaseSize));
    module.Set(Napi::String::New(env, "szExePath"), Napi::String::New(env, moduleEntries[i].szExePath));
    module.Set(Napi::String::New(env, "szModule"), Napi::String::New(env, moduleEntries[i].szModule));
    module.Set(Napi::String::New(env, "th32ProcessID"), Napi::Value::From(env, (int)moduleEntries[i].th32ProcessID));
    module.Set(Napi::String::New(env, "GlblcntUsage"), Napi::Value::From(env, (int)moduleEntries[i].GlblcntUsage));

    // Push the object to the array
    modules.Set(i, module);
  }

  // getModules can either take one argument or two arguments
  // one/two arguments is for asychronous use (the callback)
  if (args.Length() == 2) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[1].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), modules });
    return env.Null();
  } else {
    // return JSON
    return modules;
  }
}

Napi::Value findModule(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  // findModule requires moduleName (string) and processId (number).
  // It can optionally take a callback as the third argument.
  if (args.Length() < 2 || args.Length() > 3) {
    Napi::Error::New(env, "Requires 2 arguments (moduleName, processId), or 3 arguments if a callback is being used.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsString()) {
    Napi::Error::New(env, "First argument (moduleName) must be a string.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[1].IsNumber()) {
    Napi::Error::New(env, "Second argument (processId) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 3 && !args[2].IsFunction()) {
    Napi::Error::New(env, "Third argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string moduleNameStr = args[0].As<Napi::String>().Utf8Value();
  if (moduleNameStr.empty()) {
    Napi::Error::New(env, "Module name cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }

  int32_t processId = args[1].As<Napi::Number>().Int32Value();
  if (processId < 0) {
    Napi::Error::New(env, "Process ID must be a non-negative number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Define error message that may be set by the function that gets the modules
  const char* errorMessage = "";

  MODULEENTRY32 module = module::findModule(moduleNameStr.c_str(), processId, &errorMessage);

  // If an error message was returned from the function getting the module, throw the error.
  // Only throw an error if there is no callback (if there's a callback, the error is passed there).
  if (strcmp(errorMessage, "") && args.Length() != 3) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  // In case it failed to open, let's keep retrying
  while (!strcmp(module.szExePath, "")) {
    module = module::findModule(moduleName.c_str(), args[1].As<Napi::Number>().Int32Value(), &errorMessage);
  };

  // Create a v8 Object (JSON) to store the process information
  Napi::Object moduleInfo = Napi::Object::New(env);

  moduleInfo.Set(Napi::String::New(env, "modBaseAddr"), Napi::Value::From(env, (uintptr_t)module.modBaseAddr));
  moduleInfo.Set(Napi::String::New(env, "modBaseSize"), Napi::Value::From(env, (int)module.modBaseSize));
  moduleInfo.Set(Napi::String::New(env, "szExePath"), Napi::String::New(env, module.szExePath));
  moduleInfo.Set(Napi::String::New(env, "szModule"), Napi::String::New(env, module.szModule));
  moduleInfo.Set(Napi::String::New(env, "th32ProcessID"), Napi::Value::From(env, (int)module.th32ProcessID));
  moduleInfo.Set(Napi::String::New(env, "GlblcntUsage"), Napi::Value::From(env, (int)module.GlblcntUsage));

  // findModule can either take one or two arguments,
  // three arguments for asychronous use (third argument is the callback)
  if (args.Length() == 3) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[2].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), moduleInfo });
    return env.Null();
  } else {
    // return JSON
    return moduleInfo;
  }
}

Napi::Value readMemory(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 3 && args.Length() != 4) {
    Napi::Error::New(env, "requires 3 arguments, or 4 arguments if a callback is being used").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  // Address can be Number or BigInt
  if (!args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsString()) {
    Napi::Error::New(env, "Third argument (dataType) must be a string.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 4 && !args[3].IsFunction()) {
    Napi::Error::New(env, "Fourth argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) { // INVALID_HANDLE_VALUE is often -1, but NULL is a common invalid value.
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  bool lossless; // Required for BigInt operations
  if (args[1].IsBigInt()) {
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    // Using Int64Value and then casting to DWORD64. Could also use DoubleValue.
    // Important: Ensure negative numbers are handled if addresses are strictly non-negative.
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) {
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }
  // Depending on system, address 0 might be invalid for reads.
  // if (address == 0) {
  //   Napi::Error::New(env, "Address cannot be zero.").ThrowAsJavaScriptException();
  //   return env.Null();
  // }


  std::string dataTypeStr = args[2].As<Napi::String>().Utf8Value();
  if (dataTypeStr.empty()) {
    Napi::Error::New(env, "Data type string cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }
  const char* dataType = dataTypeStr.c_str();

  // Define the error message that will be set if no data type is recognised
  const char* errorMessage = "";
  Napi::Value retVal = env.Null();


  if (!strcmp(dataType, "int8") || !strcmp(dataType, "byte") || !strcmp(dataType, "char")) {

    int8_t result = Memory.readMemory<int8_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "uint8") || !strcmp(dataType, "ubyte") || !strcmp(dataType, "uchar")) {

    uint8_t result = Memory.readMemory<uint8_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "int16") || !strcmp(dataType, "short")) {

    int16_t result = Memory.readMemory<int16_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "uint16") || !strcmp(dataType, "ushort") || !strcmp(dataType, "word")) {

    uint16_t result = Memory.readMemory<uint16_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "int32") || !strcmp(dataType, "int") || !strcmp(dataType, "long")) {

    int32_t result = Memory.readMemory<int32_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "uint32") || !strcmp(dataType, "uint") || !strcmp(dataType, "ulong") || !strcmp(dataType, "dword")) {

    uint32_t result = Memory.readMemory<uint32_t>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "int64")) {

    int64_t result = Memory.readMemory<int64_t>(handle, address);
    retVal = Napi::Value::From(env, Napi::BigInt::New(env, result));

  } else if (!strcmp(dataType, "uint64")) {

    uint64_t result = Memory.readMemory<uint64_t>(handle, address);
    retVal = Napi::Value::From(env, Napi::BigInt::New(env, result));

  } else if (!strcmp(dataType, "float")) {

    float result = Memory.readMemory<float>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "double")) {

    double result = Memory.readMemory<double>(handle, address);
    retVal = Napi::Value::From(env, result);

  } else if (!strcmp(dataType, "ptr") || !strcmp(dataType, "pointer")) {

    intptr_t result = Memory.readMemory<intptr_t>(handle, address);

    if (sizeof(intptr_t) == 8) {
      retVal = Napi::Value::From(env, Napi::BigInt::New(env, (int64_t) result));
    } else {
      retVal = Napi::Value::From(env, result);
    }

  } else if (!strcmp(dataType, "uptr") || !strcmp(dataType, "upointer")) {

    uintptr_t result = Memory.readMemory<uintptr_t>(handle, address);

    if (sizeof(uintptr_t) == 8) {
      retVal = Napi::Value::From(env, Napi::BigInt::New(env, (uint64_t) result));
    } else {
      retVal = Napi::Value::From(env, result);
    }

  } else if (!strcmp(dataType, "bool") || !strcmp(dataType, "boolean")) {

    bool result = Memory.readMemory<bool>(handle, address);
    retVal = Napi::Boolean::New(env, result);

  } else if (!strcmp(dataType, "string") || !strcmp(dataType, "str")) {

    std::string str;
    if (!Memory.readString(handle, address, &str)) {
      errorMessage = "unable to read string";
    } else {
      retVal = Napi::String::New(env, str);
    }

  } else if (!strcmp(dataType, "vector3") || !strcmp(dataType, "vec3")) {

    Vector3 result = Memory.readMemory<Vector3>(handle, address);
    Napi::Object moduleInfo = Napi::Object::New(env);
    moduleInfo.Set(Napi::String::New(env, "x"), Napi::Value::From(env, result.x));
    moduleInfo.Set(Napi::String::New(env, "y"), Napi::Value::From(env, result.y));
    moduleInfo.Set(Napi::String::New(env, "z"), Napi::Value::From(env, result.z));
    retVal = moduleInfo;

  } else if (!strcmp(dataType, "vector4") || !strcmp(dataType, "vec4")) {

    Vector4 result = Memory.readMemory<Vector4>(handle, address);
    Napi::Object moduleInfo = Napi::Object::New(env);
    moduleInfo.Set(Napi::String::New(env, "w"), Napi::Value::From(env, result.w));
    moduleInfo.Set(Napi::String::New(env, "x"), Napi::Value::From(env, result.x));
    moduleInfo.Set(Napi::String::New(env, "y"), Napi::Value::From(env, result.y));
    moduleInfo.Set(Napi::String::New(env, "z"), Napi::Value::From(env, result.z));
    retVal = moduleInfo;

  } else {
    errorMessage = "unexpected data type";
  }

  if (strcmp(errorMessage, "") && args.Length() != 4) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 4) {
    Napi::Function callback = args[3].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), retVal });
    return env.Null();
  } else {
    return retVal;
  }
}

Napi::Value readBuffer(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 3 && args.Length() != 4) {
    Napi::Error::New(env, "requires 3 arguments, or 4 arguments if a callback is being used").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsNumber()) {
    Napi::Error::New(env, "Third argument (size) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 4 && !args[3].IsFunction()) {
    Napi::Error::New(env, "Fourth argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  bool lossless;
  if (args[1].IsBigInt()) {
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) {
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }

  SIZE_T size = args[2].As<Napi::Number>().Int64Value(); // Or Uint32Value/Int32Value if size is within that range
  if (size <= 0) {
    Napi::Error::New(env, "Size must be a positive number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // To fix the memory leak problem that was happening here, we need to release the
  // temporary buffer we create after we're done creating a Napi::Buffer from it.
  // Napi::Buffer::New doesn't free the memory, so it has be done manually
  // but it can segfault when the memory is freed before being accessed.
  // The solution is to use Napi::Buffer::Copy, and then we can manually free it.
  //
  // see: https://github.com/nodejs/node/issues/40936
  // see: https://sagivo.com/2015/09/30/Go-Native-Calling-C-From-NodeJS.html
  char* data = (char*) malloc(sizeof(char) * size);
  Memory.readBuffer(handle, address, size, data);

  Napi::Buffer<char> buffer = Napi::Buffer<char>::Copy(env, data, size);
  free(data);
  
  if (args.Length() == 4) {
    Napi::Function callback = args[3].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, ""), buffer });
    return env.Null();
  } else {
    return buffer;
  }
}

Napi::Value writeMemory(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 4) {
    Napi::Error::New(env, "requires 4 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  // args[2] (value) type check is dependent on dataType, done after dataType is validated.
  if (!args[3].IsString()) {
    Napi::Error::New(env, "Fourth argument (dataType) must be a string.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  bool lossless;
  if (args[1].IsBigInt()) {
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
     if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) {
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }

  std::string dataTypeStr = args[3].As<Napi::String>().Utf8Value();
  if (dataTypeStr.empty()) {
    Napi::Error::New(env, "Data type string cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }
  const char* dataType = dataTypeStr.c_str();

  // Validate args[2] (value) based on dataType
  if (!strcmp(dataType, "int64") || !strcmp(dataType, "uint64")) {
    if (!args[2].IsBigInt() && !args[2].IsNumber()) { // Allow number for non-precise BigInts for convenience
      Napi::Error::New(env, "Value for int64/uint64 must be a BigInt or a number.").ThrowAsJavaScriptException();
      return env.Null();
    }
  } else if (!strcmp(dataType, "ptr") || !strcmp(dataType, "pointer") || !strcmp(dataType, "uptr") || !strcmp(dataType, "upointer")) {
    if (sizeof(void*) == 8 && !args[2].IsBigInt() && !args[2].IsNumber()) { // 64-bit pointers
       Napi::Error::New(env, "Value for 64-bit pointer types must be a BigInt or a number.").ThrowAsJavaScriptException();
       return env.Null();
    } else if (sizeof(void*) == 4 && !args[2].IsNumber()) { // 32-bit pointers
       Napi::Error::New(env, "Value for 32-bit pointer types must be a number.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else if (!strcmp(dataType, "string") || !strcmp(dataType, "str")) {
    if (!args[2].IsString()) {
      Napi::Error::New(env, "Value for string/str must be a string.").ThrowAsJavaScriptException();
      return env.Null();
    }
  } else if (!strcmp(dataType, "bool") || !strcmp(dataType, "boolean")) {
    if (!args[2].IsBoolean()) {
      Napi::Error::New(env, "Value for bool/boolean must be a boolean.").ThrowAsJavaScriptException();
      return env.Null();
    }
  } else if (!strcmp(dataType, "vector3") || !strcmp(dataType, "vec3") || !strcmp(dataType, "vector4") || !strcmp(dataType, "vec4")) {
    if (!args[2].IsObject()) {
      Napi::Error::New(env, "Value for vector types must be an object.").ThrowAsJavaScriptException();
      return env.Null();
    }
  } else { // Default assumption for other types (int8, float, double, etc.)
    if (!args[2].IsNumber()) {
      std::string errorMsg = "Value for data type '";
      errorMsg += dataType;
      errorMsg += "' must be a number.";
      Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
      return env.Null();
    }
  }


  if (!strcmp(dataType, "int8") || !strcmp(dataType, "byte") || !strcmp(dataType, "char")) {

    Memory.writeMemory<int8_t>(handle, address, args[2].As<Napi::Number>().Int32Value());

  } else if (!strcmp(dataType, "uint8") || !strcmp(dataType, "ubyte") || !strcmp(dataType, "uchar")) {

    Memory.writeMemory<uint8_t>(handle, address, args[2].As<Napi::Number>().Uint32Value());

  } else if (!strcmp(dataType, "int16") || !strcmp(dataType, "short")) {

    Memory.writeMemory<int16_t>(handle, address, args[2].As<Napi::Number>().Int32Value());

  } else if (!strcmp(dataType, "uint16") || !strcmp(dataType, "ushort") || !strcmp(dataType, "word")) {

    Memory.writeMemory<uint16_t>(handle, address, args[2].As<Napi::Number>().Uint32Value());

  } else if (!strcmp(dataType, "int32") || !strcmp(dataType, "int") || !strcmp(dataType, "long")) {

    Memory.writeMemory<int32_t>(handle, address, args[2].As<Napi::Number>().Int32Value());

  } else if (!strcmp(dataType, "uint32") || !strcmp(dataType, "uint") || !strcmp(dataType, "ulong") || !strcmp(dataType, "dword")) {

    Memory.writeMemory<uint32_t>(handle, address, args[2].As<Napi::Number>().Uint32Value());

  } else if (!strcmp(dataType, "int64")) {

    if (args[2].As<Napi::BigInt>().IsBigInt()) {
      bool lossless;
      Memory.writeMemory<int64_t>(handle, address, args[2].As<Napi::BigInt>().Int64Value(&lossless));
    } else {
      Memory.writeMemory<int64_t>(handle, address, args[2].As<Napi::Number>().Int64Value());
    }

  } else if (!strcmp(dataType, "uint64")) {

    if (args[2].As<Napi::BigInt>().IsBigInt()) {
      bool lossless;
      Memory.writeMemory<int64_t>(handle, address,  args[2].As<Napi::BigInt>().Uint64Value(&lossless));
    } else {
      Memory.writeMemory<int64_t>(handle, address, args[2].As<Napi::Number>().Int64Value());
    }

  } else if (!strcmp(dataType, "float")) {

    Memory.writeMemory<float>(handle, address, args[2].As<Napi::Number>().FloatValue());

  } else if (!strcmp(dataType, "double")) {

    Memory.writeMemory<double>(handle, address, args[2].As<Napi::Number>().DoubleValue());

  } else if (!strcmp(dataType, "ptr") || !strcmp(dataType, "pointer")) {

    Napi::BigInt valueBigInt = args[2].As<Napi::BigInt>();

    if (sizeof(intptr_t) == 8 && !valueBigInt.IsBigInt()) {
      std::string error = "Writing 'ptr' or 'pointer' on 64 bit target build requires you to supply a BigInt.";
      Napi::Error::New(env, error).ThrowAsJavaScriptException();
      return env.Null();
    }

    if (valueBigInt.IsBigInt()) {
      bool lossless;
      Memory.writeMemory<intptr_t>(handle, address, valueBigInt.Int64Value(&lossless));
    } else {
      Memory.writeMemory<intptr_t>(handle, address, args[2].As<Napi::Number>().Int32Value());
    }

  } else if (!strcmp(dataType, "uptr") || !strcmp(dataType, "upointer")) {

    Napi::BigInt valueBigInt = args[2].As<Napi::BigInt>();

    if (sizeof(uintptr_t) == 8 && !valueBigInt.IsBigInt()) {
      std::string error = "Writing 'ptr' or 'pointer' on 64 bit target build requires you to supply a BigInt.";
      Napi::Error::New(env, error).ThrowAsJavaScriptException();
      return env.Null();
    }

    if (valueBigInt.IsBigInt()) {
      bool lossless;
      Memory.writeMemory<uintptr_t>(handle, address, valueBigInt.Uint64Value(&lossless));
    } else {
      Memory.writeMemory<uintptr_t>(handle, address, args[2].As<Napi::Number>().Uint32Value());
    }

  } else if (!strcmp(dataType, "bool") || !strcmp(dataType, "boolean")) {

    Memory.writeMemory<bool>(handle, address, args[2].As<Napi::Boolean>().Value());

  } else if (!strcmp(dataType, "string") || !strcmp(dataType, "str")) {

    std::string valueParam(args[2].As<Napi::String>().Utf8Value());
    valueParam.append("", 1);

    // Write String, Method 1
    //Memory.writeMemory<std::string>(handle, address, std::string(*valueParam));

    // Write String, Method 2
    Memory.writeMemory(handle, address, (char*) valueParam.data(), valueParam.size());

  } else if (!strcmp(dataType, "vector3") || !strcmp(dataType, "vec3")) {

    Napi::Object value = args[2].As<Napi::Object>();
    Vector3 vector = {
      value.Get(Napi::String::New(env, "x")).As<Napi::Number>().FloatValue(),
      value.Get(Napi::String::New(env, "y")).As<Napi::Number>().FloatValue(),
      value.Get(Napi::String::New(env, "z")).As<Napi::Number>().FloatValue()
    };
    Memory.writeMemory<Vector3>(handle, address, vector);

  } else if (!strcmp(dataType, "vector4") || !strcmp(dataType, "vec4")) {

    Napi::Object value = args[2].As<Napi::Object>();
    Vector4 vector = {
      value.Get(Napi::String::New(env, "w")).As<Napi::Number>().FloatValue(),
      value.Get(Napi::String::New(env, "x")).As<Napi::Number>().FloatValue(),
      value.Get(Napi::String::New(env, "y")).As<Napi::Number>().FloatValue(),
      value.Get(Napi::String::New(env, "z")).As<Napi::Number>().FloatValue()
    };
    Memory.writeMemory<Vector4>(handle, address, vector);

  } else {
    Napi::Error::New(env, "unexpected data type").ThrowAsJavaScriptException();
  }

  return env.Null();
}

Napi::Value writeBuffer(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 3) {
    Napi::Error::New(env, "required 3 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsBuffer()) {
    Napi::Error::New(env, "Third argument (buffer) must be a Buffer.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  bool lossless;
  if (args[1].IsBigInt()) {
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) {
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }

  Napi::Buffer<char> buffer = args[2].As<Napi::Buffer<char>>();
  SIZE_T length = buffer.Length();
  char* data = buffer.Data();

  if (length == 0) {
    // Depending on desired behavior, writing a 0-length buffer might be a no-op or an error.
    // For now, let's consider it a no-op and return successfully.
    // If it should be an error:
    // Napi::Error::New(env, "Buffer to write cannot be empty.").ThrowAsJavaScriptException();
    // return env.Null();
    return env.Null(); // Assuming no-op is acceptable.
  }
  
  // The Memory.writeMemory method for char* likely handles the actual WriteProcessMemory call.
  // That internal method should check the success of WriteProcessMemory.
  Memory.writeMemory<char*>(handle, address, data, length);

  return env.Null();
}

// Napi::Value findPattern(const Napi::CallbackInfo& args) {
//   Napi::Env env = args.Env();

//   HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
//   DWORD64 baseAddress = args[1].As<Napi::Number>().Int64Value();
//   DWORD64 baseSize = args[2].As<Napi::Number>().Int64Value();
//   std::string signature(args[3].As<Napi::String>().Utf8Value());
//   short flags = args[4].As<Napi::Number>().Uint32Value();
//   uint32_t patternOffset = args[5].As<Napi::Number>().Uint32Value();

//   // matching address
//   uintptr_t address = 0;
//   const char* errorMessage = "";

//   // read memory region occupied by the module to pattern match inside
//   std::vector<unsigned char> moduleBytes = std::vector<unsigned char>(baseSize);
//   ReadProcessMemory(handle, (LPVOID)baseAddress, &moduleBytes[0], baseSize, nullptr);
//   unsigned char* byteBase = const_cast<unsigned char*>(&moduleBytes.at(0));

//   Pattern.findPattern(handle, baseAddress, byteBase, baseSize, signature.c_str(), flags, patternOffset, &address);

//   if (address == 0) {
//     errorMessage = "unable to match pattern inside any modules or regions";
//   }

//   if (args.Length() == 5) {
//     Napi::Function callback = args[4].As<Napi::Function>();
//     callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
//     return env.Null();
//   } else {
//     return Napi::Value::From(env, address);
//   }
// }

Napi::Value findPattern(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 4 && args.Length() != 5) {
    Napi::Error::New(env, "requires 4 arguments, 5 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsString() || !args[2].IsNumber() || !args[3].IsNumber()) {
    Napi::Error::New(env, "expected: number, string, string, number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 5 && !args[4].IsFunction()) {
    Napi::Error::New(env, "callback argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string patternStr = args[1].As<Napi::String>().Utf8Value();
  if (patternStr.empty()) {
    Napi::Error::New(env, "Pattern string cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // flags (args[2]) and patternOffset (args[3]) are numbers, already type-checked.
  // Further range validation could be added if necessary (e.g. patternOffset >= 0).
  short flags = args[2].As<Napi::Number>().Int16Value(); // Using Int16Value for short
  uint32_t patternOffset = args[3].As<Napi::Number>().Uint32Value();

  // matching address
  uintptr_t address = 0;
  const char* errorMessage = "";

  std::vector<MODULEENTRY32> modules = module::getModules(GetProcessId(handle), &errorMessage);
  // Pass patternStr.c_str() instead of pattern.c_str() if variable name changed
  Pattern.search(handle, modules, 0, patternStr.c_str(), flags, patternOffset, &address);

  // if no match found inside any modules, search memory regions
  if (address == 0) {
    std::vector<MEMORY_BASIC_INFORMATION> regions = Memory.getRegions(handle);
    Pattern.search(handle, regions, 0, patternStr.c_str(), flags, patternOffset, &address);
  }

  if (address == 0) {
    errorMessage = "unable to match pattern inside any modules or regions";
  }

  if (args.Length() == 5) {
    Napi::Function callback = args[4].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
    return env.Null();
  } else {
    return Napi::Value::From(env, address);
  }
}

Napi::Value findPatternByModule(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 5 && args.Length() != 6) {
    Napi::Error::New(env, "requires 5 arguments, 6 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsString() || !args[2].IsString() || !args[3].IsNumber() || !args[4].IsNumber()) {
    Napi::Error::New(env, "expected: number, string, string, number, number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 6 && !args[5].IsFunction()) {
    Napi::Error::New(env, "callback argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string moduleNameStr = args[1].As<Napi::String>().Utf8Value();
  if (moduleNameStr.empty()) {
    Napi::Error::New(env, "Module name cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string patternStr = args[2].As<Napi::String>().Utf8Value();
  if (patternStr.empty()) {
    Napi::Error::New(env, "Pattern string cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  short flags = args[3].As<Napi::Number>().Int16Value(); // Using Int16Value for short
  uint32_t patternOffset = args[4].As<Napi::Number>().Uint32Value();

  // matching address
  uintptr_t address = 0;
  const char* errorMessage = "";

  MODULEENTRY32 moduleEntry = module::findModule(moduleNameStr.c_str(), GetProcessId(handle), &errorMessage);
  // Check if findModule itself failed and set an error message
  if (strcmp(errorMessage, "") != 0 || moduleEntry.dwSize == 0) { // dwSize check for valid module
      if (args.Length() == 6) { // If callback provided
          Napi::Function callback = args[5].As<Napi::Function>();
          callback.Call(env.Global(), { Napi::String::New(env, "Failed to find module or module invalid."), Napi::Value::From(env, address) });
          return env.Null();
      } else {
          Napi::Error::New(env, "Failed to find module or module invalid.").ThrowAsJavaScriptException();
          return env.Null();
      }
  }


  uintptr_t baseAddress = (uintptr_t) moduleEntry.modBaseAddr;
  DWORD baseSize = moduleEntry.modBaseSize;

  if (baseSize == 0) {
      // Avoid reading memory if module size is 0
      errorMessage = "Module size is zero, cannot scan for pattern.";
      if (args.Length() == 6) {
          Napi::Function callback = args[5].As<Napi::Function>();
          callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
          return env.Null();
      } else {
          Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
          return env.Null();
      }
  }

  // read memory region occupied by the module to pattern match inside
  std::vector<unsigned char> moduleBytes = std::vector<unsigned char>(baseSize);
  // Check ReadProcessMemory success
  if (!ReadProcessMemory(handle, (LPCVOID)baseAddress, &moduleBytes[0], baseSize, nullptr)) {
      errorMessage = "ReadProcessMemory failed for module.";
      if (args.Length() == 6) {
          Napi::Function callback = args[5].As<Napi::Function>();
          callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) }); // address is 0
          return env.Null();
      } else {
          Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
          return env.Null();
      }
  }
  unsigned char* byteBase = &moduleBytes[0]; // More direct way

  Pattern.findPattern(handle, baseAddress, byteBase, baseSize, patternStr.c_str(), flags, patternOffset, &address);

  if (address == 0) {
    errorMessage = "unable to match pattern inside any modules or regions";
  }

  if (args.Length() == 6) {
    Napi::Function callback = args[5].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
    return env.Null();
  } else {
    return Napi::Value::From(env, address);
  }
}

Napi::Value findPatternByAddress(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 5 && args.Length() != 6) {
    Napi::Error::New(env, "requires 5 arguments, 6 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsNumber() || !args[2].IsString() || !args[3].IsNumber() || !args[4].IsNumber()) {
    Napi::Error::New(env, "expected: number, number, string, number, number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 6 && !args[5].IsFunction()) {
    Napi::Error::New(env, "callback argument must be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 baseAddress;
  bool lossless;
  if (args[1].IsBigInt()) {
    baseAddress = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Base address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) { // Addresses typically non-negative
        Napi::Error::New(env, "Base address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    baseAddress = static_cast<DWORD64>(addrDouble);
  }
  // Optional: Check if baseAddress is 0 if that's invalid for this context

  std::string patternStr = args[2].As<Napi::String>().Utf8Value();
  if (patternStr.empty()) {
    Napi::Error::New(env, "Pattern string cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }

  short flags = args[3].As<Napi::Number>().Int16Value(); // Using Int16Value for short
  uint32_t patternOffset = args[4].As<Napi::Number>().Uint32Value();

  // matching address
  uintptr_t address = 0;
  const char* errorMessage = ""; // This might be set by getModules

  std::vector<MODULEENTRY32> modules = module::getModules(GetProcessId(handle), &errorMessage);
  if (strcmp(errorMessage, "") != 0) {
      // If getModules failed, handle error before proceeding
      if (args.Length() == 6) {
          Napi::Function callback = args[5].As<Napi::Function>();
          callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
          return env.Null();
      } else {
          Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
          return env.Null();
      }
  }
  Pattern.search(handle, modules, baseAddress, patternStr.c_str(), flags, patternOffset, &address);

  if (address == 0) {
    std::vector<MEMORY_BASIC_INFORMATION> regions = Memory.getRegions(handle);
    // Assuming Memory.getRegions doesn't set errorMessage in the same way, or has its own error handling
    Pattern.search(handle, regions, baseAddress, patternStr.c_str(), flags, patternOffset, &address);
  }

  if (address == 0) {
    errorMessage = "unable to match pattern inside any modules or regions";
  }

  if (args.Length() == 6) {
    Napi::Function callback = args[5].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Value::From(env, address) });
    return env.Null();
  } else {
    return Napi::Value::From(env, address);
  }
}

Napi::Value callFunction(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 4 && args.Length() != 5) {
    Napi::Error::New(env, "requires 4 arguments, 5 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[1].IsArray()) { // Corrected from IsObject
    Napi::Error::New(env, "Second argument (args) must be an array.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsNumber()) {
    Napi::Error::New(env, "Third argument (returnType) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[3].IsNumber() && !args[3].IsBigInt()) { // Address can be number or BigInt
    Napi::Error::New(env, "Fourth argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (args.Length() == 5 && !args[4].IsFunction()) {
    Napi::Error::New(env, "Fifth argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  functions::Type returnType = (functions::Type) args[2].As<Napi::Number>().Uint32Value();
  // TODO: Add check for valid functions::Type enum range if possible.
  // For example: if (returnType < functions::Type::T_VOID || returnType > functions::Type::T_DOUBLE) { ... }

  DWORD64 address;
  bool lossless;
  if (args[3].IsBigInt()) {
    address = args[3].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Function address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[3].As<Napi::Number>().DoubleValue();
    // Function addresses are usually not 0 or negative.
    if (addrDouble <= 0) {
        Napi::Error::New(env, "Function address must be a positive number.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }
  if (address == 0) { // Double check after cast
      Napi::Error::New(env, "Function address cannot be zero.").ThrowAsJavaScriptException();
      return env.Null();
  }


  // TODO: temp (?) solution to forcing variables onto the heap
  // to ensure consistent addresses. copy everything to a vector, and use the
  // vector's instances of the variables as the addresses being passed to `functions.call()`.
  // Another solution: do `int x = new int(4)` and then use `&x` for the address
  std::vector<LPVOID> heap; // Used for allocating memory for non-string args

  std::vector<functions::Arg> parsedArgs;
  Napi::Array arguments = args[1].As<Napi::Array>();
  for (unsigned int i = 0; i < arguments.Length(); i++) {
    if (!arguments.Get(i).IsObject()) {
        Napi::Error::New(env, "Each item in 'args' array must be an object.").ThrowAsJavaScriptException();
        // Cleanup 'heap' before returning
        for (auto &mem : heap) free(mem);
        return env.Null();
    }
    Napi::Object argument = arguments.Get(i).As<Napi::Object>();

    if (!argument.Has("type") || !argument.Get("type").IsNumber() || !argument.Has("value")) {
        Napi::Error::New(env, "Each argument object must have 'type' (number) and 'value' properties.").ThrowAsJavaScriptException();
        for (auto &mem : heap) free(mem);
        return env.Null();
    }

    functions::Type type = (functions::Type) argument.Get(Napi::String::New(env, "type")).As<Napi::Number>().Uint32Value();
    // TODO: Validate 'type' against known functions::Type values

    Napi::Value val = argument.Get("value");

    if (type == functions::Type::T_STRING) {
      if (!val.IsString()){
          Napi::Error::New(env, "Value for T_STRING argument must be a string.").ThrowAsJavaScriptException();
          for (auto &mem : heap) free(mem);
          return env.Null();
      }
      // For strings, functions::call expects char*. The std::string needs to live long enough.
      // This is problematic if stringValue goes out of scope.
      // A robust solution might involve allocating on heap or ensuring lifetime.
      // For now, this relies on short lifetime or specific behavior of functions::call.
      // Consider making a copy onto the heap as well if issues arise.
      std::string stringValue = val.As<Napi::String>().Utf8Value();
      // functions::call will need to handle this string's lifetime or copy it.
      // To be safe, one might allocate:
      // char* strCopy = strdup(stringValue.c_str()); heap.push_back(strCopy); parsedArgs.push_back({type, strCopy});
      // However, current `functions::call` seems to take `void*` and might cast.
      // The original code `parsedArgs.push_back({ type, &stringValue });` is unsafe as stringValue is local.
      // Let's assume functions::call makes a copy or uses it immediately.
      // For this PR, I will stick to minimal changes to existing logic beyond validation.
      // The original code is problematic here. A better way:
      char* strData = (char*) malloc(stringValue.length() + 1);
      strcpy(strData, stringValue.c_str());
      heap.push_back(strData);
      parsedArgs.push_back({ type, strData });
    } else if (type == functions::Type::T_INT) {
      if (!val.IsNumber()){
          Napi::Error::New(env, "Value for T_INT argument must be a number.").ThrowAsJavaScriptException();
          for (auto &mem : heap) free(mem);
          return env.Null();
      }
      int data = val.As<Napi::Number>().Int32Value();
      int* memory = (int*) malloc(sizeof(int));
      if (!memory) { /* handle allocation error */ }
      *memory = data;
      heap.push_back(memory);
      parsedArgs.push_back({ type, memory });
    } else if (type == functions::Type::T_FLOAT) {
      if (!val.IsNumber()){
          Napi::Error::New(env, "Value for T_FLOAT argument must be a number.").ThrowAsJavaScriptException();
          for (auto &mem : heap) free(mem);
          return env.Null();
      }
      float data = val.As<Napi::Number>().FloatValue();
      float* memory = (float*) malloc(sizeof(float));
      if (!memory) { /* handle allocation error */ }
      *memory = data;
      heap.push_back(memory);
      parsedArgs.push_back({ type, memory });
    }
    // TODO: Add cases for other types in functions::Type if they are supported
    // (e.g., T_DOUBLE, T_BOOL, T_CHAR, T_LONG etc.) with similar validation and heap allocation.
  }


  const char* errorMessage = "";
  Call data = functions::call<int>(handle, parsedArgs, returnType, address, &errorMessage);

  // Free all the memory we allocated
  for (auto &memory : heap) {
    free(memory);
  }

  heap.clear();

  if (strcmp(errorMessage, "") && args.Length() != 5) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object info = Napi::Object::New(env);

  Napi::String keyString = Napi::String::New(env, "returnValue");

  if (returnType == functions::Type::T_STRING) {
    info.Set(keyString, Napi::String::New(env, data.returnString.c_str()));
  }

  if (returnType == functions::Type::T_CHAR) {
    info.Set(keyString, Napi::Value::From(env, (char) data.returnValue));
  }

  if (returnType == functions::Type::T_BOOL) {
    info.Set(keyString, Napi::Value::From(env, (bool) data.returnValue));
  }

  if (returnType == functions::Type::T_INT) {
    info.Set(keyString, Napi::Value::From(env, (int) data.returnValue));
  }

  if (returnType == functions::Type::T_FLOAT) {
    float value = *(float *)&data.returnValue;
    info.Set(keyString, Napi::Value::From(env, value));
  }

  if (returnType == functions::Type::T_DOUBLE) {
    double value = *(double *)&data.returnValue;
    info.Set(keyString, Napi::Value::From(env, value));
  }

  info.Set(Napi::String::New(env, "exitCode"), Napi::Value::From(env, data.exitCode));

  if (args.Length() == 5) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[2].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), info });
    return env.Null();
  } else {
    // return JSON
    return info;
  }

}

Napi::Value virtualProtectEx(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 4 && args.Length() != 5) {
    Napi::Error::New(env, "requires 4 arguments, 5 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[1].IsNumber() && !args[1].IsBigInt()) { // Address can be number or BigInt
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsNumber()) {
    Napi::Error::New(env, "Third argument (size) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[3].IsNumber()) {
    Napi::Error::New(env, "Fourth argument (protection) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 5 && !args[4].IsFunction()) {
    Napi::Error::New(env, "Fifth argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  bool lossless;
  if (args[1].IsBigInt()) {
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) { // Address should be non-negative for VirtualProtectEx
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }

  SIZE_T size = args[2].As<Napi::Number>().Int64Value(); // Or Uint64Value if size can exceed 32-bit max on 32-bit
  if (size <= 0) {
    Napi::Error::New(env, "Size must be a positive number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD protection = args[3].As<Napi::Number>().Uint32Value();
  // TODO: Add validation for protection flags if a known set of valid flags exists.
  // For example, check if protection is one of the PAGE_ constants.

  DWORD result; // Stores the old protection
  bool success = VirtualProtectEx(handle, (LPVOID) address, size, protection, &result);

  const char* errorMessage = "";

  if (success == 0) {
    errorMessage = "an error occurred calling VirtualProtectEx";
    // errorMessage = GetLastErrorToString().c_str();
  }

  // If there is an error and there is no callback, throw the error
  if (strcmp(errorMessage, "") && args.Length() != 5) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 5) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[5].As<Napi::Function>();
    callback.Call(env.Global(), {
      Napi::String::New(env, errorMessage),
      Napi::Value::From(env, result)
    });
    return env.Null();
  } else {
    return Napi::Value::From(env, result);
  }
}

Napi::Value getRegions(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1 && args.Length() != 2) {
    Napi::Error::New(env, "requires 1 argument, 2 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "invalid arguments: first argument must be a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 2 && !args[1].IsFunction()) {
    Napi::Error::New(env, "callback needs to be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::vector<MEMORY_BASIC_INFORMATION> regions = Memory.getRegions(handle);
  // The Memory.getRegions C++ function itself has been updated to check for NULL/INVALID_HANDLE_VALUE
  // and return an empty vector, so an additional error throw here for that specific case might be redundant
  // if an empty array is an acceptable "not found" or "error" indicator to the JS side for this function.
  // However, being explicit about an invalid handle from JS is good practice.

  Napi::Array regionsArray = Napi::Array::New(env, regions.size());

  for (std::vector<MEMORY_BASIC_INFORMATION>::size_type i = 0; i != regions.size(); i++) {
    Napi::Object region = Napi::Object::New(env);

    region.Set(Napi::String::New(env, "BaseAddress"), Napi::Value::From(env, (DWORD64) regions[i].BaseAddress));
    region.Set(Napi::String::New(env, "AllocationBase"), Napi::Value::From(env, (DWORD64) regions[i].AllocationBase));
    region.Set(Napi::String::New(env, "AllocationProtect"), Napi::Value::From(env, (DWORD) regions[i].AllocationProtect));
    region.Set(Napi::String::New(env, "RegionSize"), Napi::Value::From(env, (SIZE_T) regions[i].RegionSize));
    region.Set(Napi::String::New(env, "State"), Napi::Value::From(env, (DWORD) regions[i].State));
    region.Set(Napi::String::New(env, "Protect"), Napi::Value::From(env, (DWORD) regions[i].Protect));
    region.Set(Napi::String::New(env, "Type"), Napi::Value::From(env, (DWORD) regions[i].Type));

    char moduleName[MAX_PATH];
    DWORD size = GetModuleFileNameExA(handle, (HINSTANCE)regions[i].AllocationBase, moduleName, MAX_PATH);

    if (size != 0) {
      region.Set(Napi::String::New(env, "szExeFile"), Napi::String::New(env, moduleName));
    }

    regionsArray.Set(i, region);
  }

  if (args.Length() == 2) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[1].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, ""), regionsArray });
    return env.Null();
  } else {
    // return JSON
    return regionsArray;
  }
}

Napi::Value virtualQueryEx(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2 && args.Length() != 3) {
    Napi::Error::New(env, "requires 2 arguments, 3 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsNumber()) {
    Napi::Error::New(env, "first and second argument need to be a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 3 && !args[2].IsFunction()) {
    Napi::Error::New(env, "callback needs to be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD64 address;
  // Assuming address can be passed as BigInt from JS for full 64-bit range
  if (args[1].IsBigInt()) {
    bool lossless;
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) {
       Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else if (args[1].IsNumber()) {
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    // VirtualQueryEx can take any address, so negative might not be strictly invalid for the API itself,
    // but typically memory addresses are positive. For consistency, let's block negative.
    if (addrDouble < 0) {
        Napi::Error::New(env, "Address cannot be negative.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  } else {
    // This case should have been caught by the IsNumber() check earlier, but as a safeguard:
    Napi::Error::New(env, "Second argument (address) must be a number or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }


  MEMORY_BASIC_INFORMATION information;
  SIZE_T result = VirtualQueryEx(handle, (LPVOID)address, &information, sizeof(information));

  const char* errorMessage = "";

  if (result == 0 || result != sizeof(information)) {
    errorMessage = "an error occurred calling VirtualQueryEx";
    // errorMessage = GetLastErrorToString().c_str();
  }

  // If there is an error and there is no callback, throw the error
  if (strcmp(errorMessage, "") && args.Length() != 3) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Object region = Napi::Object::New(env);

  region.Set(Napi::String::New(env, "BaseAddress"), Napi::Value::From(env, (DWORD64) information.BaseAddress));
  region.Set(Napi::String::New(env, "AllocationBase"), Napi::Value::From(env, (DWORD64) information.AllocationBase));
  region.Set(Napi::String::New(env, "AllocationProtect"), Napi::Value::From(env, (DWORD) information.AllocationProtect));
  region.Set(Napi::String::New(env, "RegionSize"), Napi::Value::From(env, (SIZE_T) information.RegionSize));
  region.Set(Napi::String::New(env, "State"), Napi::Value::From(env, (DWORD) information.State));
  region.Set(Napi::String::New(env, "Protect"), Napi::Value::From(env, (DWORD) information.Protect));
  region.Set(Napi::String::New(env, "Type"), Napi::Value::From(env, (DWORD) information.Type));

  if (args.Length() == 3) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[1].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, ""), region });
    return env.Null();
  } else {
    // return JSON
    return region;
  }
}

Napi::Value virtualAllocEx(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 5 && args.Length() != 6) {
    Napi::Error::New(env, "requires 5 arguments, 6 with callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Argument type validation
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  // args[1] can be null, number, or BigInt
  if (!args[1].IsNull() && !args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Second argument (address) must be null, a number, or BigInt.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[2].IsNumber()) {
    Napi::Error::New(env, "Third argument (size) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[3].IsNumber()) {
    Napi::Error::New(env, "Fourth argument (allocationType) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[4].IsNumber()) {
    Napi::Error::New(env, "Fifth argument (protection) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 6 && !args[5].IsFunction()) {
    Napi::Error::New(env, "Sixth argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Extracted value validation
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  LPVOID address = NULL; // Default to NULL if args[1] is env.Null()
  if (!args[1].IsNull()) {
    bool lossless;
    if (args[1].IsBigInt()) {
        // Using Uint64Value for addresses, assuming they are non-negative.
        // VirtualAllocEx can take specific addresses, which could be large.
        address = (LPVOID)args[1].As<Napi::BigInt>().Uint64Value(&lossless);
        if (!lossless) {
            Napi::Error::New(env, "Address conversion from BigInt resulted in loss of precision.").ThrowAsJavaScriptException();
            return env.Null();
        }
    } else { // IsNumber
        double addrDouble = args[1].As<Napi::Number>().DoubleValue();
        if (addrDouble < 0) { // Specific addresses for VirtualAllocEx are usually positive or NULL.
            Napi::Error::New(env, "If providing an address, it cannot be negative.").ThrowAsJavaScriptException();
            return env.Null();
        }
        address = (LPVOID)static_cast<DWORD64>(addrDouble);
    }
  }


  SIZE_T size = args[2].As<Napi::Number>().Int64Value(); // Or Uint64Value
  if (size <= 0) {
    Napi::Error::New(env, "Size must be a positive number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD allocationType = args[3].As<Napi::Number>().Uint32Value();
  // TODO: Validate allocationType against known flags (MEM_COMMIT, MEM_RESERVE, etc.)
  DWORD protection = args[4].As<Napi::Number>().Uint32Value();
  // TODO: Validate protection against known flags (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.)


  LPVOID allocatedAddress = VirtualAllocEx(handle, address, size, allocationType, protection);

  const char* errorMessage = "";

  // If null, it means an error occurred
  if (allocatedAddress == NULL) {
    errorMessage = "an error occurred calling VirtualAllocEx";
    // errorMessage = GetLastErrorToString().c_str();
  }

  // If there is an error and there is no callback, throw the error
  if (strcmp(errorMessage, "") && args.Length() != 6) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 6) {
    // Callback to let the user handle with the information
    Napi::Function callback = args[5].As<Napi::Function>();
    callback.Call(env.Global(), {
      Napi::String::New(env, errorMessage),
      Napi::Value::From(env, (intptr_t)allocatedAddress)
    });
    return env.Null();
  } else {
    return Napi::Value::From(env, (intptr_t)allocatedAddress);
  }
}

Napi::Value attachDebugger(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2) {
    Napi::Error::New(env, "requires 2 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsBoolean()) {
    Napi::Error::New(env, "first argument needs to be a number, second a boolean").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Args already checked: args[0] is Number, args[1] is Boolean
  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  if (args[0].As<Napi::Number>().DoubleValue() < 0) { // Check original value before Uint32Value cast
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }
  // processId can be 0 (for system/idle), so no explicit check for processId == 0 here.

  bool killOnExit = args[1].As<Napi::Boolean>().Value();

  bool success = debugger::attach(processId, killOnExit);
  return Napi::Boolean::New(env, success);
}

Napi::Value detachDebugger(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1) {
    Napi::Error::New(env, "Requires 1 argument: processId (number).").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (processId) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  if (args[0].As<Napi::Number>().DoubleValue() < 0) { // Check original value
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }

  bool success = debugger::detatch(processId); // Note: "detatch" might be a typo for "detach" in debugger namespace
  return Napi::Boolean::New(env, success);
}

Napi::Value awaitDebugEvent(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2) {
    Napi::Error::New(env, "requires 2 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsNumber()) {
    Napi::Error::New(env, "both arguments need to be a number").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Args already checked: args[0] and args[1] are Numbers
  Register hardwareRegister = static_cast<Register>(args[0].As<Napi::Number>().Uint32Value());
  // Validate hardwareRegister enum (e.g., DR0-DR3 maps to 0-3)
  if (hardwareRegister < Register::DR0 || hardwareRegister > Register::DR3) {
      Napi::Error::New(env, "Invalid hardware register specified.").ThrowAsJavaScriptException();
      return env.Null();
  }

  int millisTimeout = args[1].As<Napi::Number>().Int32Value(); // Using Int32 for timeout
  if (millisTimeout < 0) {
      Napi::Error::New(env, "Timeout cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }

  DebugEvent debugEvent;
  bool success = debugger::awaitDebugEvent(millisTimeout, &debugEvent);

  if (success && debugEvent.hardwareRegister == hardwareRegister) {
    Napi::Object info = Napi::Object::New(env);

    info.Set(Napi::String::New(env, "processId"), Napi::Value::From(env, (DWORD) debugEvent.processId));
    info.Set(Napi::String::New(env, "threadId"), Napi::Value::From(env, (DWORD) debugEvent.threadId));
    info.Set(Napi::String::New(env, "exceptionCode"), Napi::Value::From(env, (DWORD) debugEvent.exceptionCode));
    info.Set(Napi::String::New(env, "exceptionFlags"), Napi::Value::From(env, (DWORD) debugEvent.exceptionFlags));
    info.Set(Napi::String::New(env, "exceptionAddress"), Napi::Value::From(env, (DWORD64) debugEvent.exceptionAddress));
    info.Set(Napi::String::New(env, "hardwareRegister"), Napi::Value::From(env, static_cast<int>(debugEvent.hardwareRegister)));

    return info;
  }

  // If we aren't interested in passing this event back to the JS space,
  // just silently handle it
  if (success && debugEvent.hardwareRegister != hardwareRegister) {
    debugger::handleDebugEvent(debugEvent.processId, debugEvent.threadId);
  }

  return env.Null();
}

Napi::Value handleDebugEvent(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2) {
    Napi::Error::New(env, "requires 2 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsNumber()) {
    Napi::Error::New(env, "both arguments need to be numbers").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Args already checked: args[0] and args[1] are Numbers
  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  DWORD threadId = args[1].As<Napi::Number>().Uint32Value();

  if (args[0].As<Napi::Number>().DoubleValue() < 0) {
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }
  // Thread IDs are typically non-zero, but 0 can be valid in some contexts.
  // Assuming non-negative is sufficient for now.
  if (args[1].As<Napi::Number>().DoubleValue() < 0) {
      Napi::Error::New(env, "Thread ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }

  bool success = debugger::handleDebugEvent(processId, threadId);
  return Napi::Boolean::New(env, success);
}

Napi::Value setHardwareBreakpoint(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 5) {
    Napi::Error::New(env, "Requires 5 arguments: processId, address, register, trigger, length (all numbers).").ThrowAsJavaScriptException();
    return env.Null();
  }

  for (unsigned int i = 0; i < args.Length(); i++) {
    // Address (args[1]) can be BigInt
    if (i == 1 && args[i].IsBigInt()) continue;
    if (!args[i].IsNumber()) {
      char errorMsg[100];
      sprintf(errorMsg, "Argument %d must be a number (or BigInt for address).", i);
      Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  if (args[0].As<Napi::Number>().DoubleValue() < 0) {
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }

  DWORD64 address;
  if (args[1].IsBigInt()) {
    bool lossless;
    address = args[1].As<Napi::BigInt>().Uint64Value(&lossless);
     if (!lossless || address == 0) { // address 0 is usually invalid for breakpoints
       Napi::Error::New(env, "Invalid address: cannot be zero or conversion resulted in loss.").ThrowAsJavaScriptException();
       return env.Null();
    }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble <= 0) { // Breakpoint addresses must be positive
        Napi::Error::New(env, "Address must be a positive number.").ThrowAsJavaScriptException();
        return env.Null();
    }
    address = static_cast<DWORD64>(addrDouble);
  }


  Register hardwareRegister = static_cast<Register>(args[2].As<Napi::Number>().Uint32Value());
  if (hardwareRegister < Register::DR0 || hardwareRegister > Register::DR3) {
      Napi::Error::New(env, "Invalid hardware register specified.").ThrowAsJavaScriptException();
      return env.Null();
  }

  // Trigger conditions for hardware breakpoints (DR7 register bits)
  // 00: execute, 01: write, 11: read/write, 10: I/O read/write (not typically used this way)
  int trigger = args[3].As<Napi::Number>().Uint32Value();
  if (trigger != 0x0 && trigger != 0x1 && trigger != 0x3) {
      Napi::Error::New(env, "Invalid trigger condition. Must be 0 (execute), 1 (write), or 3 (read/write).").ThrowAsJavaScriptException();
      return env.Null();
  }

  // Length of the breakpoint (size of data to watch)
  // 00: 1-byte, 01: 2-bytes, 11: 4-bytes, 10: 8-bytes (if supported by CPU)
  int length = args[4].As<Napi::Number>().Uint32Value();
   if (length != 1 && length != 2 && length != 4 && length != 8) {
      Napi::Error::New(env, "Invalid length. Must be 1, 2, 4, or 8 bytes.").ThrowAsJavaScriptException();
      return env.Null();
  }
  // The setHardwareBreakpoint C++ function internally maps this to the 00,01,10,11 format if needed.

  bool success = debugger::setHardwareBreakpoint(processId, address, hardwareRegister, trigger, length);
  return Napi::Boolean::New(env, success);
}

Napi::Value removeHardwareBreakpoint(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2) {
    Napi::Error::New(env, "requires 2 arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsNumber()) {
    Napi::Error::New(env, "both arguments need to be numbers").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Args already checked: args[0] and args[1] are Numbers
  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  if (args[0].As<Napi::Number>().DoubleValue() < 0) {
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }

  Register hardwareRegister = static_cast<Register>(args[1].As<Napi::Number>().Uint32Value());
  if (hardwareRegister < Register::DR0 || hardwareRegister > Register::DR3) {
      Napi::Error::New(env, "Invalid hardware register specified.").ThrowAsJavaScriptException();
      return env.Null();
  }

  // To remove a hardware breakpoint, its address field in the debug register is typically set to 0.
  // The debugger::setHardwareBreakpoint function with address 0 should handle this.
  // The trigger and length for removal are often don't-care or 0.
  bool success = debugger::setHardwareBreakpoint(processId, 0, hardwareRegister, 0, 0); // Using 0 for address, trigger, length to signify removal
  return Napi::Boolean::New(env, success);
}

Napi::Value injectDll(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2 && args.Length() != 3) {
    Napi::Error::New(env, "requires 2 arguments, or 3 with a callback").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber() || !args[1].IsString()) {
    Napi::Error::New(env, "first argument needs to be a number, second argument needs to be a string").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 3 && !args[2].IsFunction()) {
    Napi::Error::New(env, "callback needs to be a function").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Args already checked: args[0] is Number, args[1] is String, optional args[2] is Function
  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string dllPathStr(args[1].As<Napi::String>().Utf8Value());
  if (dllPathStr.empty()) {
    Napi::Error::New(env, "DLL path cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }
  // Basic check for .dll, though the OS loader will ultimately determine validity.
  if (dllPathStr.rfind(".dll") == std::string::npos && dllPathStr.rfind(".DLL") == std::string::npos) {
      Napi::Error::New(env, "DLL path should typically end with .dll.").ThrowAsJavaScriptException();
      return env.Null();
  }


  const char* errorMessage = "";
  DWORD moduleHandleValue = -1; // Changed name to avoid conflict
  // The dll::inject function is expected to set errorMessage on failure.
  bool success = dll::inject(handle, dllPathStr, &errorMessage, &moduleHandleValue);

  if (strcmp(errorMessage, "") != 0 && args.Length() != 3) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Comment about moduleHandle truncation is noted.
  // For the N-API layer, we just report success/failure and any message.

  if (args.Length() == 3) {
    Napi::Function callback = args[2].As<Napi::Function>(); // Moved here as it's only used for callback case
    callback.Call(env.Global(), { Napi::String::New(env, errorMessage), Napi::Boolean::New(env, success) });
    return env.Null();
  } else {
    return Napi::Boolean::New(env, success);
  }
}

Napi::Value unloadDll(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 2 && args.Length() != 3) {
    Napi::Error::New(env, "Requires 2 arguments (handle, moduleIdentifier), or 3 with a callback.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (handle) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[1].IsNumber() && !args[1].IsString()) { // moduleIdentifier can be number (address) or string (name)
    Napi::Error::New(env, "Second argument (moduleIdentifier) must be a number or a string.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (args.Length() == 3 && !args[2].IsFunction()) {
    Napi::Error::New(env, "Third argument (callback) must be a function.").ThrowAsJavaScriptException();
    return env.Null();
  }

  HANDLE handle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid handle provided.").ThrowAsJavaScriptException();
    return env.Null();
  }

  HMODULE moduleToUnload = NULL; // Renamed from moduleHandle to avoid scope issues
  const char* findModuleError = ""; // Separate error for findModule part

  if (args[1].IsNumber()) {
    uint64_t moduleAddr = args[1].As<Napi::Number>().Int64Value(); // Addresses are positive
    if (moduleAddr == 0) { // Module base addresses are typically not 0.
        Napi::Error::New(env, "Module address cannot be zero.").ThrowAsJavaScriptException();
        return env.Null();
    }
    moduleToUnload = (HMODULE)moduleAddr;
  } else { // IsString
    std::string moduleNameStr = args[1].As<Napi::String>().Utf8Value();
    if (moduleNameStr.empty()) {
        Napi::Error::New(env, "Module name cannot be empty if provided as a string.").ThrowAsJavaScriptException();
        return env.Null();
    }
    // Note: GetProcessId(handle) might not be reliable if handle is for a different process
    // and current process doesn't have rights, or if handle is not a process handle.
    // Assuming handle is for the target process.
    DWORD targetProcessId = GetProcessId(handle); 
    if (targetProcessId == 0) { // GetProcessId returns 0 on failure.
        findModuleError = "Failed to get Process ID from handle for finding module by name.";
    } else {
        MODULEENTRY32 foundModule = module::findModule(moduleNameStr.c_str(), targetProcessId, &findModuleError);
        if (strcmp(findModuleError, "") != 0 || foundModule.dwSize == 0) { // dwSize check
            if (args.Length() == 3) {
                Napi::Function callback = args[2].As<Napi::Function>();
                callback.Call(env.Global(), { Napi::String::New(env, findModuleError), Napi::Boolean::New(env, false) });
                return env.Null();
            } else {
                Napi::Error::New(env, findModuleError).ThrowAsJavaScriptException();
                return env.Null();
            }
        }
        moduleToUnload = (HMODULE)foundModule.modBaseAddr;
    }
  }
  
  if (strcmp(findModuleError, "") != 0) { // If findModuleError was set and not handled by callback case
     Napi::Error::New(env, findModuleError).ThrowAsJavaScriptException();
     return env.Null();
  }

  if (moduleToUnload == NULL) { // If moduleToUnload is still NULL (e.g. from numeric 0 or failed GetProcessId)
    Napi::Error::New(env, "Failed to determine module handle for unload.").ThrowAsJavaScriptException();
    return env.Null();
  }

  const char* unloadErrorMessage = "";
  bool success = dll::unload(handle, &unloadErrorMessage, moduleToUnload);

  if (strcmp(unloadErrorMessage, "") != 0 && args.Length() != 3) {
    Napi::Error::New(env, unloadErrorMessage).ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false); // Return false, as error was thrown
  }

  if (args.Length() == 3) {
    Napi::Function callback = args[2].As<Napi::Function>();
    callback.Call(env.Global(), { Napi::String::New(env, unloadErrorMessage), Napi::Boolean::New(env, success) });
    return env.Null();
  } else {
    return Napi::Boolean::New(env, success);
  }
}

Napi::Value openFileMapping(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1) {
    Napi::Error::New(env, "Requires 1 argument: fileName (string).").ThrowAsJavaScriptException();
    return env.Null();
  }
  if (!args[0].IsString()) {
    Napi::Error::New(env, "First argument (fileName) must be a string.").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string fileNameStr = args[0].As<Napi::String>().Utf8Value();
  if (fileNameStr.empty()) {
    Napi::Error::New(env, "File name cannot be empty.").ThrowAsJavaScriptException();
    return env.Null();
  }

  HANDLE fileMapHandle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fileNameStr.c_str()); // Renamed variable

  if (fileMapHandle == NULL) {
    // Use GetLastErrorToString() for a more descriptive error if possible
    std::string errorMsg = "Error opening file mapping: " + GetLastErrorToString();
    Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Value::From(env, (uintptr_t) fileMapHandle);
}

Napi::Value mapViewOfFile(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 5) {
    Napi::Error::New(env, "Requires 5 arguments: processHandle, fileHandle, offset, viewSize, pageProtection.").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Type checking for all arguments
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "Argument 1 (processHandle) must be a number.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[1].IsNumber()) {
    Napi::Error::New(env, "Argument 2 (fileHandle) must be a number.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[2].IsNumber() && !args[2].IsBigInt()) {
    Napi::Error::New(env, "Argument 3 (offset) must be a number or BigInt.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[3].IsNumber() && !args[3].IsBigInt()) {
    Napi::Error::New(env, "Argument 4 (viewSize) must be a number or BigInt.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[4].IsNumber()) {
    Napi::Error::New(env, "Argument 5 (pageProtection) must be a number.").ThrowAsJavaScriptException(); return env.Null();
  }


  HANDLE processHandle = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (processHandle == NULL || processHandle == INVALID_HANDLE_VALUE) {
     Napi::Error::New(env, "Invalid processHandle provided.").ThrowAsJavaScriptException(); return env.Null();
  }
  HANDLE fileHandleVal = (HANDLE)args[1].As<Napi::Number>().Int64Value(); // Renamed variable
  if (fileHandleVal == NULL) { // INVALID_HANDLE_VALUE might also be relevant depending on OpenFileMapping return for errors other than NULL
     Napi::Error::New(env, "Invalid fileHandle provided (cannot be NULL).").ThrowAsJavaScriptException(); return env.Null();
  }


  uint64_t offset;
  bool lossless;
  if (args[2].IsBigInt()) {
    offset = args[2].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) { Napi::Error::New(env, "Offset conversion from BigInt resulted in loss.").ThrowAsJavaScriptException(); return env.Null(); }
  } else { // IsNumber
    double offsetDouble = args[2].As<Napi::Number>().DoubleValue();
    if (offsetDouble < 0) { Napi::Error::New(env, "Offset cannot be negative.").ThrowAsJavaScriptException(); return env.Null(); }
    offset = static_cast<uint64_t>(offsetDouble);
  }
  
  size_t viewSize;
  if (args[3].IsBigInt()) {
    viewSize = args[3].As<Napi::BigInt>().Uint64Value(&lossless);
     if (!lossless) { Napi::Error::New(env, "View size conversion from BigInt resulted in loss.").ThrowAsJavaScriptException(); return env.Null(); }
  } else { // IsNumber
    double viewSizeDouble = args[3].As<Napi::Number>().DoubleValue();
    if (viewSizeDouble < 0) { Napi::Error::New(env, "View size cannot be negative.").ThrowAsJavaScriptException(); return env.Null(); }
    viewSize = static_cast<size_t>(viewSizeDouble);
  }
  // A viewSize of 0 means map the entire file object from the offset. This is valid.

  ULONG pageProtection = args[4].As<Napi::Number>().Uint32Value(); // ULONG is typically uint32
  // TODO: Validate pageProtection against known Windows constants if possible.


  LPVOID baseAddress = MapViewOfFile2(fileHandleVal, processHandle, offset, NULL, viewSize, 0, pageProtection);

  if (baseAddress == NULL) {
    std::string errorMsg = "Error mapping view of file: " + GetLastErrorToString();
    Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
    return env.Null();
  }

  return Napi::Value::From(env, (uintptr_t) baseAddress);
}

// https://stackoverflow.com/a/17387176
std::string GetLastErrorToString() {
  DWORD errorMessageID = ::GetLastError();

  // No error message, return empty string
  if(errorMessageID == 0) {
    return std::string();
  }

  LPSTR messageBuffer = nullptr;

  size_t size = FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    errorMessageID,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR)&messageBuffer,
    0,
    NULL
  );

  std::string message(messageBuffer, size);

  // Free the buffer
  LocalFree(messageBuffer);
  return message;
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "openProcess"), Napi::Function::New(env, openProcess));
  exports.Set(Napi::String::New(env, "closeHandle"), Napi::Function::New(env, closeHandle));
  exports.Set(Napi::String::New(env, "getProcesses"), Napi::Function::New(env, getProcesses));
  exports.Set(Napi::String::New(env, "getModules"), Napi::Function::New(env, getModules));
  exports.Set(Napi::String::New(env, "findModule"), Napi::Function::New(env, findModule));
  exports.Set(Napi::String::New(env, "readMemory"), Napi::Function::New(env, readMemory));
  exports.Set(Napi::String::New(env, "readBuffer"), Napi::Function::New(env, readBuffer));
  exports.Set(Napi::String::New(env, "writeMemory"), Napi::Function::New(env, writeMemory));
  exports.Set(Napi::String::New(env, "writeBuffer"), Napi::Function::New(env, writeBuffer));
  exports.Set(Napi::String::New(env, "findPattern"), Napi::Function::New(env, findPattern));
  exports.Set(Napi::String::New(env, "findPatternByModule"), Napi::Function::New(env, findPatternByModule));
  exports.Set(Napi::String::New(env, "findPatternByAddress"), Napi::Function::New(env, findPatternByAddress));
  exports.Set(Napi::String::New(env, "virtualProtectEx"), Napi::Function::New(env, virtualProtectEx));
  exports.Set(Napi::String::New(env, "callFunction"), Napi::Function::New(env, callFunction));
  exports.Set(Napi::String::New(env, "virtualAllocEx"), Napi::Function::New(env, virtualAllocEx));
  exports.Set(Napi::String::New(env, "getRegions"), Napi::Function::New(env, getRegions));
  exports.Set(Napi::String::New(env, "virtualQueryEx"), Napi::Function::New(env, virtualQueryEx));
  exports.Set(Napi::String::New(env, "attachDebugger"), Napi::Function::New(env, attachDebugger));
  exports.Set(Napi::String::New(env, "detachDebugger"), Napi::Function::New(env, detachDebugger));
  exports.Set(Napi::String::New(env, "awaitDebugEvent"), Napi::Function::New(env, awaitDebugEvent));
  exports.Set(Napi::String::New(env, "handleDebugEvent"), Napi::Function::New(env, handleDebugEvent));
  exports.Set(Napi::String::New(env, "setHardwareBreakpoint"), Napi::Function::New(env, setHardwareBreakpoint));
  exports.Set(Napi::String::New(env, "removeHardwareBreakpoint"), Napi::Function::New(env, removeHardwareBreakpoint));
  exports.Set(Napi::String::New(env, "injectDll"), Napi::Function::New(env, injectDll));
  exports.Set(Napi::String::New(env, "unloadDll"), Napi::Function::New(env, unloadDll));
  exports.Set(Napi::String::New(env, "openFileMapping"), Napi::Function::New(env, openFileMapping));
  exports.Set(Napi::String::New(env, "mapViewOfFile"), Napi::Function::New(env, mapViewOfFile));
  exports.Set(Napi::String::New(env, "findPatternInRegion"), Napi::Function::New(env, findPatternInRegionApi));
  exports.Set(Napi::String::New(env, "getThreads"), Napi::Function::New(env, getThreadsApi)); // Added new export for getThreads
  return exports;
}

Napi::Value getThreadsApi(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  if (args.Length() != 1 && args.Length() != 2) { // Optional callback
    Napi::Error::New(env, "Requires 1 argument (processId), or 2 arguments if a callback is being used.").ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "First argument (processId) must be a number.").ThrowAsJavaScriptException();
    return env.Null();
  }

  int callbackArgIndex = -1;
  if (args.Length() == 2) {
    if (!args[1].IsFunction()) {
      Napi::Error::New(env, "Second argument (callback) must be a function.").ThrowAsJavaScriptException();
      return env.Null();
    }
    callbackArgIndex = 1;
  }

  DWORD processId = args[0].As<Napi::Number>().Uint32Value();
  if (processId == 0 && args[0].As<Napi::Number>().DoubleValue() != 0) { // Check if negative before cast
      Napi::Error::New(env, "Process ID cannot be negative.").ThrowAsJavaScriptException();
      return env.Null();
  }
   if (processId == 0) { // module::getThreads already checks this and sets an error.
      // However, to be consistent with N-API validation:
      // Napi::Error::New(env, "Process ID cannot be zero.").ThrowAsJavaScriptException();
      // return env.Null();
      // Let's rely on the C++ function's error message for this specific case for now.
   }


  const char* errorMessage = "";
  std::vector<THREADENTRY32> threadEntries = module::getThreads(processId, &errorMessage);

  if (strcmp(errorMessage, "") != 0 && callbackArgIndex == -1) {
    Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Array threadsArray = Napi::Array::New(env, threadEntries.size());
  for (size_t i = 0; i < threadEntries.size(); ++i) {
    Napi::Object threadInfo = Napi::Object::New(env);
    threadInfo.Set(Napi::String::New(env, "threadId"), Napi::Number::New(env, threadEntries[i].th32ThreadID));
    threadInfo.Set(Napi::String::New(env, "ownerProcessId"), Napi::Number::New(env, threadEntries[i].th32OwnerProcessID));
    threadInfo.Set(Napi::String::New(env, "basePriority"), Napi::Number::New(env, threadEntries[i].tpBasePri));
    threadsArray.Set(i, threadInfo);
  }

  if (callbackArgIndex != -1) {
    Napi::Function callback = args[callbackArgIndex].As<Napi::Function>();
    if (strcmp(errorMessage, "") != 0) {
        callback.Call(env.Global(), {Napi::String::New(env, errorMessage), env.Null()});
    } else {
        callback.Call(env.Global(), {env.Null(), threadsArray});
    }
    return env.Null();
  } else {
    return threadsArray;
  }
}

// New N-API function for findPatternInRegion
Napi::Value findPatternInRegionApi(const Napi::CallbackInfo& args) {
  Napi::Env env = args.Env();

  // Expected arguments: handle, baseAddress, scanSize, pattern, [flags, patternOffset], [callback]
  // Minimum 4 args, max 7 (if flags, offset, and callback are provided)
  if (args.Length() < 4 || args.Length() > 7) {
    Napi::Error::New(env, "Requires 4 to 7 arguments: handle, baseAddress, scanSize, pattern, [flags (optional)], [patternOffset (optional)], [callback (optional)]").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Type validation for required arguments
  if (!args[0].IsNumber()) {
    Napi::Error::New(env, "Argument 1 (handle) must be a number.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[1].IsNumber() && !args[1].IsBigInt()) {
    Napi::Error::New(env, "Argument 2 (baseAddress) must be a number or BigInt.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[2].IsNumber() && !args[2].IsBigInt()) {
    Napi::Error::New(env, "Argument 3 (scanSize) must be a number or BigInt.").ThrowAsJavaScriptException(); return env.Null();
  }
  if (!args[3].IsString()) {
    Napi::Error::New(env, "Argument 4 (pattern) must be a string.").ThrowAsJavaScriptException(); return env.Null();
  }

  int callbackArgIndex = -1;
  if (args.Length() > 4 && args[args.Length() - 1].IsFunction()) {
    callbackArgIndex = args.Length() - 1;
  }

  short flags = 0; // Default ST_NORMAL
  uint32_t patternOffset = 0; // Default offset 0

  if (callbackArgIndex == -1) { // No callback or callback is not the last arg
      if (args.Length() >= 5 && !args[4].IsUndefined()) { // Check if flags is provided
          if (!args[4].IsNumber()) { Napi::Error::New(env, "Argument 5 (flags) must be a number.").ThrowAsJavaScriptException(); return env.Null(); }
          flags = args[4].As<Napi::Number>().Int16Value();
      }
      if (args.Length() >= 6 && !args[5].IsUndefined()) { // Check if patternOffset is provided
          if (!args[5].IsNumber()) { Napi::Error::New(env, "Argument 6 (patternOffset) must be a number.").ThrowAsJavaScriptException(); return env.Null(); }
          patternOffset = args[5].As<Napi::Number>().Uint32Value();
      }
  } else { // Callback is present
      if (args.Length() -1 >= 5 && !args[4].IsUndefined()) { // Check flags
          if (!args[4].IsNumber()) { Napi::Error::New(env, "Argument 5 (flags) must be a number.").ThrowAsJavaScriptException(); return env.Null(); }
          flags = args[4].As<Napi::Number>().Int16Value();
      }
      if (args.Length() -1 >= 6 && !args[5].IsUndefined()) { // Check patternOffset
          if (!args[5].IsNumber()) { Napi::Error::New(env, "Argument 6 (patternOffset) must be a number.").ThrowAsJavaScriptException(); return env.Null(); }
          patternOffset = args[5].As<Napi::Number>().Uint32Value();
      }
  }


  // Extracted value validation
  HANDLE hProcess = (HANDLE)args[0].As<Napi::Number>().Int64Value();
  if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "Invalid process handle provided.").ThrowAsJavaScriptException(); return env.Null();
  }

  uintptr_t baseAddress;
  bool lossless;
  if (args[1].IsBigInt()) {
    baseAddress = (uintptr_t)args[1].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) { Napi::Error::New(env, "baseAddress conversion from BigInt resulted in loss.").ThrowAsJavaScriptException(); return env.Null(); }
  } else { // IsNumber
    double addrDouble = args[1].As<Napi::Number>().DoubleValue();
    if (addrDouble < 0) { Napi::Error::New(env, "baseAddress cannot be negative.").ThrowAsJavaScriptException(); return env.Null(); }
    baseAddress = (uintptr_t)addrDouble;
  }
  if (baseAddress == 0) { Napi::Error::New(env, "baseAddress cannot be zero.").ThrowAsJavaScriptException(); return env.Null(); }


  SIZE_T scanSize;
  if (args[2].IsBigInt()) {
    scanSize = (SIZE_T)args[2].As<Napi::BigInt>().Uint64Value(&lossless);
    if (!lossless) { Napi::Error::New(env, "scanSize conversion from BigInt resulted in loss.").ThrowAsJavaScriptException(); return env.Null(); }
  } else { // IsNumber
    double sizeDouble = args[2].As<Napi::Number>().DoubleValue();
    if (sizeDouble < 0) { Napi::Error::New(env, "scanSize cannot be negative.").ThrowAsJavaScriptException(); return env.Null(); }
    scanSize = (SIZE_T)sizeDouble;
  }
  if (scanSize == 0) { Napi::Error::New(env, "scanSize cannot be zero.").ThrowAsJavaScriptException(); return env.Null(); }

  std::string patternStr = args[3].As<Napi::String>().Utf8Value();
  if (patternStr.empty()) {
    Napi::Error::New(env, "Pattern string cannot be empty.").ThrowAsJavaScriptException(); return env.Null();
  }

  if (flags < 0) { // Basic validation for flags
      Napi::Error::New(env, "Flags cannot be negative.").ThrowAsJavaScriptException(); return env.Null();
  }
  // patternOffset is uint32_t, so implicitly non-negative from As<Napi::Number>().Uint32Value()

  uintptr_t foundAddress = 0;
  const char* errorMessage = "";

  bool success = Pattern.findPatternInRegion(hProcess, baseAddress, scanSize, patternStr.c_str(), flags, patternOffset, &foundAddress, &errorMessage);

  if (callbackArgIndex != -1) {
    Napi::Function callback = args[callbackArgIndex].As<Napi::Function>();
    if (success) {
      callback.Call(env.Global(), { Napi::String::New(env, ""), Napi::Value::From(env, (uintptr_t)foundAddress) });
    } else {
      callback.Call(env.Global(), { Napi::String::New(env, errorMessage), env.Null() });
    }
    return env.Null();
  } else {
    if (success) {
      return Napi::Value::From(env, (uintptr_t)foundAddress);
    } else {
      if (strcmp(errorMessage, "") != 0) {
        Napi::Error::New(env, errorMessage).ThrowAsJavaScriptException();
      }
      return Napi::Value::From(env, (uintptr_t)0); // Return 0 if not found and no other error message
    }
  }
}

NODE_API_MODULE(memoryprocess, init)
