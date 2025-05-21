#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include "module.h"
#include "process.h"
#include "memoryprocess.h"

DWORD64 module::getBaseAddress(const char* processName, DWORD processId) {
  if (processName == nullptr || *processName == '\0') {
    // Cannot set errorMessage here as signature doesn't support it.
    // Returning 0 as an indicator of failure.
    return 0;
  }
  if (processId == 0) { // Or < 0 if PIDs could be negative, though DWORD is unsigned.
    // Cannot set errorMessage here.
    return 0;
  }

  const char* findModuleError = ""; // Use a separate error message variable
  MODULEENTRY32 baseModule = module::findModule(processName, processId, &findModuleError);
  
  // If findModule itself indicated an error or returned an empty/invalid module
  if (strcmp(findModuleError, "") != 0 || baseModule.dwSize == 0) {
      return 0; // Base address not found or error occurred
  }
  return (DWORD64)baseModule.modBaseAddr; 
}

MODULEENTRY32 module::findModule(const char* moduleName, DWORD processId, const char** errorMessage) {
  MODULEENTRY32 module{}; // Value-initialize
  *errorMessage = ""; // Initialize error message

  if (moduleName == nullptr || *moduleName == '\0') {
    *errorMessage = "Module name cannot be null or empty.";
    return module;
  }
  if (processId == 0) {
    *errorMessage = "Process ID cannot be zero.";
    return module;
  }

  bool found = false;
  std::vector<MODULEENTRY32> moduleEntries = getModules(processId, errorMessage);

  // If getModules itself failed and set an error message
  if (strcmp(*errorMessage, "") != 0) {
      return module; // Return empty module struct
  }

  // Loop over every module
  for (std::vector<MODULEENTRY32>::size_type i = 0; i != moduleEntries.size(); i++) {
    // Check to see if this is the module we want.
    if (!strcmp(moduleEntries[i].szModule, moduleName)) {
      // module is returned and moduleEntry is used internally for reading/writing to memory
      module = moduleEntries[i];
      found = true;
      break;
    }
  }

  if (!found) {
    *errorMessage = "unable to find module";
  }

  return module;
} 

std::vector<MODULEENTRY32> module::getModules(DWORD processId, const char** errorMessage) {
  // Take a snapshot of all modules inside a given process.
  *errorMessage = ""; // Initialize error message

  if (processId == 0) {
    *errorMessage = "Process ID cannot be zero for getModules.";
    return {}; // Return empty vector
  }

  HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
  MODULEENTRY32 mEntry{}; // Value-initialize

  if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
    *errorMessage = "CreateToolhelp32Snapshot failed for modules.";
    // Consider GetLastError() for more details
    return {}; // Return empty vector
  }

  // Before use, set the structure size.
  mEntry.dwSize = sizeof(mEntry);

  // Exit if unable to find the first module.
  if (!Module32First(hModuleSnapshot, &mEntry)) {
    CloseHandle(hModuleSnapshot);
    *errorMessage = "Module32First failed to retrieve the first module.";
    // Consider GetLastError()
    return {}; // Return empty vector
  }

  std::vector<MODULEENTRY32> modules;

  // Loop through modules.
  do {
    // Add the module to the vector
    modules.push_back(mEntry);
  } while (Module32Next(hModuleSnapshot, &mEntry));

  CloseHandle(hModuleSnapshot);

  return modules;
}

std::vector<THREADENTRY32> module::getThreads(DWORD processId, const char** errorMessage) {
  *errorMessage = ""; // Initialize error message

  if (processId == 0) {
      *errorMessage = "Process ID cannot be zero for getThreads.";
      return {}; // Return empty vector
  }

  HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
  THREADENTRY32 tEntry{}; // Value-initialize, changed name to avoid conflict with MODULEENTRY32 mEntry

  if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
    *errorMessage = "CreateToolhelp32Snapshot failed for threads.";
    return {}; // Return empty vector
  }

  tEntry.dwSize = sizeof(tEntry); // Use tEntry

  if(!Thread32First(hThreadSnapshot, &tEntry)) { // Use tEntry
    CloseHandle(hThreadSnapshot);
    *errorMessage = "Thread32First failed to retrieve the first thread.";
    return {}; // Return empty vector
  }

  std::vector<THREADENTRY32> threads;

  do {
    threads.push_back(tEntry); // Use tEntry
  } while (Thread32Next(hThreadSnapshot, &tEntry)); // Use tEntry

  CloseHandle(hThreadSnapshot);

  return threads;
}
