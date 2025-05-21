#include <node.h>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include "process.h"
#include "memoryprocess.h"

process::process() {}
process::~process() {}

using v8::Exception;
using v8::Isolate;
using v8::String;

process::Pair process::openProcess(const char* processName, const char** errorMessage){
  PROCESSENTRY32 process; // Intentionally uninitialized, only valid if handle is not NULL
  HANDLE handle = NULL;
  *errorMessage = nullptr; // Initialize error message for this function

  // A list of processes (PROCESSENTRY32)
  std::vector<PROCESSENTRY32> processes = getProcesses(errorMessage);

  // If getProcesses failed, *errorMessage will be set. Propagate this.
  if (*errorMessage != nullptr) {
    return { NULL, process };
  }

  // If getProcesses succeeded but returned no processes
  if (processes.empty()) {
    *errorMessage = "No processes found in the system.";
    return { NULL, process };
  }

  bool foundProcessByName = false;
  for (std::vector<PROCESSENTRY32>::size_type i = 0; i != processes.size(); i++) {
    if (strcmp(processes[i].szExeFile, processName) == 0) {
      foundProcessByName = true;
      handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i].th32ProcessID);
      if (handle != NULL) {
        process = processes[i];
        *errorMessage = nullptr; // Clear any prior error message (e.g. from a previous failed OpenProcess)
        break; 
      } else {
        // OpenProcess failed for this specific process
        *errorMessage = "OpenProcess failed for the specified process name. Verify permissions or check GetLastError().";
        // Continue searching, another process might match and be accessible
      }
    }
  }

  if (handle == NULL) {
    if (!foundProcessByName) {
      *errorMessage = "Unable to find any process with the specified name.";
    } else {
      // Process with name was found, but all attempts to OpenProcess failed.
      // *errorMessage should already be set by the OpenProcess failure case.
      // If it's not set for some reason, provide a generic message.
      if (*errorMessage == nullptr) {
        *errorMessage = "Found process by name, but failed to open it. Unknown error during OpenProcess.";
      }
    }
  }

  return {
    handle,
    process,
  };
}

process::Pair process::openProcess(DWORD processId, const char** errorMessage) {
  PROCESSENTRY32 process; // Intentionally uninitialized
  HANDLE handle = NULL;
  *errorMessage = nullptr; // Initialize error message for this function

  // A list of processes (PROCESSENTRY32)
  std::vector<PROCESSENTRY32> processes = getProcesses(errorMessage);

  // If getProcesses failed, *errorMessage will be set. Propagate this.
  if (*errorMessage != nullptr) {
    return { NULL, process };
  }

  // If getProcesses succeeded but returned no processes
  if (processes.empty()) {
    *errorMessage = "No processes found in the system.";
    return { NULL, process };
  }

  bool foundProcessById = false;
  for (std::vector<PROCESSENTRY32>::size_type i = 0; i != processes.size(); i++) {
    if (processes[i].th32ProcessID == processId) {
      foundProcessById = true;
      handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i].th32ProcessID);
      if (handle != NULL) {
        process = processes[i];
        *errorMessage = nullptr; // Clear error on successful open
        break; 
      } else {
        // OpenProcess failed for this specific process ID
        *errorMessage = "OpenProcess failed for the specified process ID. Verify permissions or check GetLastError().";
        // Since process ID is unique, we can break here.
        break;
      }
    }
  }

  if (handle == NULL) {
    if (!foundProcessById) {
      *errorMessage = "Unable to find any process with the specified ID.";
    } else {
      // Process with ID was found, but OpenProcess failed.
      // *errorMessage should already be set by the OpenProcess failure case.
      // If it's not set for some reason, provide a generic message.
      if (*errorMessage == nullptr) {
        *errorMessage = "Found process by ID, but failed to open it. Unknown error during OpenProcess.";
      }
    }
  }

  return {
    handle,
    process,
  };
}

std::vector<PROCESSENTRY32> process::getProcesses(const char** errorMessage) {
  // Take a snapshot of all processes.
  HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  PROCESSENTRY32 pEntry;
  *errorMessage = nullptr; // Initialize error message

  if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
    *errorMessage = "CreateToolhelp32Snapshot failed. Could not take snapshot of processes.";
    return {}; // Return empty vector on failure
  }

  // Before use, set the structure size.
  pEntry.dwSize = sizeof(pEntry);

  // Exit if unable to find the first process.
  if (!Process32First(hProcessSnapshot, &pEntry)) {
    CloseHandle(hProcessSnapshot);
    *errorMessage = "Process32First failed. Could not retrieve the first process.";
    return {}; // Return empty vector on failure
  }

  std::vector<PROCESSENTRY32> processes;

  // Loop through processes.
  do {
    // Add the process to the vector
    processes.push_back(pEntry);
  } while (Process32Next(hProcessSnapshot, &pEntry));

  CloseHandle(hProcessSnapshot);
  return processes;
}
