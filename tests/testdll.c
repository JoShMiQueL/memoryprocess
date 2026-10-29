// Minimal DLL for injectDll/ejectDll/callRemote tests.
#include <windows.h>
#include <stdint.h>

__declspec(dllexport) volatile int g_injected = 42;

// Returns its argument — used to verify remote-thread parameter passing.
__declspec(dllexport) DWORD WINAPI mp_echo(LPVOID p) { return (DWORD)(uintptr_t)p; }

// Fixed sentinel — used to verify remote-thread exit codes.
__declspec(dllexport) DWORD WINAPI mp_fortytwo(LPVOID p) { (void)p; return 42; }

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
  (void)hinst; (void)reason; (void)reserved;
  return TRUE;
}
