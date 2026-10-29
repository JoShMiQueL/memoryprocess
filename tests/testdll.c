// Minimal DLL for injectDll/ejectDll tests.
#include <windows.h>

__declspec(dllexport) volatile int g_injected = 42;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
  (void)hinst; (void)reason; (void)reserved;
  return TRUE;
}
