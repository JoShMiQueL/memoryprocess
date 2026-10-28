// Victim process with known values at stable locations for tests.
// Compiled to build/victim.exe by scripts/build-victim.mjs (cl).
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

__declspec(dllexport) volatile int32_t  g_i32  = 0x12345678;
__declspec(dllexport) volatile int64_t  g_i64  = 0x1122334455667788;
__declspec(dllexport) volatile uint32_t g_u32  = 0xDEADBEEF;
__declspec(dllexport) volatile float    g_f32  = 3.14159265f;
__declspec(dllexport) volatile double   g_f64  = 2.718281828459045;
__declspec(dllexport) volatile char     g_str[64] = "memoryprocess_v2_victim";
__declspec(dllexport) volatile uint8_t  g_pattern[16] = {
  0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0x90, 0x90,
  0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33
};
__declspec(dllexport) volatile int32_t* g_ptr = NULL;

int main(void) {
  g_ptr = (volatile int32_t*)&g_i32;
  printf("PID=%lu\n", GetCurrentProcessId());
  printf("&g_i32=%p &g_i64=%p &g_u32=%p &g_f32=%p &g_f64=%p &g_str=%p &g_pattern=%p &g_ptr=%p\n",
    &g_i32,&g_i64,&g_u32,&g_f32,&g_f64,&g_str,&g_pattern,&g_ptr);
  fflush(stdout);
  while (1) Sleep(1000);
  return 0;
}
