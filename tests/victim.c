// Hardened victim for memoryprocess tests: pointers chains, arrays,
// structs, packed data, guarded/hidden regions, and self-mutating values.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
  int32_t  id;
  float    health;
  double   mana;
  char     name[32];
  uint8_t  flags;
  uint64_t xp;
} Entity;
#pragma pack(pop)

// flat scalars
__declspec(dllexport) volatile int32_t  g_i32  = 0x12345678;
__declspec(dllexport) volatile int64_t  g_i64  = 0x1122334455667788;
__declspec(dllexport) volatile uint32_t g_u32  = 0xDEADBEEF;
__declspec(dllexport) volatile float    g_f32  = 3.14159265f;
__declspec(dllexport) volatile double   g_f64  = 2.718281828459045;
__declspec(dllexport) volatile char     g_str[64] = "memoryprocess_v2_victim";
__declspec(dllexport) volatile uint16_t g_u16 = 0xBEEF;
__declspec(dllexport) volatile uint8_t  g_u8  = 0x7F;
__declspec(dllexport) volatile wchar_t  g_wstr[32] = L"wide_str_test";

// signature pattern (unique)
__declspec(dllexport) volatile uint8_t  g_pattern[16] = {
  0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0x90, 0x90,
  0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33
};

// pointer chain: base -> lvl1 -> lvl2 -> lvl3 -> g_i32
__declspec(dllexport) volatile int32_t*  g_ptr  = NULL;
__declspec(dllexport) volatile int32_t** g_pp   = NULL;
__declspec(dllexport) volatile int32_t*** g_ppp = NULL;

// struct + array
__declspec(dllexport) volatile Entity    g_entity;
__declspec(dllexport) volatile int32_t   g_array[64];
__declspec(dllexport) volatile uint8_t   g_bigbuf[4096];

// self-mutating counter (for repeated-read tests)
__declspec(dllexport) volatile int32_t g_counter = 0;

// second instance of the common 2-byte sequence "DE AD" so module scans of it
// are guaranteed to be multi-hit (first instance lives inside g_pattern)
__declspec(dllexport) volatile uint8_t g_pattern2[8] = {
  0xDE, 0xAD, 0x00, 0x11, 0xDE, 0xAD, 0x22, 0x33
};

int main(void) {
  g_ptr = (volatile int32_t*)&g_i32;
  g_pp  = (volatile int32_t**)&g_ptr;
  g_ppp = (volatile int32_t***)&g_pp;

  memset((void*)&g_entity, 0, sizeof(g_entity));
  g_entity.id = 1337;
  g_entity.health = 87.5f;
  g_entity.mana = 4200.75;
  strcpy_s((char*)g_entity.name, 32, "TestEntity");
  g_entity.flags = 0xA5;
  g_entity.xp = 0xDEADCAFEBABEULL;

  for (int i = 0; i < 64; i++) g_array[i] = i * 100;
  memset((void*)g_bigbuf, 0xAB, sizeof(g_bigbuf));

  printf("PID=%lu\n", GetCurrentProcessId());
  printf("&g_i32=%p &g_i64=%p &g_u32=%p &g_f32=%p &g_f64=%p &g_str=%p &g_u16=%p &g_u8=%p &g_wstr=%p\n",
    &g_i32,&g_i64,&g_u32,&g_f32,&g_f64,&g_str,&g_u16,&g_u8,&g_wstr);
  printf("&g_pattern=%p &g_ptr=%p &g_pp=%p &g_ppp=%p &g_entity=%p &g_array=%p &g_bigbuf=%p &g_counter=%p\n",
    &g_pattern,&g_ptr,&g_pp,&g_ppp,&g_entity,&g_array,&g_bigbuf,&g_counter);
  printf("&g_i64=%p\n", &g_i64); // repeat for parser

  // PAGE_GUARD region: 2 pages — first page committed RW filled with 0xC5,
  // second page RW + PAGE_GUARD (unreadable via ReadProcessMemory).
  {
    LPVOID guard = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (guard) {
      DWORD oldp = 0;
      memset(guard, 0xC5, 0x1000);
      VirtualProtect((BYTE*)guard + 0x1000, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldp);
      printf("&g_guard=%p &g_guard_end=%p\n", guard, (BYTE*)guard + 0x2000);
    }
  }
  printf("&g_pattern2=%p\n", &g_pattern2);
  fflush(stdout);

  DWORD t = 0;
  while (1) { g_counter++; Sleep(50); if (++t % 20 == 0) g_i32++; }
  return 0;
}
