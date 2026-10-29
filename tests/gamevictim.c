// Simulated game engine — heap-allocated, polymorphic entities, a ticking
// simulation thread, an orbiting camera (view matrix), and a deep pointer
// chain. Exercises memoryprocess v2's cheat-dev layer (addr chains,
// entityList, Entity snapshots, Offsets, findPointersTo, readSafe).
//
// Stable pointer chain for tests (4 hops):
//   &g_engine +0x00  ->  GameEngine* g_engine
//   g_engine +0x18   ->  World* world
//   world    +0x20   ->  EntityList* entities
//   entities +0x00   ->  Entity** array     (contiguous ptr array)
//   entities +0x08   ->  int count
//   world    +0x28   ->  Entity* localPlayer
//   world    +0x40   ->  float viewMatrix[16]
//   g_engine +0x30   ->  NetworkState* net
//   entity   +0x38   ->  float health      (displayName[32] wide str +0x50)
//   entity   +0x90   ->  Inventory* inv    (inv +0x40 = float money)
//   entity   +0x98   ->  subclass blob (type id int32 at +0x98 = 0xA00+kind)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define TICK_MS        50
#define MIN_ENTITIES    4
#define MAX_ENTITIES   16
#define ENT_ARRAY_CAP  64

/* Polymorphic Entity — shared vtable in .rdata, extra data appended as an
 * untyped subclass blob (subclasses only differ in appended field content). */
typedef void *EntityVTable[3];
typedef struct Entity {
  EntityVTable *vtable;     /* +0x00  [0]=~Entity [1]=getName [2]=getHealth */
  int32_t       id;         /* +0x08 */
  char          name[32];   /* +0x0C  UTF-8 */
  float         pos[3];     /* +0x2C */
  float         health;     /* +0x38 */
  float         maxHealth;  /* +0x3C */
  int32_t       team;       /* +0x40 */
  uint64_t      flags;      /* +0x44  bit 0 = alive */
  wchar_t       displayName[32]; /* +0x50  UTF-16 (NUL-terminated) */
  struct Inventory *inv;    /* +0x90 */
  /* +0x98 subclass blob — EntityPlayer, EntityNPC, EntityItem,
   * EntityProjectile, EntityVehicle, EntityProp all start here but differ
   * in content (ammo, itemId, teamId...). */
} Entity;

typedef struct Inventory {
  int32_t slots[16];        /* +0x00 */
  float   money;            /* +0x40 */
} Inventory;

typedef struct EntityList {
  Entity **array;           /* +0x00 contiguous Entity*[ENT_ARRAY_CAP] */
  int32_t  count;           /* +0x08 */
  int32_t  capacity;        /* +0x0C */
} EntityList;

/* World layout is spelled out explicitly (offsetof-proof):
 *   +0x00 char name[16]
 *   +0x10 pad
 *   +0x18 pad2
 *   +0x20 EntityList* entities
 *   +0x28 Entity* localPlayer
 *   +0x30 pad3
 *   +0x40 float viewMatrix[16] */
typedef struct WorldImpl {
  char       name[32];      /* +0x00 */
  EntityList *entities;     /* +0x20 */
  Entity    *localPlayer;   /* +0x28 */
  void      *_pad;          /* +0x30 */
  int32_t    _pad2;         /* +0x38 */
  int32_t    _pad3;         /* +0x3C */
  float      viewMatrix[16];/* +0x40 */
} World;

typedef struct NetworkState {
  int32_t tickRate;         /* +0x00 */
  int32_t _pad;             /* +0x04 */
  char    serverName[32];   /* +0x08 */
} NetworkState;

typedef struct GameEngine {
  void         *_pad0;      /* +0x00 */
  void         *_pad1;      /* +0x08 */
  int64_t       uptime;     /* +0x10 */
  World        *world;      /* +0x18 */
  int32_t       frame;      /* +0x20 */
  int32_t       _pad2;      /* +0x24 */
  int32_t       _pad3;      /* +0x28 */
  int32_t       _pad4;      /* +0x2C */
  NetworkState *net;        /* +0x30 */
} GameEngine;

/* vtable — three real function pointers (dtor/getName/getHealth), kept in
 * .rdata like a real C++ vtable. */
static void        e_dtor(void)    {}
static const char *e_getName(void) { return "Entity"; }
static float       e_getHealth(void) { return 0.0f; }
static EntityVTable g_entityVTable = {
  (void *)e_dtor, (void *)e_getName, (void *)e_getHealth,
};

/* Emitted pointers (module+rva anchors + AOB sentinel). */
__declspec(dllexport) volatile GameEngine *g_engine = NULL;
__declspec(dllexport) volatile uint8_t g_marker[16] = {
  0x4D, 0x50, 0x47, 0x56, /* "MPGV" */
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xAA, 0xBB,
};

static EntityList      *g_entities;  /* World+0x20 contents */
static Entity         **g_entArray;  /* EntityList+0x00 contents */
static Entity          *g_localPlayer;
static CRITICAL_SECTION g_lock;
static int              g_nextId = 1;

static void fillWide(const char *src, wchar_t *dst, size_t dstChars) {
  size_t i = 0;
  while (i + 1 < dstChars && src[i]) { dst[i] = (wchar_t)(unsigned char)src[i]; i++; }
  dst[i] = 0;
}

static Entity *spawnEntity(const char *type, int kind) {
  /* kind selects a "subclass": 0 Player, 1 NPC, 2 Item, 3 Projectile,
   * 4 Vehicle, 5 Prop, 6 Drone, 7 Turret — all share the Entity vtable and
   * append a distinct subclass blob after +0x98 (total 0xB0 bytes). */
  Entity *e = (Entity *)calloc(1, 0xB0);
  snprintf(e->name, 32, "%s_%03d", type, g_nextId);
  fillWide(e->name, e->displayName, 32);
  e->vtable    = &g_entityVTable;
  e->id        = g_nextId++;
  e->pos[0]    = (float)(rand() % 2000 - 1000) / 10.0f;
  e->pos[1]    = (float)(rand() % 2000 - 1000) / 10.0f;
  e->pos[2]    = (float)(rand() % 400) / 10.0f;
  e->maxHealth = 100.0f;
  e->health    = 30.0f + (float)(rand() % 70);
  e->team      = kind % 3;
  e->flags     = 1ull | ((uint64_t)kind << 8); /* alive + kind in byte 1 */
  Inventory *inv = (Inventory *)calloc(1, sizeof(Inventory));
  inv->money   = 100.0f + (float)(rand() % 900);
  for (int i = 0; i < 16; i++) inv->slots[i] = rand() % 99;
  e->inv       = inv;
  /* subclass blob at +0x98 — kind-discriminating data so derived-class
   * fields differ per type (like real C++ subclass layouts). */
  unsigned char *sub = (unsigned char *)e + 0x98;
  memset(sub, kind + 1, 8);
  *(int32_t *)sub = 0xA00 + kind; /* subclass "type id" */
  return e;
}

/* Free a heap entity (inv subobject first, like a real dtor). */
static void killEntity(int idx) {
  Entity *e = g_entArray[idx];
  free(e->inv);
  free(e);
  g_entArray[idx] = g_entArray[g_entities->count - 1];
  g_entArray[g_entities->count - 1] = NULL;
  g_entities->count--;
}

static void addEntity(Entity *e) {
  if (g_entities->count >= MAX_ENTITIES) return;
  g_entArray[g_entities->count++] = e;
}

static DWORD WINAPI simThread(LPVOID _) {
  static const char *types[8] = {
    "Player", "NPC", "Item", "Projectile", "Vehicle", "Prop", "Drone", "Turret",
  };
  float camAngle = 0.0f;
  (void)_;
  for (;;) {
    Sleep(TICK_MS);
    EnterCriticalSection(&g_lock);
    /* churn: keep count oscillating 4-16 */
    if (g_entities->count < MIN_ENTITIES ||
        (g_entities->count < MAX_ENTITIES && (rand() % 3) == 0)) {
      int kind = rand() % 8;
      addEntity(spawnEntity(types[kind], kind));
    } else if ((rand() % 4) == 0 && g_entities->count > MIN_ENTITIES) {
      int idx = rand() % g_entities->count;
      Entity *victim = g_entArray[idx];
      if (victim != g_localPlayer) killEntity(idx);
    }
    /* drift + regen */
    for (int i = 0; i < g_entities->count; i++) {
      Entity *e = g_entArray[i];
      e->pos[0] += ((float)(rand() % 200 - 100)) / 50.0f;
      e->pos[1] += ((float)(rand() % 200 - 100)) / 50.0f;
      if (e->health < e->maxHealth) e->health += 1.5f;
      if (e->health > e->maxHealth) e->health = e->maxHealth;
      e->flags = (e->flags & ~(uint64_t)2) |
                 ((uint64_t)(rand() & 1) << 1); /* flicker "visible" bit */
    }
    /* camera orbits the origin -> viewMatrix changes every tick */
    camAngle += 0.03f;
    {
      float *m = g_engine->world->viewMatrix;
      float c = cosf(camAngle), s = sinf(camAngle);
      memset(m, 0, 16 * sizeof(float));
      m[0] = c;   m[2] = -s;  m[5] = 1.0f; m[8] = s;   m[10] = c;
      m[14] = -5.0f + 2.0f * s; /* dolly */
      m[15] = 1.0f;
    }
    g_engine->frame++;
    g_engine->uptime += TICK_MS;
    LeaveCriticalSection(&g_lock);
  }
  return 0;
}

/* Code-page reference to g_engine — "48 8B 05 <rel32>" (mov rax,[rip+x]).
 * Real function, called once, so the bytes actually live in .text and
 * scanUnique finds exactly one hit. */
static GameEngine *getEngine(void) { return (GameEngine *)g_engine; }

int main(void) {
  InitializeCriticalSection(&g_lock);
  srand(1337);

  GameEngine *eng = (GameEngine *)calloc(1, sizeof(GameEngine));
  World      *w   = (World *)calloc(1, sizeof(World));
  EntityList *el  = (EntityList *)calloc(1, sizeof(EntityList));
  Entity    **arr = (Entity **)calloc(ENT_ARRAY_CAP, sizeof(Entity *));
  NetworkState *net = (NetworkState *)calloc(1, sizeof(NetworkState));

  strcpy_s(w->name, 32, "mpv2_world");
  el->array = arr;
  el->capacity = ENT_ARRAY_CAP;
  w->entities = el;
  net->tickRate = 20;
  strcpy_s(net->serverName, 32, "mpv2-sim-01");
  eng->world = w;
  eng->net = net;
  g_engine = eng;
  g_entities = el;
  g_entArray = arr;

  Entity *player = spawnEntity("LocalPlayer", 0);
  player->health = player->maxHealth = 100.0f;
  player->team = 0;
  g_localPlayer = player;
  w->localPlayer = player;
  addEntity(player);
  for (int i = 1; i < 8; i++) {
    static const char *t[8] = {
      "Player", "NPC", "Item", "Projectile", "Vehicle", "Prop", "Drone", "Turret",
    };
    addEntity(spawnEntity(t[i], i));
  }

  /* PAGE_GUARD region: first page 0xC5, second page guard. */
  void *guard = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  void *guardEnd = NULL;
  if (guard) {
    DWORD oldp;
    memset(guard, 0xC5, 0x1000);
    VirtualProtect((BYTE *)guard + 0x1000, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldp);
    guardEnd = (BYTE *)guard + 0x2000;
  }

  /* Sanity-check the documented offsets against this build. */
  if (offsetof(Entity, health) != 0x38 || offsetof(Entity, inv) != 0x90 ||
      offsetof(World, entities) != 0x20 || offsetof(World, viewMatrix) != 0x40 ||
      offsetof(World, localPlayer) != 0x28 || offsetof(GameEngine, world) != 0x18 ||
      offsetof(GameEngine, net) != 0x30 || offsetof(Inventory, money) != 0x40) {
    fprintf(stderr, "layout drift!\n");
    return 1;
  }

  volatile GameEngine *e0 = getEngine(); /* keep the rip-ref alive in .text */
  (void)e0;

  CreateThread(NULL, 0, simThread, NULL, 0, NULL);

  /* Wait for the first tick so count/viewMatrix are already live. */
  Sleep(TICK_MS * 3);

  printf("PID=%lu\n", GetCurrentProcessId());
  printf("&g_engine=%p &g_marker=%p\n", &g_engine, &g_marker);
  printf("&g_engineObj=%p &g_world=%p &g_entities=%p &g_entArray=%p &g_localPlayer=%p\n",
         g_engine, w, el, arr, g_localPlayer);
  printf("&g_viewMatrix=%p &g_net=%p &g_vtable=%p &g_guard=%p &g_guard_end=%p\n",
         w->viewMatrix, net, &g_entityVTable, guard, guardEnd);
  printf("&g_count=%p\n", &el->count);
  fflush(stdout);
  for (;;) Sleep(1000);
  return 0;
}
