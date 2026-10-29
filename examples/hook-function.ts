// hook-function.ts — divert a remote function to your own code with a
// 5-byte E9 detour + trampoline, then restore it.
//
// The demo is self-contained: we allocate RWX memory inside the target,
// write a fake "target function" (returns 42) and a fake "hook function"
// (returns 99), then drive it with callRemote so you can watch the
// return value change. In a real scenario `src` would be an address you
// found via proc.scan()/module exports and `dst` your payload in a code
// cave or injected module.
//
// Run: bun examples/hook-function.ts <pid-or-name>
import { Process, Protection } from '../src/index.js';

const target = process.argv[2] ?? 'notepad.exe';
using proc = Process.open(/^\d+$/.test(target) ? Number(target) : target);

// x64 stubs: mov eax,imm32; ret
const RET_42 = Buffer.from([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]);
const RET_99 = Buffer.from([0xb8, 0x63, 0x00, 0x00, 0x00, 0xc3]);

const addr = proc.alloc(0x1000, Protection.EXECUTE_READWRITE);
const src = addr; // "target function"
const dst = addr + 0x100n; // "hook function"
try {
  proc.writeBuffer(src, RET_42);
  proc.writeBuffer(dst, RET_99);

  // baseline — remote call runs the original code
  console.log('before hook:', proc.callRemote(src, 0)); // 42

  // hook() steals >=5 whole bytes at src (never splits an instruction),
  // copies them into a trampoline stub ending with a jump back to
  // src+stolen, and writes E9 rel32: src -> dst.
  const h = proc.hook(src, dst);
  console.log(
    `hooked 0x${h.src.toString(16)} -> 0x${h.dst.toString(16)}; ` +
      `stub at 0x${h.stub.toString(16)}, stole ${h.stolen.length} bytes: ${h.stolen.toString('hex')}`,
  );

  // diverted — the remote call now runs our hook
  console.log('after hook:', proc.callRemote(src, 0)); // 99

  // Calling the hook in a real patch? Invoke h.stub to run the original
  // (stolen instructions + jump back):
  //   proc.callRemote(h.stub, 0) → 42

  // unhook() writes the stolen bytes back over the E9 and frees the stub.
  proc.unhook(h);
  console.log('restored:', proc.callRemote(src, 0)); // 42
} finally {
  proc.free(addr);
}

// Thread safety: in a real target, wrap the hook/unhook in
// proc.suspendAll() / proc.resumeAll() so no thread executes src while
// you're mid-patch.
