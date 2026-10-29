// inject-dll.ts — inject a DLL into a target process and eject it again.
// Run: bun examples/inject-dll.ts <pid-or-name> <abs-path-to.dll>
import { Process, InjectError } from '../src/index.js';

const [target, dllPath] = process.argv.slice(2);
if (!target || !dllPath) {
  console.error(
    'usage: bun examples/inject-dll.ts <pid-or-name> <abs-path-to.dll>',
  );
  process.exit(1);
}

using proc = Process.open(/^\d+$/.test(target) ? Number(target) : target);

try {
  // injectDll spawns a remote thread on kernel32!LoadLibraryA(absPath).
  // The path must be absolute and readable by the target process.
  proc.injectDll(dllPath);
  console.log(`injected ${dllPath}`);

  // the loader needs a moment — poll until the module shows up
  const dllName = dllPath.split(/[\\/]/).pop()!;
  let mod;
  for (let i = 0; i < 50 && !mod; i++) {
    mod = proc.module(dllName);
    if (!mod) await Bun.sleep(100);
  }
  if (!mod)
    throw new Error('module never appeared — injection may have failed');
  console.log(
    `loaded at base=0x${mod.base.toString(16)} size=0x${mod.size.toString(16)}`,
  );

  // ... do work while the DLL is resident ...

  // eject via FreeLibrary on a remote thread (name substring or ModuleInfo)
  proc.ejectDll(mod);
  console.log('ejected');
} catch (e) {
  if (e instanceof InjectError) {
    console.error(`injection failed: ${e.message} (win32=${e.win32code})`);
  } else {
    throw e;
  }
}
