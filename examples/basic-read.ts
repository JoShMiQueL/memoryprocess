// basic-read.ts — open notepad, enumerate modules, read a typed value.
// Run: bun examples/basic-read.ts   (start notepad.exe first)
import { Process } from '../src/index.js';

const info = Process.find('notepad');
if (!info) {
  console.error('notepad.exe not running — start it and retry');
  process.exit(1);
}

using proc = Process.open(info.pid);
console.log(
  `opened notepad.exe pid=${proc.pid} wow64=${proc.isWow64} ptr=${proc.pointerSize}`,
);

// list loaded modules
for (const m of proc.modules()) {
  const name = m.path.split(/[\\/]/).pop();
  console.log(
    `  ${name}  base=0x${m.base.toString(16)}  size=0x${m.size.toString(16)}`,
  );
}

// read the PE magic of the main module — should be 'MZ' (0x5A4D)
const main = proc.modules()[0]!;
const mz = proc.readUInt16(main.base);
console.log(
  `main module magic: 0x${mz.toString(16)} (${mz === 0x5a4d ? 'MZ ok' : 'unexpected'})`,
);
