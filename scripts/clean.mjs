import { rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
for (const d of ['build', 'dist', 'prebuilds'])
  rmSync(join(root, d), { recursive: true, force: true });
console.log('cleaned build/, dist/, prebuilds/');
