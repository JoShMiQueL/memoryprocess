// Compile tests/victim.c + tests/gamevictim.c -> .exe using MSVC (cl).
// Locates vcvars via vswhere so it works without a VS dev prompt.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const vswhere = `${process.env['ProgramFiles(x86)']}\\Microsoft Visual Studio\\Installer\\vswhere.exe`;
if (!existsSync(vswhere)) {
  console.error('vswhere not found — Visual Studio Build Tools required');
  process.exit(1);
}
const vsPath = spawnSync(
  vswhere,
  [
    '-latest',
    '-products',
    '*',
    '-requires',
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    '-property',
    'installationPath',
  ],
  { encoding: 'utf8' },
).stdout.trim();
const vcvars = join(vsPath, 'VC', 'Auxiliary', 'Build', 'vcvars64.bat');

let failed = false;
for (const name of ['victim', 'gamevictim']) {
  const src = join(root, 'tests', `${name}.c`);
  const out = join(root, 'tests', `${name}.exe`);
  const r = spawnSync(`"${vcvars}" && cl "${src}" /Fe:"${out}" /nologo`, {
    shell: true,
    stdio: 'inherit',
  });
  if (r.status !== 0 || !existsSync(out)) {
    console.error(`${name}.c failed to compile`);
    failed = true;
  } else {
    console.log(`built tests/${name}.exe`);
  }
}
process.exit(failed ? 1 : 0);
