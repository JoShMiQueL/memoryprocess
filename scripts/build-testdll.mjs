// Compile tests/testdll.c -> tests/testdll.dll using MSVC (cl /LD).
// Locates vcvars via vswhere so it works without a VS dev prompt.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'tests', 'testdll.c');
const out = join(root, 'tests', 'testdll.dll');

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

const r = spawnSync(`"${vcvars}" && cl "${src}" /LD /Fe:"${out}" /nologo`, {
  shell: true,
  stdio: 'inherit',
});
if (r.status !== 0 || !existsSync(out)) {
  console.error('testdll.c failed to compile');
  process.exit(1);
}
console.log('built tests/testdll.dll');
