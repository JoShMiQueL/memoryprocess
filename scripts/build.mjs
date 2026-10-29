// Cross-platform build: node-gyp -> tsdown -> tsc emit types -> copy .node
// Runs under `bun run build` or `node scripts/build.mjs`.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const isWin = process.platform === 'win32';
const run = (cmd, args, shellCmd = false) => {
  const r = shellCmd
    ? spawnSync(cmd, { cwd: root, stdio: 'inherit', shell: true })
    : spawnSync(cmd, args, { cwd: root, stdio: 'inherit' });
  if (r.status !== 0)
    throw new Error(`${cmd} ${args.join(' ')} failed (${r.status})`);
};

// resolve a node_modules tool's JS entrypoint (portable, no .bin shim needed)
const tool = (pkg, binPath) => join(root, 'node_modules', pkg, binPath);
const nodeGypJs = tool('node-gyp', 'bin/node-gyp.js');
const nodeGyp = () => {
  run(process.execPath, [nodeGypJs, 'clean']);
  run(process.execPath, [nodeGypJs, 'configure', '--arch', 'x64']);
  run(process.execPath, [nodeGypJs, 'build']);
};

const t = (label, fn) => {
  const s = performance.now();
  fn();
  console.log(`✓ ${label} [${Math.round(performance.now() - s)}ms]`);
};

try {
  t('node-gyp build', () => nodeGyp());

  const native = join(root, 'build', 'Release', 'memoryprocess.node');
  if (!existsSync(native)) throw new Error('memoryprocess.node not produced');

  mkdirSync(join(root, 'dist'), { recursive: true });

  // tsdown cleans dist/ before writing — run it BEFORE copying the .node
  t('tsdown bundle', () =>
    run(process.execPath, [
      tool('tsdown', 'dist/run.mjs'),
      'src/index.ts',
      '--format',
      'esm',
      '--out-dir',
      'dist',
      '--no-dts',
    ]),
  );

  // normalize: index.mjs -> index.js so `main: dist/index.js` resolves
  t('rename index.mjs -> index.js', () => {
    cpSync(join(root, 'dist', 'index.mjs'), join(root, 'dist', 'index.js'), {
      force: true,
    });
    rmSync(join(root, 'dist', 'index.mjs'), { force: true });
  });

  t('tsc emit .d.ts', () =>
    run(process.execPath, [
      tool('typescript', 'bin/tsc'),
      '--project',
      'tsconfig.json',
    ]),
  );

  t('copy .node to dist', () =>
    cpSync(native, join(root, 'dist', 'memoryprocess.node')),
  );

  t('clean build dir', () =>
    rmSync(join(root, 'build'), { recursive: true, force: true }),
  );
  console.log('✓ build complete');
} catch (e) {
  console.error('✗ build failed:', e.message);
  process.exit(1);
}
