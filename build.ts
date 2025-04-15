interface BuildOptions {
  arch?: 'x64' | 'ia32';
  debug?: boolean;
  clean?: boolean;
}

function formatTime(ms: number): string {
  return `${(ms / 1000).toFixed(2)}s`;
}

function log(message: string, type: 'info' | 'success' | 'error' = 'info') {
  const colors = {
    info: '\x1b[36m',    // cyan
    success: '\x1b[32m', // green
    error: '\x1b[31m',   // red
    reset: '\x1b[0m'
  };
  console.log(`${colors[type]}${message}${colors.reset}`);
}

async function execCommand(command: string[], cwd?: string): Promise<undefined> {
  const startTime = performance.now();
  const proc = Bun.spawnSync(command, { cwd });
  
  if (proc.exitCode !== 0) {
    const error = new Error(`Command failed: ${command.join(' ')}\n${proc.stderr.toString()}`);
    log(error.message, 'error');
    log(proc.stderr.toString(), 'error');
    throw error;
  }
  
  const duration = performance.now() - startTime;
  return;
}

async function build(options: BuildOptions = {}) {
  const startTime = performance.now();
  const {
    arch = 'x64',
    debug = false,
    clean = true
  } = options;

  log('🚀 Building @joshmiquel/memoryjs...', 'info');

  try {
    // Build native module
    const nodeGypArgs = ['node-gyp'];
    if (clean) nodeGypArgs.push('clean');
    nodeGypArgs.push('configure', 'build', `--arch=${arch}`);
    if (debug) nodeGypArgs.push('--debug');
    
    await execCommand(nodeGypArgs);
    log('✓ Native module built', 'success');

    // Build TypeScript files with Bun
    await Bun.build({
      entrypoints: [
        'index.ts',
        'src/debugger.ts',
        'src/types.ts',
        'src/utils.ts'
      ],
      outdir: 'lib',
      target: 'node',
      splitting: true,
      minify: !debug
    });
    log('✓ TypeScript files built', 'success');

    // Run these tasks sequentially
    // Clean build directory
    await execCommand(['rm', '-rf', 'build']);
    
    // Generate TypeScript declaration files
    await execCommand(['tsc']);
    
    // Generate API documentation
    await execCommand(['api-extractor', 'run', '--local']);

    // Clean temporary types
    await execCommand(['rm', '-rf', 'temptypes']);

    const totalTime = performance.now() - startTime;
    log(`✨ Build completed in ${formatTime(totalTime)}`, 'success');
  } catch (error) {
    log(`Build failed: ${error.message}`, 'error');
    process.exit(1);
  }
}

// Run build if this is the main module
if (import.meta.path === Bun.main) {
  await build();
}

export { build, BuildOptions };
