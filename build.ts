import { $ } from "bun";
import { Extractor, ExtractorConfig, ExtractorResult } from '@microsoft/api-extractor';
import * as fs from 'fs/promises'; 
import * as path from 'path'; 

export const TEMP_DLL_PATH = "_temp_dllmemproc";
export const BUILD_PATH = "lib";

const apiExtractorJsonPath: string = path.join(import.meta.dir, 'config', 'api-extractor.json');

interface BuildOptions {
  outdir?: string;
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

async function build(options: BuildOptions = {}) {
  const startTime = performance.now();
  let buildSuccess = false; 

  const { outdir = BUILD_PATH } = options;
  const tempDllFilePath = path.join(TEMP_DLL_PATH, 'memoryprocess.dll');
  const finalDllPath = path.join(outdir, 'memoryprocess.dll');

  log('🚀 Building MemoryProcess...', 'info');

  try {
    await fs.mkdir(outdir, { recursive: true });
    await fs.mkdir(TEMP_DLL_PATH, { recursive: true });
    log('✓ Directories ensured', 'success');


    await $`zig build-lib native/*.cc -dynamic -target x86_64-windows-gnu -lc -lc++ -femit-bin=${tempDllFilePath}`;
    log('✓ Native module built', 'success');

    await fs.copyFile(tempDllFilePath, finalDllPath);
    log(`✓ Copied DLL to ${finalDllPath}`, 'success');

    await Bun.build({
      entrypoints: [
        "src/index.ts"
      ],
      outdir,
      target: 'bun',
      splitting: false,
      minify: true,
      external: ["*.dll"]
    });
    log('✓ TypeScript files built', 'success');

    // Create the node-error.js file for Node.js environments
    const nodeErrorContent = `throw new Error('The "memoryprocess" package requires the Bun runtime (https://bun.sh) and is not compatible with Node.js.');`;
    const nodeErrorPath = path.join(outdir, 'node-error.js');
    await fs.writeFile(nodeErrorPath, nodeErrorContent);
    log('✓ Node.js error file created', 'success');

    await $`bunx tsc`;
    log("✓ TypeScript declaration files generated", "success")
 
    const extractorConfig: ExtractorConfig = ExtractorConfig.loadFileAndPrepare(apiExtractorJsonPath);

    const extractorResult: ExtractorResult = Extractor.invoke(extractorConfig, {
      localBuild: true,
    });

    if (extractorResult.succeeded) {
      log("✓ API Extractor completed", "success");
      buildSuccess = true; 
    } else {
      log(
        `API Extractor completed with ${extractorResult.errorCount} errors` +
          ` and ${extractorResult.warningCount} warnings`, "error"
      );
      buildSuccess = false; 
    }

    const totalTime = performance.now() - startTime;
    if (buildSuccess) {
        log(`✨ Build completed successfully in ${formatTime(totalTime)}`, 'success');
    } else {
        log(` Build failed after ${formatTime(totalTime)}`, 'error');
    }


  } catch (error) {
    buildSuccess = false; 
    if (error instanceof Error) {
      log(`Build failed: ${error.message}`, 'error');
    } else {
      log(`Build failed: ${String(error)}`, 'error');
    }
    console.error(error); 

  } finally {
    try {
        await fs.rm(TEMP_DLL_PATH, { recursive: true, force: true });
        log('✓ Temporary directory cleaned up', 'info');
    } catch (cleanupError) {
        log(`Failed to clean up temporary directory: ${cleanupError}`, 'error');
    }
    process.exit(buildSuccess ? 0 : 1);
  }
}

if (import.meta.path === Bun.main) {
  await build();
}

export { build, BuildOptions };
