// 1. Build native code using node-gyp
// 2. Copy .node file from build/Release to src/
// 3. Build with bun.build
// 4. Build types with tsc
// 5. Bundle types with api-extractor
// 6. Remove all .d.ts files from lib/ folder except index.d.ts
// 7. Remove .node file from src/
// 8. Remove build/ folder
// 9. Remove all remaining empty folders from lib/ folder

import path from "path";
import { Extractor, ExtractorConfig, ExtractorResult } from '@microsoft/api-extractor';

function log(message: any, type: 'info' | 'success' | 'error' | 'warning' = 'info') {
  const colors = {
    info: '\x1b[36m',     // cyan
    success: '\x1b[32m',  // green
    error: '\x1b[31m',    // red
    warning: '\x1b[33m'   // yellow
  };
  
  let prefix = '';
  if (process.stdout.isTTY) {
    if (type === 'success') {
      prefix = '✓ ';
    } else if (type === 'info') {
      prefix = 'ℹ ';
    } else if (type === 'error') {
      prefix = '✗ ';
    } else if (type === 'warning') {
      prefix = '⚠ ';
    }
  }
  
  const coloredMessage = `${colors[type]}${prefix}${message}\x1b[0m`;
  
  if (type === 'error') {
    console.error(coloredMessage);
  } else if (type === 'warning') {
    console.warn(coloredMessage);
  } else if (type === 'info') {
    console.info(coloredMessage);
  } else {
    console.log(coloredMessage);
  }
}

function logWithTime(message: string, startTime: number, type: 'info' | 'success' | 'error' | 'warning' = 'success') {
  const elapsedMs = performance.now() - startTime;
  let timeString: string;
  
  if (elapsedMs < 1000) {
    timeString = `${Math.round(elapsedMs)}ms`;
  } else {
    const seconds = elapsedMs / 1000;
    timeString = seconds < 60 
      ? `${seconds.toFixed(2)}s` 
      : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  }
  
  log(`${message} \x1b[90m[${timeString}]\x1b[0m`, type);
}

const srcGlob = new Bun.Glob("src/**/*.ts");

try {
  // 1. Build native code using node-gyp
  const startTime = performance.now();
  log("Starting native build...", "info");
  
  const result = Bun.spawnSync(["node-gyp", "clean", "configure", "build", "--arch", "x64"]);
  if (result.exitCode !== 0) {
    log(`Native build failed with exit code ${result.exitCode}`, "error");
    throw new Error(`node-gyp build failed: ${result.stderr.toString()}`);
  }
  
  logWithTime("Native build completed", startTime, "success");

  // 2. Copy .node file from build/Release to src/
  const copyStartTime = performance.now();
  log("Copying native module to src directory...", "info");
  
  const copyResult = Bun.spawnSync(["cp", "build/Release/native.node", "src/"]);
  if (copyResult.exitCode !== 0) {
    log(`Failed to copy native module: ${copyResult.stderr.toString()}`, "error");
    throw new Error("Failed to copy native module");
  }
  logWithTime("Native module copied successfully", copyStartTime, "success");

  // 3. Build with bun.build
  const bundleStartTime = performance.now();
  log("Starting TypeScript build...", "info");
  const entryFiles = [
    "index.ts",
    ...await Array.fromAsync(srcGlob.scan()),
    "src/native.node"
  ];
  log(`Found ${entryFiles.length} entry files for bundling`, "info");

  const buildResult = await Bun.build({
    entrypoints: entryFiles,
    outdir: "lib",
    minify: true,
    target: "node"
  });

  if (!buildResult.success) {
    log(`Build failed with ${buildResult.logs.length} errors`, "error");
    for (const logItem of buildResult.logs) {
      log(logItem.message, "error");
    }
    throw new Error("TypeScript build failed");
  }

  logWithTime(`Build completed successfully (${buildResult.outputs.length} files)`, bundleStartTime, "success");

  // 4. Build types with tsc
  const typesStartTime = performance.now();
  log("Starting types build...", "info");
  
  const tscResult = Bun.spawnSync(["tsc", "--project", "tsconfig.json"]);
  if (tscResult.exitCode !== 0) {
    log(`Types build failed: ${tscResult.stderr.toString()}`, "error");
    throw new Error("Types build failed");
  }
  logWithTime("Types build completed", typesStartTime, "success");

  // 5. Bundle types with api-extractor
  const bundleTypesStartTime = performance.now();
  log("Starting types bundle...", "info");

  const apiExtractorJsonPath: string = path.join(__dirname, '..', 'config', 'api-extractor.json');

  const extractorConfig: ExtractorConfig = ExtractorConfig.loadFileAndPrepare(apiExtractorJsonPath);

  const extractorResult: ExtractorResult = Extractor.invoke(extractorConfig, {
    localBuild: true,
  });
  
  if (extractorResult.succeeded) {
    if (extractorResult.warningCount && extractorResult.warningCount > 0) {
      logWithTime(`Types bundle completed with ${extractorResult.warningCount} warnings`, bundleTypesStartTime, "warning");
    } else {
      logWithTime("Types bundle completed", bundleTypesStartTime, "success");
    }
  } else {
    logWithTime(`Types bundle failed with ${extractorResult.errorCount} errors`, bundleTypesStartTime, "error");
    throw new Error("Types bundle failed");
  }

  // 6. Remove all .d.ts files from lib/ folder except index.d.ts
  const removeTypesStartTime = performance.now();
  log("Starting types cleanup...", "info");
  
  const removeTypesResult = Bun.spawnSync(["find", "lib", "-name", "*.d.ts", "-not", "-name", "index.d.ts", "-delete"]);
  if (removeTypesResult.exitCode !== 0) {
    log(`Failed to remove types: ${removeTypesResult.stderr.toString()}`, "warning");
  } else {
    logWithTime("Types cleanup completed", removeTypesStartTime, "success");
  }

  // 7. Remove .node file from src/
  const cleanupStartTime = performance.now();
  log("Cleaning up temporary native module...", "info");
  
  const cleanupResult = Bun.spawnSync(["rm", "src/native.node"]);
  if (cleanupResult.exitCode !== 0) {
    log(`Failed to remove temporary native module: ${cleanupResult.stderr.toString()}`, "warning");
  } else {
    logWithTime("Native module cleanup completed", cleanupStartTime, "success");
  }

  // 8. Remove build/ folder
  const finalCleanupStartTime = performance.now();
  log("Removing build/ directory...", "info");
  
  const finalCleanupResult = Bun.spawnSync(["rm", "-rf", "build"]);
  if (finalCleanupResult.exitCode !== 0) {
    log(`Failed to remove build/ directory: ${finalCleanupResult.stderr.toString()}`, "warning");
  } else {
    logWithTime("Successfully removed build/ directory", finalCleanupStartTime, "success");
  }

  // 9. Remove all remaining empty folders from lib/ folder
  const removeEmptyFoldersStartTime = performance.now();
  log("Starting empty folders cleanup...", "info");
  
  const removeEmptyFoldersResult = Bun.spawnSync(["find", "lib", "-type", "d", "-empty", "-delete"]);
  if (removeEmptyFoldersResult.exitCode !== 0) {
    log(`Failed to remove empty folders: ${removeEmptyFoldersResult.stderr.toString()}`, "warning");
  } else {
    logWithTime("Empty folders cleanup completed", removeEmptyFoldersStartTime, "success");
  }
  
  logWithTime("Total build process completed", startTime, "success");
} catch (e) {
  const error = e as AggregateError;
  log("Build Failed", "error");

  // Example: Using the built-in formatter
  log(error, "error");

  // Example: Serializing the failure as a JSON string.
  log(JSON.stringify(error, null, 2), "error");
  process.exit(1);
}
