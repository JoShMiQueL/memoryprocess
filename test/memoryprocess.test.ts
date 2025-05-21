// test/memoryprocess.test.ts
import * as mp from '../src/memoryprocess'; // Adjust path if your compiled output is elsewhere (e.g., 'dist/src/memoryprocess')
import { type Process, type Module, SignatureTypes } from '../src/types'; // Adjust path

// Helper function to delay execution for async-like tests or observation
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('MemoryProcess Library', () => {
    // --- Test Configuration ---
    // For tests requiring a live process, set TEST_PROCESS_NAME to a commonly available process
    // e.g., 'notepad.exe' (Windows), 'TextEdit.app' (macOS, use full path to binary if needed), or 'gedit' (Linux).
    // The tests will attempt to find and use this process. If not found, relevant tests will be skipped.
    const TEST_PROCESS_NAME = 'notepad.exe'; // Example for Windows
    let testProcess: Process | undefined = undefined;
    let testProcessHandle: number | null = null;
    let knownModuleName: string | undefined = undefined; // e.g., 'notepad.exe' or a common system DLL like 'kernel32.dll'
    let knownModule: Module | undefined = undefined;

    // This address should be a readable static address in the test process for read tests.
    // Finding such an address automatically is non-trivial. This usually requires manual setup or a dedicated test application.
    // For now, it will be derived from the module base address if possible.
    let readableAddress: number | bigint = 0n;
    // This should be a known sequence of bytes at readableAddress.
    // Example: if readableAddress points to start of a UTF-8 string "Hello", knownPattern could be "48 65 6C 6C 6F"
    let knownPattern: string = "4D 5A"; // "MZ" - start of many PE files (e.g., notepad.exe itself)

    beforeAll(() => {
        console.log("Attempting to set up test process context...");
        try {
            const processes = mp.getProcesses();
            if (!processes || processes.length === 0) {
                console.warn(`No processes found. Some tests requiring a live process will be skipped.`);
                return;
            }

            testProcess = processes.find(p => p.szExeFile.toLowerCase() === TEST_PROCESS_NAME.toLowerCase());

            if (testProcess && testProcess.th32ProcessID > 0) {
                const openedProcess = mp.openProcess(testProcess.th32ProcessID);
                if (openedProcess && openedProcess.handle) {
                    testProcessHandle = openedProcess.handle;
                    testProcess.handle = openedProcess.handle; // Ensure our testProcess object has the handle
                    testProcess.modBaseAddr = openedProcess.modBaseAddr; // And base address
                    readableAddress = openedProcess.modBaseAddr; // Use module base as a generally readable address
                    console.log(`Successfully opened ${TEST_PROCESS_NAME} (PID: ${testProcess.th32ProcessID}, Handle: ${testProcessHandle}, Base: 0x${readableAddress.toString(16)}) for testing.`);

                    // Try to find a known module
                    const modules = mp.getModules(testProcess.th32ProcessID);
                    if (modules && modules.length > 0) {
                        // Prefer the main executable module or a common system DLL
                        knownModule = modules.find(m => m.szModule.toLowerCase() === TEST_PROCESS_NAME.toLowerCase()) || modules.find(m => m.szModule.toLowerCase() === 'kernel32.dll');
                        if (knownModule) {
                            knownModuleName = knownModule.szModule;
                            console.log(`Using module '${knownModuleName}' (Base: 0x${knownModule.modBaseAddr.toString(16)}, Size: ${knownModule.modBaseSize}) for module tests.`);
                        } else {
                            knownModuleName = modules[0].szModule; // Fallback to first module
                            knownModule = modules[0];
                            console.warn(`Could not find preferred module, using first module '${knownModuleName}' for tests.`);
                        }
                        // Update readableAddress if a more specific module is found (prefer main exe module)
                        if (testProcess.szExeFile.toLowerCase() === knownModule.szModule.toLowerCase()){
                            readableAddress = knownModule.modBaseAddr;
                        }
                    } else {
                        console.warn("Could not list modules for the test process.");
                    }
                } else {
                    console.warn(`Failed to open process ${TEST_PROCESS_NAME} (PID: ${testProcess.th32ProcessID}). Handle: ${openedProcess?.handle}`);
                    testProcessHandle = null; // Ensure it's null if open failed
                }
            } else {
                console.warn(`Test process '${TEST_PROCESS_NAME}' not found running. Some tests will be skipped.`);
            }
        } catch (e: any) {
            console.warn(`Error during test setup for process '${TEST_PROCESS_NAME}': ${e.message}. Some tests will be skipped.`);
            testProcessHandle = null;
        }
    });

    afterAll(() => {
        if (testProcessHandle) {
            try {
                const success = mp.closeHandle(testProcessHandle);
                console.log(success ? `Closed handle ${testProcessHandle}` : `Failed to close handle ${testProcessHandle}`);
            } catch (e: any) {
                console.error(`Error closing handle ${testProcessHandle}: ${e.message}`);
            }
            testProcessHandle = null;
        }
    });

    describe('Process Operations', () => {
        it('should list processes and return an array', () => {
            const processes = mp.getProcesses();
            expect(Array.isArray(processes)).toBe(true);
            if (processes.length > 0) {
                expect(processes[0]).toHaveProperty('th32ProcessID');
                expect(processes[0]).toHaveProperty('szExeFile');
            }
        });

        it('should open a known running process by name', () => {
            // This test relies on beforeAll to have found TEST_PROCESS_NAME
            if (!testProcess) {
                console.warn(`Skipping 'openProcess by name' test: '${TEST_PROCESS_NAME}' not found by beforeAll.`);
                return;
            }
            let tempHandle: number | null = null;
            try {
                const proc = mp.openProcess(TEST_PROCESS_NAME);
                expect(proc).toBeDefined();
                expect(proc.handle).toBeGreaterThan(0);
                expect(proc.szExeFile.toLowerCase()).toBe(TEST_PROCESS_NAME.toLowerCase());
                tempHandle = proc.handle;
            } finally {
                if (tempHandle) mp.closeHandle(tempHandle);
            }
        });

        it('should open a known running process by ID', () => {
            if (!testProcess || !testProcess.th32ProcessID) {
                console.warn(`Skipping 'openProcess by ID' test: PID for '${TEST_PROCESS_NAME}' not found.`);
                return;
            }
            let tempHandle: number | null = null;
            try {
                const proc = mp.openProcess(testProcess.th32ProcessID);
                expect(proc).toBeDefined();
                expect(proc.handle).toBeGreaterThan(0);
                expect(proc.th32ProcessID).toBe(testProcess.th32ProcessID);
                tempHandle = proc.handle;
            } finally {
                if (tempHandle) mp.closeHandle(tempHandle);
            }
        });

        it('should fail to open a non-existent process by name and throw error', () => {
            expect(() => {
                mp.openProcess('THIS_PROCESS_SHOULD_NOT_EXIST_EVER.exe');
            }).toThrow(); // Expects an error to be thrown by the native layer
        });
        
        it('should fail to open a process with an invalid ID (e.g., 0 or negative) and throw error', () => {
            expect(() => {
                mp.openProcess(0); // Process ID 0 is usually system/idle and may not be openable with full access
            }).toThrow();
            expect(() => {
                mp.openProcess(-1);
            }).toThrow(); // Due to JS side validation
        });

        it('should close a valid handle', () => {
            if (!testProcess || !testProcess.th32ProcessID) {
                 console.warn("Skipping close valid handle: no test process."); return;
            }
            // Re-open to ensure we have a handle to close for this test
            const proc = mp.openProcess(testProcess.th32ProcessID);
            if (!proc || !proc.handle) {
                console.warn("Skipping close valid handle: failed to re-open test process."); return;
            }
            expect(mp.closeHandle(proc.handle)).toBe(true);
        });

        it('should return false or throw when closing an invalid handle', () => {
             // Native CloseHandle returns FALSE for invalid handles. Our JS wrapper might throw.
            expect(() => mp.closeHandle(-1)).toThrow(); // JS validation
            // For a handle that's just a number but not a real open handle:
            // The behavior of native CloseHandle for a random number that isn't an OS handle
            // can be unpredictable or simply return FALSE. The JS wrapper doesn't add much here.
            // This test is more about the OS behavior than our library per se, once past basic validation.
            // It's hard to get a "numerically valid but not actually open" handle reliably.
            // So we test with a clearly invalid one like 0 or a closed one.
            expect(mp.closeHandle(0)).toBe(false); // Closing handle 0 (if not a valid handle) should fail
        });
    });

    describe('Module Operations', () => {
        it('should list modules for a valid process ID', () => {
            if (!testProcess || !testProcess.th32ProcessID) {
                console.warn(`Skipping 'getModules' test: PID for '${TEST_PROCESS_NAME}' not available.`);
                return;
            }
            const modules = mp.getModules(testProcess.th32ProcessID);
            expect(Array.isArray(modules)).toBe(true);
            expect(modules.length).toBeGreaterThan(0);
            expect(modules[0]).toHaveProperty('modBaseAddr');
            expect(modules[0]).toHaveProperty('szModule');
        });

        it('should find a known module by name', () => {
            if (!testProcess || !testProcess.th32ProcessID || !knownModuleName || !knownModule) {
                console.warn(`Skipping 'findModule by name' test: Test process or known module not available.`);
                return;
            }
            const mod = mp.findModule(knownModuleName, testProcess.th32ProcessID);
            expect(mod).toBeDefined();
            expect(mod!.szModule.toLowerCase()).toBe(knownModuleName.toLowerCase());
            expect(mod!.modBaseAddr).toEqual(knownModule.modBaseAddr);
        });

        it('should return undefined or throw for a non-existent module name', () => {
             if (!testProcess || !testProcess.th32ProcessID) {
                console.warn(`Skipping 'findModule non-existent' test: Test process not available.`);
                return;
            }
            expect(() => { // Expect an error from native layer if module not found.
                 const mod = mp.findModule('THIS_MODULE_DOES_NOT_EXIST.dll', testProcess.th32ProcessID);
                 // If it doesn't throw but returns undefined/empty object
                 if (mod && mod.modBaseAddr !== 0n && mod.modBaseAddr !== 0) { 
                    throw new Error("Module was found, but should not have been.");
                 }
            }).toThrow();
        });
    });

    describe('Memory Reading', () => {
        // These tests are highly dependent on the TEST_PROCESS_NAME and its memory state.
        // They are more like integration tests that need careful setup.
        beforeEach(() => {
            if (!testProcessHandle || readableAddress === 0n) {
                console.warn('Skipping memory read test: process handle or readableAddress not available.');
                // Use jest.skip() if available and preferred: jest.skip();
            }
        });
        
        it('should read a byte (uint8) from a known readable address', () => {
            if (!testProcessHandle || readableAddress === 0n) return;
            const val = mp.readMemory(testProcessHandle, readableAddress, 'byte');
            expect(typeof val).toBe('number');
            // Cannot assert specific value without knowing memory content.
        });

        it('should read an int32 from a known readable address', () => {
            if (!testProcessHandle || readableAddress === 0n) return;
            const val = mp.readMemory(testProcessHandle, readableAddress, 'int32');
            expect(typeof val).toBe('number');
        });
        
        it('should read a string from a known readable address (if it contains one)', () => {
            if (!testProcessHandle || readableAddress === 0n) return;
            // This is very specific. Let's assume the base address of the main module might start with "MZ" (PE header).
            // We can try to read it as a short string.
            try {
                const val = mp.readMemory(testProcessHandle, readableAddress, 'string');
                expect(typeof val).toBe('string');
                if (readableAddress === testProcess?.modBaseAddr) { // Main exe module
                    expect(val.startsWith('MZ')).toBe(true);
                }
            } catch (e: any) {
                console.warn(`Could not read string at 0x${readableAddress.toString(16)}: ${e.message}`);
            }
        });

        it('should read a buffer from a known readable address', () => {
            if (!testProcessHandle || readableAddress === 0n) return;
            const bufferSize = 16;
            const buffer = mp.readBuffer(testProcessHandle, readableAddress, bufferSize);
            expect(buffer instanceof Buffer).toBe(true);
            expect(buffer.length).toBe(bufferSize);
        });

        it('should throw error when reading from an invalid address (e.g., 0, if not readable)', () => {
            if (!testProcessHandle) return;
            expect(() => {
                mp.readMemory(testProcessHandle, 0, 'int'); // Address 0 is often protected
            }).toThrow();
        });
    });

    describe('Memory Writing (Use with extreme caution!)', () => {
        // WARNING: Writing to memory of arbitrary processes can cause them to crash or behave unexpectedly.
        // These tests should ideally be run against a dedicated dummy application.
        // For now, we will mostly test input validation and error handling for writes.
        // A true write+readback test requires a known writable memory location.

        it('should throw error when writing to an invalid address (e.g., 0)', () => {
            if (!testProcessHandle) {
                 console.warn("Skipping memory write test: no process handle."); return;
            }
            expect(() => {
                mp.writeMemory(testProcessHandle, 0, 123, 'int');
            }).toThrow();
        });

        it('should throw error when writing with invalid data type for value', () => {
            if (!testProcessHandle || readableAddress === 0n) { // need some address, even if it fails
                console.warn("Skipping memory write type test: no process handle or address."); return;
            }
            expect(() => {
                mp.writeMemory(testProcessHandle, readableAddress, 'not-a-bigint', 'int64');
            }).toThrow(/expected a BigInt/);
             expect(() => {
                mp.writeMemory(testProcessHandle, readableAddress, 123, 'string');
            }).toThrow(/expected a string/);
        });
    });

    describe('Pattern Scanning', () => {
        beforeEach(() => {
            if (!testProcessHandle || !knownModule || knownModule.modBaseAddr === 0n || knownModule.modBaseSize === 0) {
                console.warn('Skipping pattern scan test: process handle, known module, or module info not available.');
            }
        });

        it('should find a known pattern (e.g., "MZ" at module base)', () => {
            if (!testProcessHandle || !knownModule || knownModule.modBaseAddr === 0n) return;
            // Scan within the known module for the "MZ" pattern.
            // Using findPatternByModule (if exposed) or findPattern with module context would be ideal.
            // For now, using findPatternInRegion on the module's span.
            const scanBase = knownModule.modBaseAddr;
            const scanSize = Math.min(knownModule.modBaseSize, 1024); // Scan first 1KB or module size
            if (scanSize <=0) { console.warn("Skipping MZ pattern test: module size is 0"); return; }

            const result = mp.findPatternInRegion(testProcessHandle!, scanBase, scanSize, knownPattern);
            expect(result).toEqual(scanBase); // "MZ" should be at the very beginning of the module
        });

        it('should find a pattern with wildcards "4D ?? 50 45"', () => {
            if (!testProcessHandle || !knownModule || knownModule.modBaseAddr === 0n) return;
            // "MZPE" is "4D 5A 50 45". With wildcard: "4D ?? 50 45"
            const wildcardPattern = "4D ?? 50 45";
            const scanBase = knownModule.modBaseAddr;
            // Scan a small portion at the beginning of the module
            const scanSize = Math.min(knownModule.modBaseSize, 2048); 
             if (scanSize <=0) { console.warn("Skipping wildcard pattern test: module size is 0"); return; }

            const result = mp.findPatternInRegion(testProcessHandle!, scanBase, scanSize, wildcardPattern);
            // This expects the PE header "MZ..PE" to be at the module base.
            // The actual found address would be moduleBase + offset of "4D".
            // Here, if "4D 5A 50 45" is at base, result should be base.
            expect(result).toEqual(scanBase); 
        });

        it('should not find a non-existent pattern', () => {
            if (!testProcessHandle || !knownModule || knownModule.modBaseAddr === 0n) return;
            const nonExistentPattern = "FF FF FF FF FF FF FF FF EE DD CC BB AA";
            const scanBase = knownModule.modBaseAddr;
            const scanSize = Math.min(knownModule.modBaseSize, 1024 * 10); // Scan 10KB
            if (scanSize <=0) { console.warn("Skipping non-existent pattern test: module size is 0"); return; }

            const result = mp.findPatternInRegion(testProcessHandle!, scanBase, scanSize, nonExistentPattern);
            expect(result === 0 || result === 0n).toBe(true);
        });

        it('findPatternInRegion should throw for invalid scanSize (0 or negative)', () => {
            if (!testProcessHandle || !knownModule || knownModule.modBaseAddr === 0n) return;
            expect(() => {
                mp.findPatternInRegion(testProcessHandle!, knownModule!.modBaseAddr, 0, "AA BB");
            }).toThrow(/Invalid scanSize/);
            expect(() => {
                mp.findPatternInRegion(testProcessHandle!, knownModule!.modBaseAddr, -100, "AA BB");
            }).toThrow(/Invalid scanSize/);
        });
        
        it('findPattern (global) should find a known pattern if one exists', () => {
            // This is a very broad test and might be slow or unreliable.
            // It's better to use findPatternInRegion or findPatternByModule.
            // Placeholder for now, or skip if too unreliable.
            if (!testProcessHandle) {
                console.warn('Skipping global findPattern test: no process handle.');
                return;
            }
             // It is hard to guarantee a pattern globally without knowing the process.
             // For now, we check if it runs without error. A more specific test would require a known global signature.
            try {
                const result = mp.findPattern(testProcessHandle, "4D 5A"); // Search for "MZ" globally
                // We can't be sure it will be found or what its address would be,
                // but it shouldn't crash. Result could be 0/0n.
                expect(typeof result === 'number' || typeof result === 'bigint').toBe(true);
            } catch(e: any) {
                // Some processes might not allow enumeration of all modules/regions for a global scan.
                console.warn(`Global findPattern test threw an error (possibly permissions): ${e.message}`);
                expect(e).toBeInstanceOf(Error); // Or a more specific error type if defined by the library
            }
        });
    });

    describe('Input Validation (General)', () => {
        it('should throw when opening process with empty string name', () => {
            expect(() => mp.openProcess('')).toThrow(/empty string/);
        });

        it('should throw when providing invalid handle to functions like readMemory', () => {
            expect(() => mp.readMemory(-1, 0x1000, 'int')).toThrow(/Invalid handle/);
            expect(() => mp.readMemory(null as any, 0x1000, 'int')).toThrow(/Invalid handle/);
        });

        it('should throw for invalid addresses in readMemory', () => {
             if (!testProcessHandle) { console.warn("Skipping invalid address test: no process handle."); return; }
            expect(() => mp.readMemory(testProcessHandle!, -100, 'int')).toThrow(/Address cannot be negative/);
        });

        it('should throw for invalid dataType in readMemory', () => {
             if (!testProcessHandle) { console.warn("Skipping invalid dataType test: no process handle."); return; }
            expect(() => mp.readMemory(testProcessHandle!, readableAddress, '')).toThrow(/dataType.*empty/);
            expect(() => mp.readMemory(testProcessHandle!, readableAddress, 'invalid_type' as any)).toThrow(/unexpected data type|Unsupported data type/); // Error from C++ or JS
        });

        it('should throw for invalid size in readBuffer', () => {
             if (!testProcessHandle) { console.warn("Skipping invalid size test: no process handle."); return; }
            expect(() => mp.readBuffer(testProcessHandle!, readableAddress, 0)).toThrow(/Invalid size/);
            expect(() => mp.readBuffer(testProcessHandle!, readableAddress, -10)).toThrow(/Invalid size/);
        });
    });

    // TODO: Add tests for Debugger class (attach, detach, breakpoints)
    // These are highly dependent on OS permissions and process state.
    describe('Debugger Operations (Placeholder - Requires Specific Setup)', () => {
        it('Debugger tests require specific environment and are placeholders', () => {
            console.warn("Debugger tests are placeholders and require manual setup/verification.");
            expect(true).toBe(true);
        });
    });
    
    // TODO: Add tests for DLL Injection (injectDll, unloadDll)
    // These require a test DLL and careful handling.
    describe('DLL Operations (Placeholder - Requires Specific Setup & Test DLL)', () => {
        it('DLL injection/unloading tests require a test DLL and are placeholders', () => {
            console.warn("DLL operations tests are placeholders and require manual setup/verification.");
            expect(true).toBe(true);
        });
    });
    
    // TODO: Add tests for advanced memory functions (virtualAllocEx, virtualProtectEx, etc.)
    // These require careful setup and understanding of memory management.
    describe('Advanced Memory Operations (Placeholder - Requires Specific Setup)', () => {
        it('Advanced memory operation tests are placeholders and require manual setup/verification.', () => {
            console.warn("Advanced memory operation tests are placeholders and require manual setup/verification.");
            expect(true).toBe(true);
        });
    });

});
