// @ts-ignore
import { openProcess, closeProcess, readMemory } from 'memoryprocess';

const PROCESS_NAME = "DarkSoulsRemastered.exe";

try {
  // 1. Open the game process
  console.log(`Attempting to open process: ${PROCESS_NAME}`);
  const processObject = openProcess(PROCESS_NAME);

  if (!processObject || !processObject.handle) {
    console.error(`Failed to open process "${PROCESS_NAME}". Is the game running?`);
    process.exit(1); // Use Bun's exit
  }

  console.log(`Process "${PROCESS_NAME}" opened successfully.`);
  console.log(`Process ID: ${processObject.th32ProcessID}`);
  console.log(`Base Address: 0x${processObject.modBaseAddr.toString(16)}`); // Log base address in hex

  // 2. Define offsets (these are specific to Dark Souls Remastered and might need updates)
  const playerDataBase = 0x1D278F0;
  const playerDataStruct = 0x10;
  const soulsOffset = 0x94;

  // 3. Read the pointer chain to find the souls address
  console.log(`Reading player data base pointer at BaseAddress + 0x${playerDataBase.toString(16)}`);
  const pointer1Address = processObject.modBaseAddr + playerDataBase;
  const pointer1Value = readMemory(processObject.handle, pointer1Address, "int"); // Assuming 32-bit pointers/game
  if (pointer1Value === 0) {
     console.error(`Failed to read base pointer at 0x${pointer1Address.toString(16)}. Value was 0.`);
     closeProcess(processObject.handle);
     process.exit(1);
  }
  console.log(`Read Pointer 1 Value (Player Data Base): 0x${pointer1Value.toString(16)}`);


  console.log(`Reading player data struct pointer at Pointer1Value + 0x${playerDataStruct.toString(16)}`);
  const pointer2Address = pointer1Value + playerDataStruct;
  const pointer2Value = readMemory(processObject.handle, pointer2Address, "int");
   if (pointer2Value === 0) {
     console.error(`Failed to read pointer 2 at 0x${pointer2Address.toString(16)}. Value was 0.`);
     closeProcess(processObject.handle);
     process.exit(1);
  }
  console.log(`Read Pointer 2 Value (Player Data Struct): 0x${pointer2Value.toString(16)}`);

  const soulsAddress = pointer2Value + soulsOffset;
  console.log(`Calculated Souls Address: 0x${soulsAddress.toString(16)}`);

  // 4. Read the souls value from the final address
  const currentSouls = readMemory(processObject.handle, soulsAddress, "int");

  console.log(`\nCurrent Player Souls: ${currentSouls}`);

  // 5. Close the process handle
  console.log("Closing process handle.");
  closeProcess(processObject.handle);
  console.log("Process handle closed.");

} catch (error) {
  console.error("An error occurred:", error);
}
