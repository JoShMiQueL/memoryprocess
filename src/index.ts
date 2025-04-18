import { readMemory, writeMemory } from './memory';
import { openProcess, closeProcess, type ProcessObject } from './process';

export {
  readMemory,
  writeMemory,
  openProcess,
  closeProcess,
  type ProcessObject
};

const memoryprocess = {
  readMemory,
  writeMemory,
  openProcess,
  closeProcess
};

export default memoryprocess;
