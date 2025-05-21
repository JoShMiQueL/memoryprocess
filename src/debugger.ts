// @ts-nocheck
// TODO: In the future, we plan to add proper typing
import EventEmitter from 'events';

const lengths = {
  byte: 1,
  int: 4,
  int32: 4,
  uint32: 4,
  int64: 8,
  uint64: 8,
  dword: 4,
  short: 2,
  long: 8,
  float: 4,
  double: 8,
  bool: 1,
  boolean: 1,
  ptr: 4,
  pointer: 4,
  // str: 0,
  // string: 0,
  // vec3: 0,
  // vector3: 0,
  // vec4: 0,
  // vector4: 0,
};

// Tracks used and unused registers
class Registers {
  constructor() {
    this.registers = Object.freeze({
      DR0: 0x0,
      DR1: 0x1,
      DR2: 0x2,
      DR3: 0x3,
    });

    this.used = [];
  }

  getRegister() {
    const unused = Object
      .values(this.registers)
      .filter(r => !this.used.includes(r));

    return unused[0];
  }

  busy(register) {
    this.used.push(register);
  }

  unbusy(register) {
    this.used.splice(this.used.indexOf(register), 1);
  }
}

class Debugger extends EventEmitter {
  constructor(memoryprocess) {
    super();
    if (!memoryprocess) {
      throw new Error('Debugger constructor requires a memoryprocess instance.');
    }
    this.memoryprocess = memoryprocess;
    this.registers = new Registers();
    this.attached = false;
    this.intervals = [];
  }

  attach(processId, killOnDetach = false) {
    if (typeof processId !== 'number' || processId < 0) {
      throw new Error('Invalid processId: must be a non-negative number.');
    }
    // killOnDetach is boolean, no specific check needed unless strict true/false is required over truthy/falsy

    const success = this.memoryprocess.attachDebugger(processId, killOnDetach);

    if (success) {
      this.attached = true;
    }

    return success;
  }

  detach(processId) {
    if (typeof processId !== 'number' || processId < 0) {
      throw new Error('Invalid processId: must be a non-negative number.');
    }

    this.intervals.map(({ id }) => clearInterval(id));
    return this.memoryprocess.detachDebugger(processId);
  }

  removeHardwareBreakpoint(processId, register) {
    if (typeof processId !== 'number' || processId < 0) {
      throw new Error('Invalid processId: must be a non-negative number.');
    }
    if (typeof register !== 'number' || !Object.values(this.registers.registers).includes(register)) {
      throw new Error('Invalid register: must be one of the defined hardware registers (DR0-DR3).');
    }

    const success = this.memoryprocess.removeHardwareBreakpoint(processId, register);

    if (success) {
      this.registers.unbusy(register);
    }

    // Find the register's corresponding interval and delete it
    this.intervals.forEach(({ register: r, id }) => {
      if (r === register) {
        clearInterval(id);
      }
    });

    return success;
  }

  setHardwareBreakpoint(processId, address, trigger, dataType) {
    if (typeof processId !== 'number' || processId < 0) {
      throw new Error('Invalid processId: must be a non-negative number.');
    }
    if (typeof address !== 'number' || address <= 0) { // Breakpoint addresses are typically positive
      throw new Error('Invalid address: must be a positive number.');
    }
    // Assuming trigger is a number, e.g., 0 (execute), 1 (write), 3 (read/write)
    // A more specific check would require knowing the valid enum/values for trigger.
    if (typeof trigger !== 'number' || trigger < 0 || trigger > 3) { // Common range for HW breakpoints
      throw new Error('Invalid trigger: must be a number representing a valid trigger condition (e.g., 0-3).');
    }
    if (typeof dataType !== 'string' || (!lengths.hasOwnProperty(dataType) && dataType !== 'str' && dataType !== 'string')) {
      throw new Error(`Invalid dataType: '${dataType}'. Must be a known type or 'str'/'string'.`);
    }

    let size = lengths[dataType];

    // If we are breakpointing a string, we need to determine the length of it
    if (dataType === 'str' || dataType === 'string') {
      // Ensure processId is valid before opening, though already checked above.
      const processData = this.memoryprocess.openProcess(processId);
      if (!processData || !processData.handle) {
        throw new Error(`Failed to open process ${processId} to determine string length for breakpoint.`);
      }
      const { handle } = processData;
      // Assuming STRING is a valid dataType for readMemory in the native module
      const value = this.memoryprocess.readMemory(handle, address, 'string'); 
      if (typeof value !== 'string') {
        this.memoryprocess.closeHandle(handle);
        throw new Error(`Failed to read string at address ${address} for process ${processId}.`);
      }
      size = value.length;
      this.memoryprocess.closeHandle(handle);
    }
    
    if (size === undefined && (dataType === 'str' || dataType === 'string')) {
        // This case should not be reached if the above logic is correct, but as a safeguard:
        throw new Error(`Could not determine size for string dataType at address ${address}.`);
    }
    if (size === undefined && dataType !== 'str' && dataType !== 'string') {
      throw new Error(`Invalid dataType '${dataType}': size could not be determined from 'lengths' object.`);
    }


    // Obtain an available register
    const register = this.registers.getRegister();
    if (register === undefined) {
      throw new Error('No available hardware registers to set breakpoint.');
    }

    const success = this.memoryprocess
      .setHardwareBreakpoint(processId, address, register, trigger, size);

    // If the breakpoint was set, mark this register as busy
    if (success) {
      this.registers.busy(register);
      this.monitor(register); // Pass timeout if it's configurable for monitor
    }

    return register;
  }

  monitor(register, timeout = 100) {
    if (typeof register !== 'number' || !Object.values(this.registers.registers).includes(register)) {
      throw new Error('Invalid register: must be one of the defined hardware registers (DR0-DR3) to monitor.');
    }
    if (typeof timeout !== 'number' || timeout < 0) {
      throw new Error('Invalid timeout: must be a non-negative number.');
    }

    const id = setInterval(() => {
      const debugEvent = this.memoryprocess.awaitDebugEvent(register, timeout);

      if (debugEvent) {
        this.memoryprocess.handleDebugEvent(debugEvent.processId, debugEvent.threadId);

        // Global event for all registers
        this.emit('debugEvent', {
          register,
          event: debugEvent,
        });

        // Event per register
        this.emit(register, debugEvent);
      }
    }, 100);

    this.intervals.push({
      register,
      id,
    });
  }
}

export default Debugger;
