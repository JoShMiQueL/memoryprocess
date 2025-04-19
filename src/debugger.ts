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
    this.memoryprocess = memoryprocess;
    this.registers = new Registers();
    this.attached = false;
    this.intervals = [];
  }

  attach(processId, killOnDetach = false) {
    const success = this.memoryprocess.attachDebugger(processId, killOnDetach);

    if (success) {
      this.attached = true;
    }

    return success;
  }

  detach(processId) {
    this.intervals.map(({ id }) => clearInterval(id));
    return this.memoryprocess.detachDebugger(processId);
  }

  removeHardwareBreakpoint(processId, register) {
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
    let size = lengths[dataType];

    // If we are breakpointing a string, we need to determine the length of it
    if (dataType === 'str' || dataType === 'string') {
      const { handle } = this.memoryprocess.openProcess(processId);
      const value = this.memoryprocess.readMemory(handle, address, this.memoryprocess.STRING);

      size = value.length;

      this.memoryprocess.closeProcess(handle);
    }

    // Obtain an available register
    const register = this.registers.getRegister();
    const success = this.memoryprocess
      .setHardwareBreakpoint(processId, address, register, trigger, size);

    // If the breakpoint was set, mark this register as busy
    if (success) {
      this.registers.busy(register);
      this.monitor(register);
    }

    return register;
  }

  monitor(register, timeout = 100) {
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
