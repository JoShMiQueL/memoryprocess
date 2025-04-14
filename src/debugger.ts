import { EventEmitter } from 'node:events';

interface DebugEvent {
  processId: number;
  threadId: number;
}

interface ProcessHandle {
  handle: number;
}

interface MemoryJS {
  attachDebugger(processId: number, killOnDetach: boolean): boolean;
  detachDebugger(processId: number): boolean;
  removeHardwareBreakpoint(processId: number, register: number): boolean;
  setHardwareBreakpoint(processId: number, address: number, register: number, trigger: string, size: number): boolean;
  readMemory(handle: number, address: number, dataType: string): any;
  openProcess(processId: number): ProcessHandle;
  closeProcess(handle: number): void;
  awaitDebugEvent(register: number, timeout: number): DebugEvent | null;
  handleDebugEvent(processId: number, threadId: number): void;
  STRING: string;
}

interface Interval {
  register: number;
  id: NodeJS.Timeout;
}

const lengths = {
  str: 0,
  string: 0,
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
interface RegisterMap {
  DR0: number;
  DR1: number;
  DR2: number;
  DR3: number;
}

class Registers {
  private registers: RegisterMap;
  private used: number[];

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

  busy(register: number) {
    this.used.push(register);
  }

  unbusy(register: number) {
    this.used.splice(this.used.indexOf(register), 1);
  }
}

class Debugger extends EventEmitter {
  private memoryjs: MemoryJS;
  private registers: Registers;
  private attached: boolean;
  private intervals: Interval[];
  constructor(memoryjs: MemoryJS) {
    super();
    this.memoryjs = memoryjs;
    this.registers = new Registers();
    this.attached = false;
    this.intervals = [];
  }

  attach(processId: number, killOnDetach: boolean = false): boolean {
    const success = this.memoryjs.attachDebugger(processId, killOnDetach);

    if (success) {
      this.attached = true;
    }

    return success;
  }

  detach(processId: number): boolean {
    this.intervals.map(({ id }) => clearInterval(id));
    return this.memoryjs.detachDebugger(processId);
  }

  removeHardwareBreakpoint(processId: number, register: number): boolean {
    const success = this.memoryjs.removeHardwareBreakpoint(processId, register);

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

  setHardwareBreakpoint(processId: number, address: number, trigger: string, dataType: keyof typeof lengths): number {
    let size = lengths[dataType];

    // If we are breakpointing a string, we need to determine the length of it
    if (dataType === 'str' || dataType === 'string') {
      const { handle } = this.memoryjs.openProcess(processId);
      const value = this.memoryjs.readMemory(handle, address, this.memoryjs.STRING);

      size = value.length;

      this.memoryjs.closeProcess(handle);
    }

    // Obtain an available register
    const register = this.registers.getRegister();
    const success = this.memoryjs
      .setHardwareBreakpoint(processId, address, register, trigger, size);

    // If the breakpoint was set, mark this register as busy
    if (success) {
      this.registers.busy(register);
      this.monitor(register);
    }

    return register;
  }

  monitor(register: number, timeout: number = 100): void {
    const id = setInterval(() => {
      const debugEvent = this.memoryjs.awaitDebugEvent(register, timeout);

      if (debugEvent) {
        this.memoryjs.handleDebugEvent(debugEvent.processId, debugEvent.threadId);

        // Global event for all registers
        this.emit('debugEvent', {
          register,
          event: debugEvent,
        });

        // Event per register
        this.emit(String(register), debugEvent);
      }
    }, 100);

    this.intervals.push({
      register,
      id,
    });
  }
}

export { lengths }

export default Debugger;
