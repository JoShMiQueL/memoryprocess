import test from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Full API compat smoke per Node version: not just "the .node loads" — exercise
// the real N-API paths (RPM/WPM/alloc/pattern-scan/CreateRemoteThread) against
// the test process itself, so no external victim is needed.
const ACCESS = 0x0010 | 0x0020 | 0x0008 | 0x0400 | 0x0002; // VM_READ|VM_WRITE|VM_OP|QUERY|CREATE_THREAD
const PAGE_EXECUTE_READWRITE = 0x40;

test('native addon loads and lists processes', () => {
  const native = require('../../dist/memoryprocess.node');
  const procs = native.listProcesses();
  assert.ok(Array.isArray(procs) && procs.length > 0, 'should list processes');
});

test('open/write/read/free round-trip on own process', () => {
  const native = require('../../dist/memoryprocess.node');
  const { handle, pid } = native.openProcess(process.pid, ACCESS);
  assert.ok(pid === process.pid, 'pid should match');

  const addr = native.allocMemory(handle, 0x1000, PAGE_EXECUTE_READWRITE);
  assert.ok(addr > 0n, 'allocMemory returns base');
  const base = Number(addr);

  // typed value write + read at base
  assert.strictEqual(
    native.writeValue(handle, base, 'int32', 0x1234abcd),
    true,
  );
  assert.strictEqual(native.readValue(handle, base, 'int32'), 0x1234abcd);

  // unique byte pattern placed at base+0x10 so the int32 write can't overlap it
  const magic = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x48, 0x8b, 0x05, 0x90]);
  assert.strictEqual(native.writeBuffer(handle, base + 0x10, magic), true);
  const back = native.readBuffer(handle, base + 0x10, magic.length);
  assert.deepStrictEqual(
    [...back],
    [...magic],
    'readback matches written bytes',
  );

  // pattern scan over the alloc'd region
  return Promise.resolve(
    native.scan(pid, 'DE AD BE EF 48 8B 05 90', {
      start: base,
      end: base + 0x1000,
    }),
  ).then((hits) => {
    assert.strictEqual(hits.length, 1, 'scan finds the unique pattern');
    assert.strictEqual(hits[0], BigInt(base + 0x10));
    assert.strictEqual(native.freeMemory(handle, base), true);
    assert.strictEqual(native.closeHandle(handle), true);
  });
});

test('execShellcode-equivalent: callRemote runs code in own process', async () => {
  const native = require('../../dist/memoryprocess.node');
  const { handle, pid } = native.openProcess(process.pid, ACCESS);

  const addr = native.allocMemory(handle, 0x1000, PAGE_EXECUTE_READWRITE);
  // mov eax, 0x2A ; ret  ->  B8 2A 00 00 00 C3
  assert.strictEqual(
    native.writeBuffer(
      handle,
      Number(addr),
      Buffer.from([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]),
    ),
    true,
  );
  const exit = native.callRemote(pid, Number(addr), 0, 5000);
  assert.strictEqual(
    exit,
    0x2a,
    'remote thread exit code is the shellcode return value',
  );

  assert.strictEqual(native.freeMemory(handle, Number(addr)), true);
  assert.strictEqual(native.closeHandle(handle), true);
});
