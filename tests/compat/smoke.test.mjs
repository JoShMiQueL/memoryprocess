import test from 'node:test'
import assert from 'node:assert'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

test('native addon loads and lists processes under Node', async () => {
  const native = require('../../dist/memoryprocess.node')
  const procs = native.listProcesses()
  assert.ok(Array.isArray(procs) && procs.length > 0, 'should list processes')
  const self = native.openProcess(process.pid)
  assert.ok(self.handle > 0, 'should open own process')
  assert.ok(native.closeHandle(self.handle), 'should close handle')
})
