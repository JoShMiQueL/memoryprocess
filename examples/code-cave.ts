// code-cave.ts — find a code cave in a target module and redirect a call
// site into it with a 5-byte E9 jump. Skeleton with safe guard rails:
// it only demonstrates the mechanics — adapt addresses to your target.
//
// Run: bun examples/code-cave.ts <pid-or-name>
import { Process, Protection } from '../src/index.js'

const target = process.argv[2] ?? 'notepad.exe'
using proc = Process.open(/^\d+$/.test(target) ? Number(target) : target)

// 1) Find a cave of >= 32 bytes in the main module (or any module you pass).
const main = proc.modules()[0]!
const modName = main.path.split(/[\\/]/).pop()!
const cave = proc.findCodeCave(32, { module: modName })
if (!cave) {
  console.error('no code cave found — try a larger/different module')
  process.exit(1)
}
console.log(`cave at 0x${cave.toString(16)} in ${modName}`)

// 2) Write your detour payload into the cave. Example payload (x64):
//    - your code here
//    - original instructions you overwrote at the hook site
//    - E9 back to hookSite+5
// Below is a placeholder that just returns (C3) — real payloads vary.
const payload = Buffer.from([0xc3])
proc.writeProtected(cave, payload)

// 3) Redirect a call site. Pick an address inside an executable region
//    where you can afford to overwrite 5 bytes.
//    NOTE: in real use you'd locate the site via proc.scan(...) for a
//    stable signature. Here we just demonstrate the mechanics and restore.
const site = cave + 8n // demo-only: patch within the cave itself
const original = proc.readBuffer(site, 5)

proc.suspendAll() // freeze threads while patching
try {
  proc.patchJump(site, cave) // E9 rel32: site -> cave
  console.log(`patched 0x${site.toString(16)} -> 0x${cave.toString(16)}`)
  // verify
  const bytes = proc.readBuffer(site, 5)
  console.log(`site bytes: ${bytes.toString('hex')}`) // e9 xx xx xx xx
} finally {
  // restore and resume — always leave the target in a sane state
  proc.writeProtected(site, original)
  proc.resumeAll()
}
console.log('restored original bytes; done')

// In a real detour you'd:
//   - keep the original 5 bytes, append them + a jump-back inside the cave
//   - leave the patch in place instead of restoring
//   - flush icache is handled for you by writeProtected/patchJump
