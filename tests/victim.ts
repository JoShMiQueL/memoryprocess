import { spawn, type ChildProcess } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const exe = join(dir, 'victim.exe');

export interface Victim {
  proc: ChildProcess;
  pid: number;
  addr: Record<string, bigint>;
  kill: () => void;
}

export async function spawnVictim(): Promise<Victim> {
  const proc = spawn(exe, [], { stdio: ['ignore', 'pipe', 'inherit'] });
  let buf = '';
  await new Promise<void>((res, rej) => {
    // Newer victims print &g_guard_end last; older binaries end at &g_ptr —
    // fall back to a short quiet period so both work.
    let ptrTimer: NodeJS.Timeout | undefined;
    proc.stdout!.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('&g_guard_end')) {
        clearTimeout(ptrTimer);
        res();
      } else if (buf.includes('&g_ptr') && !ptrTimer) {
        ptrTimer = setTimeout(res, 300);
      }
    });
    proc.on('error', rej);
    setTimeout(() => rej(new Error('victim spawn timeout')), 10_000);
  });
  const pid = Number(buf.match(/PID=(\d+)/)![1]);
  const addr: Record<string, bigint> = {};
  for (const m of buf.matchAll(/&(g_\w+)=([0-9A-Fa-f]+)/g))
    addr[m[1]] = BigInt('0x' + m[2]);
  return { proc, pid, addr, kill: () => proc.kill() };
}
