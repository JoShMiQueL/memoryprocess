import { spawn, type ChildProcess } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const exe = join(dir, 'gamevictim.exe');

export interface GameVictim {
  proc: ChildProcess;
  pid: number;
  addr: Record<string, bigint>;
  kill: () => void;
}

/**
 * Spawn tests/gamevictim.exe and collect its emitted `&g_*=0x...` table.
 * Ready when `&g_count` arrives (printed last).
 */
export async function spawnGameVictim(): Promise<GameVictim> {
  const proc = spawn(exe, [], { stdio: ['ignore', 'pipe', 'inherit'] });
  let buf = '';
  await new Promise<void>((res, rej) => {
    proc.stdout!.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('&g_count')) res();
    });
    proc.on('error', rej);
    setTimeout(() => rej(new Error('gamevictim spawn timeout')), 10_000);
  });
  const pid = Number(buf.match(/PID=(\d+)/)![1]);
  const addr: Record<string, bigint> = {};
  for (const m of buf.matchAll(/&(g_\w+)=([0-9A-Fa-f]+)/g))
    addr[m[1]] = BigInt('0x' + m[2]);
  return { proc, pid, addr, kill: () => proc.kill() };
}
