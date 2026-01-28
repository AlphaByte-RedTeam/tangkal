import fs from 'fs/promises';
import { spawn } from 'child_process';
import chalk from 'chalk';

export type PackageManager = 'npm' | 'yarn' | 'pnpm' | 'bun' | 'deno';

export async function detectPackageManager(dir: string): Promise<PackageManager> {
  const files = await fs.readdir(dir).catch(() => []);

  if (files.includes('deno.json') || files.includes('deno.lock')) return 'deno';
  if (files.includes('bun.lockb') || files.includes('bun.lock')) return 'bun';
  if (files.includes('pnpm-lock.yaml')) return 'pnpm';
  if (files.includes('yarn.lock')) return 'yarn';
  
  return 'npm';
}

export async function runInstall(pm: PackageManager, dir: string): Promise<void> {
  console.log(chalk.gray(`> Running ${pm} install...`));

  return new Promise((resolve, reject) => {
    const cmd = pm;

    // Use shell: true to handle cross-platform command resolution (especially for .cmd on Windows)
    const child = spawn(cmd, ['install'], {
      cwd: dir,
      stdio: 'inherit',
      shell: true
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${pm} install failed with code ${code}`));
      }
    });

    child.on('error', (err) => {
      reject(err);
    });
  });
}
