import ignore from 'ignore';
import fs from 'fs/promises';
import path from 'path';
import type { Ignore } from 'ignore';

export async function loadIgnore(dir: string): Promise<Ignore> {
  const ig = ignore();
  const ignorePath = path.join(dir, '.tangkalignore');

  try {
    const content = await fs.readFile(ignorePath, 'utf-8');
    ig.add(content);
  } catch (e) {
    // If file doesn't exist, we just return the empty ignore instance
  }

  // Always ignore common noise
  ig.add(['node_modules', '.git', 'dist', 'build', 'coverage', '*.min.js', '*.map']);
  
  return ig;
}
