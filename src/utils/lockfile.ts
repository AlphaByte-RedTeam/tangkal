import fs from 'fs/promises';
import path from 'path';
import * as yarnLockfile from '@yarnpkg/lockfile';
import yaml from 'yaml';

export interface Dependency {
  name: string;
  version: string;
}

interface PackageLockV2 {
  packages?: Record<string, { version?: string }>;
  dependencies?: Record<string, any>;
}

/**
 * Parses lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml) to get a flat list of dependencies.
 */
export async function parsePackageLock(dir: string): Promise<Dependency[] | null> {
  // 1. Try package-lock.json
  try {
    const lockPath = path.join(dir, 'package-lock.json');
    const content = await fs.readFile(lockPath, 'utf-8');
    const lock: PackageLockV2 = JSON.parse(content);
    
    const dependencies: Dependency[] = [];
    
    if (lock.packages) {
      for (const [key, val] of Object.entries(lock.packages)) {
        if (key === '') continue;
        const name = key.split('node_modules/').pop();
        if (name && typeof val.version === 'string') {
          dependencies.push({ name, version: val.version });
        }
      }
    } else if (lock.dependencies) {
        // v1 recursive
        const traverse = (deps: any) => {
            for (const [name, val] of Object.entries(deps)) {
                if (typeof (val as any).version === 'string') {
                    dependencies.push({ name, version: (val as any).version });
                }
                if ((val as any).dependencies) traverse((val as any).dependencies);
            }
        };
        traverse(lock.dependencies);
    }
    return deduplicate(dependencies);
  } catch (e) {}

  // 2. Try yarn.lock
  try {
      const lockPath = path.join(dir, 'yarn.lock');
      const content = await fs.readFile(lockPath, 'utf-8');
      const parsed = yarnLockfile.parse(content);
      
      if (parsed.type === 'success' && parsed.object) {
          const dependencies: Dependency[] = [];
          for (const [key, val] of Object.entries(parsed.object)) {
              const nameMatch = key.match(/^(@?[^@]+)@/);
              const name = nameMatch ? nameMatch[1] : key;
              if (name && typeof (val as any).version === 'string') {
                  dependencies.push({ name, version: (val as any).version as string });
              }
          }
          return deduplicate(dependencies);
      }
  } catch (e) {}

  // 3. Try pnpm-lock.yaml
  try {
      const lockPath = path.join(dir, 'pnpm-lock.yaml');
      const content = await fs.readFile(lockPath, 'utf-8');
      const parsed = yaml.parse(content);
      
      const dependencies: Dependency[] = [];
      if (parsed.packages) {
          for (const key of Object.keys(parsed.packages)) {
              let cleanKey = key.startsWith('/') ? key.substring(1) : key;
              if (cleanKey.includes('(')) {
                  cleanKey = cleanKey.split('(')[0] ?? cleanKey;
              }

              const parts = cleanKey.split('/');
              if (parts.length >= 2) {
                  const version = parts.pop();
                  const name = parts.join('/');
                  if (name && typeof version === 'string') {
                      dependencies.push({ name, version });
                  }
              } else if (cleanKey.includes('@')) {
                  const lastAt = cleanKey.lastIndexOf('@');
                  const name = cleanKey.substring(0, lastAt);
                  const version = cleanKey.substring(lastAt + 1);
                  if (name && typeof version === 'string') {
                      dependencies.push({ name, version });
                  }
              }
          }
          return deduplicate(dependencies);
      }
  } catch (e) {}

  // 4. Try bun.lock (Text format)
  try {
      const lockPath = path.join(dir, 'bun.lock');
      const content = await fs.readFile(lockPath, 'utf-8');
      if (content.trim().startsWith('#') || content.includes('lockfile v1')) {
          const parsed = yarnLockfile.parse(content);
          if (parsed.type === 'success' && parsed.object) {
              const dependencies: Dependency[] = [];
              for (const [key, val] of Object.entries(parsed.object)) {
                  const nameMatch = key.match(/^(@?[^@]+)@/);
                  const name = nameMatch ? nameMatch[1] : key;
                  if (name && typeof (val as any).version === 'string') {
                      dependencies.push({ name, version: (val as any).version as string });
                  }
              }
              return deduplicate(dependencies);
          }
      }
  } catch (e) {}

  // 5. Try deno.lock (JSON)
  try {
      const lockPath = path.join(dir, 'deno.lock');
      const content = await fs.readFile(lockPath, 'utf-8');
      const lock = JSON.parse(content);
      const dependencies: Dependency[] = [];
      
      if (lock.packages && lock.packages.specifiers) {
          for (const key of Object.keys(lock.packages.specifiers)) {
              if (key.startsWith('npm:')) {
                  const resolved = lock.packages.specifiers[key];
                  if (typeof resolved === 'string' && resolved.startsWith('npm:')) {
                       const parts = resolved.replace('npm:', '').split('@');
                       const version = parts.pop();
                       const name = parts.join('@');
                       if (name && typeof version === 'string') {
                           dependencies.push({ name, version });
                       }
                  }
              }
          }
      } 
      return deduplicate(dependencies);
  } catch (e) {}

  return null;
}

function deduplicate(deps: Dependency[]): Dependency[] {
    const unique = new Map<string, Dependency>();
    deps.forEach(d => unique.set(`${d.name}@${d.version}`, d));
    return Array.from(unique.values());
}