import fs from 'fs/promises';
import path from 'path';

export interface Dependency {
  name: string;
  version: string;
}

interface LockFileV2 {
  packages?: Record<string, { version?: string; dependencies?: Record<string, string> }>;
  dependencies?: Record<string, any>;
}

interface LockFileV1Dependency {
  version: string;
  dependencies?: Record<string, LockFileV1Dependency>;
}

interface LockFileV1 {
  dependencies?: Record<string, LockFileV1Dependency>;
}

/**
 * Parses package-lock.json (v2/v3) to get a flat list of all resolved dependencies.
 */
export async function parsePackageLock(dir: string): Promise<Dependency[] | null> {
  try {
    const lockPath = path.join(dir, 'package-lock.json');
    const content = await fs.readFile(lockPath, 'utf-8');
    const lock: LockFileV2 & LockFileV1 = JSON.parse(content);
    
    const dependencies: Dependency[] = [];

    // v2/v3 format has "packages"
    if (lock.packages) {
      for (const [key, val] of Object.entries(lock.packages)) {
        // key is "" for root, "node_modules/foo" for deps
        if (key === '') continue;
        
        // We only want top-level of the key name? No, we want the package name.
        // key "node_modules/foo" -> name "foo"
        // key "node_modules/foo/node_modules/bar" -> name "bar"
        const name = key.split('node_modules/').pop();
        
        if (name && val.version) {
          dependencies.push({ name, version: val.version });
        }
      }
    } 
    // v1 format has nested "dependencies"
    else if (lock.dependencies) {
      // Recursive flatten
      const traverse = (deps: Record<string, LockFileV1Dependency>) => {
        for (const [name, val] of Object.entries(deps)) {
            if (val.version) {
                dependencies.push({ name, version: val.version });
            }
            if (val.dependencies) {
                traverse(val.dependencies);
            }
        }
      };
      traverse(lock.dependencies as Record<string, LockFileV1Dependency>);
    }

    // Deduplicate (some packages might appear multiple times with same version)
    const unique = new Map<string, Dependency>();
    dependencies.forEach(d => unique.set(`${d.name}@${d.version}`, d));
    
    return Array.from(unique.values());

  } catch (e) {
    return null; // No lockfile or invalid
  }
}
