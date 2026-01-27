import fg from 'fast-glob';
import fs from 'fs/promises';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { loadIgnore } from './utils/ignore.js';
import { analyzeContent, analyzeStream, type Finding } from './analyzers/static-analysis.js';
import { checkTyposquatting } from './analyzers/dependencies.js';
import { auditDependencies } from './analyzers/network.js';
import { parsePackageLock, type Dependency } from './utils/lockfile.js';

interface ScanOptions {
  json?: boolean;
  skipAudit?: boolean;
}

export async function scanDirectory(directory: string, options: ScanOptions = {}): Promise<Finding[]> {
  const targetDir = path.resolve(directory);
  const ig = await loadIgnore(targetDir);
  const allFindings: Finding[] = [];

  // 1. Find Files (Streaming)
  const stream = fg.stream(['**/*.{js,ts,jsx,tsx,json}'], {
    cwd: targetDir,
    dot: true,
    ignore: ['**/node_modules/**', '**/.git/**']
  });

  if (!options.json) {
    console.log(chalk.gray(`Scanning files from ${targetDir} (Streaming)...`));
  }

  let packageJsonFound = false;

  // 2. Scan Content
  for await (const entry of stream) {
    const file = entry as string;
    if (ig.ignores(file)) continue;

    const filePath = path.join(targetDir, file);
    try {
        const stat = await fs.stat(filePath);
        
        // Optimize: Stream large files (>1MB)
        if (stat.size > 1024 * 1024) {
            const streamFindings = await analyzeStream(filePath);
            streamFindings.forEach(f => { f.file = file; allFindings.push(f); });
            continue;
        }

        // Standard Read for small files
        let content = await fs.readFile(filePath, 'utf-8');
        content = content.replace(/^\uFEFF/, '');

        // Check package.json specifically
        if (file === 'package.json') {
            packageJsonFound = true;
            try {
                const pkg = JSON.parse(content);
                
                // A. Lifecycle Scripts
                const scripts = pkg.scripts || {};
                const dangerousScripts = ['preinstall', 'postinstall', 'install'];
                for (const name of dangerousScripts) {
                    if (scripts[name]) {
                        allFindings.push({
                            type: 'Lifecycle Script',
                            name: name,
                            file,
                            line: 0,
                            severity: 'critical',
                            content: scripts[name],
                            description: 'Dangerous lifecycle script that runs automatically on install.'
                        });
                    }
                }

                // B. Typosquatting (Async & Network-aware)
                const typoFindings = await checkTyposquatting(pkg);
                typoFindings.forEach(f => {
                    allFindings.push({ ...f, file });
                });
                
            } catch (e) { 
                // Error parsing or checking typosquat
            }
        }

        // Static Code Analysis (AST)
        const contentFindings = analyzeContent(content, file);
        allFindings.push(...contentFindings);

    } catch (e) {
        // failed to read file
    }
  }

  // 3. Network Audit (Reputation & Vulnerability)
  if (!options.skipAudit) {
      const lockDeps = await parsePackageLock(targetDir);
      
      if (lockDeps && lockDeps.length > 0) {
          if (!options.json) console.log(chalk.gray('Running deep dependency audit...'));
          const spinner = !options.json ? ora(`Auditing ${lockDeps.length} dependencies...`).start() : null;

          const netFindings = await auditDependencies(lockDeps);
          allFindings.push(...netFindings);
          
          if (spinner) spinner.succeed(`Audit complete: scanned ${lockDeps.length} packages.`);
      } else if (packageJsonFound) {
           try {
              const pkgPath = path.join(targetDir, 'package.json');
              const pkgContent = await fs.readFile(pkgPath, 'utf-8');
              const pkg = JSON.parse(pkgContent);
              const deps = { ...pkg.dependencies, ...pkg.devDependencies };
              const directDeps = Object.keys(deps).map(k => ({ name: k, version: deps[k].replace(/[\^~]/g, '') }));
              
              if (directDeps.length > 0) {
                  if (!options.json) console.log(chalk.gray('No lockfile found. Auditing direct dependencies...'));
                  const spinner = !options.json ? ora(`Auditing ${directDeps.length} direct dependencies...`).start() : null;
                  
                  const netFindings = await auditDependencies(directDeps);
                  allFindings.push(...netFindings);
                  
                  if (spinner) spinner.succeed(`Audit complete: scanned ${directDeps.length} packages.`);
              }
           } catch(e) {}
      }
  }

  return allFindings;
}