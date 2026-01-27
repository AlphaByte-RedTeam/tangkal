import fg from 'fast-glob';
import fs from 'fs/promises';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { loadIgnore } from './utils/ignore.js';
import { analyzeContent, type Finding } from './analyzers/static-analysis.js';
import { checkTyposquatting } from './analyzers/dependencies.js';
import { checkReputation, checkVulnerabilitiesBatch } from './analyzers/network.js';
import { parsePackageLock, type Dependency } from './utils/lockfile.js';

interface ScanOptions {
  json?: boolean;
  skipAudit?: boolean;
}

export async function scanDirectory(directory: string, options: ScanOptions = {}): Promise<Finding[]> {
  const targetDir = path.resolve(directory);
  const ig = await loadIgnore(targetDir);
  const allFindings: Finding[] = [];

  // 1. Find Files
  const entries = await fg(['**/*.{js,ts,jsx,tsx,json}'], {
    cwd: targetDir,
    dot: true,
    ignore: ['**/node_modules/**', '**/.git/**']
  });

  const files = entries.filter(f => !ig.ignores(f));

  if (!options.json) {
    console.log(chalk.gray(`Scanning ${files.length} files from ${targetDir}...`));
  }

  let packageJsonFound = false;

  // 2. Scan Content (Sync/Fast)
  for (const file of files) {
    const filePath = path.join(targetDir, file);
    try {
        const content = await fs.readFile(filePath, 'utf-8');

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

                // B. Typosquatting (Fast Static)
                const typoFindings = checkTyposquatting(pkg);
                typoFindings.forEach(f => {
                    allFindings.push({ ...f, file });
                });
                
            } catch (e) { /* invalid json */ }
        }

        // Static Code Analysis
        const contentFindings = analyzeContent(content, file);
        allFindings.push(...contentFindings);

    } catch (e) {
        // failed to read file
    }
  }

  // 3. Network Audit (Reputation & Vulnerability)
  if (!options.skipAudit && packageJsonFound) {
      if (!options.json) console.log(chalk.gray('Running deep dependency audit...'));
      const spinner = !options.json ? ora('Analyzing dependencies...').start() : null;

      // Try to parse lockfile for Full Transitive Scan
      const lockDeps = await parsePackageLock(targetDir);
      let depsToScan: Dependency[] = [];
      let scanType = 'Direct';

      if (lockDeps) {
        depsToScan = lockDeps;
        scanType = 'Transitive (Lockfile)';
        if (spinner) spinner.text = `Found package-lock.json. Auditing ${depsToScan.length} transitive dependencies...`;
      } else {
        // Fallback to package.json (Direct only)
        try {
            const pkgPath = path.join(targetDir, 'package.json');
            const pkgContent = await fs.readFile(pkgPath, 'utf-8');
            const pkg = JSON.parse(pkgContent);
            const deps = { ...pkg.dependencies, ...pkg.devDependencies };
            depsToScan = Object.keys(deps).map(k => ({ name: k, version: deps[k].replace(/[\^~]/g, '') })); // Clean version roughly
            scanType = 'Direct (Manifest)';
            if (spinner) spinner.text = `No lockfile found. Auditing ${depsToScan.length} direct dependencies...`;
        } catch (e) {}
      }

      // EXECUTE AUDIT
      if (depsToScan.length > 0) {
        // 1. Check Reputation (only for direct deps usually, or all? Let's do all, but it might be slow for transitive. 
        // actually, reputation check for 1000 transitive deps is too slow and noisy.
        // Let's keep Reputation Check for DIRECT deps only, and Vulnerability for ALL.
        
        // We need to re-read package.json to know which are direct for Reputation check
        let directDepsNames: string[] = [];
        try {
            const pkg = JSON.parse(await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8'));
            directDepsNames = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
        } catch(e) {}

        const reputationPromises = directDepsNames.map(name => checkReputation(name));
        
        // 2. Check Vulnerabilities (Batch)
        const vulnPromise = checkVulnerabilitiesBatch(depsToScan);

        const [repResults, vulnResults] = await Promise.all([
            Promise.all(reputationPromises),
            vulnPromise
        ]);

        const repFindings = repResults.flat();
        
        repFindings.forEach(f => allFindings.push({ ...f, file: 'package.json' }));
        vulnResults.forEach(f => allFindings.push({ ...f, file: 'package-lock.json' })); // Attribute to lockfile if possible

        if (spinner) spinner.succeed(`Audit complete (${scanType}): scanned ${depsToScan.length} packages.`);
      } else {
         if (spinner) spinner.stop();
      }
  }

  return allFindings;
}
