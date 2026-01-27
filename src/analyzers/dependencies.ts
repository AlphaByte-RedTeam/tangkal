import levenshtein from 'fast-levenshtein';
import { POPULAR_PACKAGES } from '../config.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import type { Finding } from './static-analysis.js';

const execAsync = promisify(exec);

export function checkTyposquatting(pkgJson: any): Finding[] {
  const findings: Finding[] = [];
  const allDeps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies
  };

  for (const depName of Object.keys(allDeps)) {
    for (const popular of POPULAR_PACKAGES) {
      if (depName === popular) continue; // Exact match is fine

      const distance = levenshtein.get(depName, popular);
      // specific logic: if length is small (<5), distance 1 is bad.
      // if length is long, distance 2 might be bad.
      const threshold = popular.length < 5 ? 1 : 2;

      if (distance <= threshold) {
        findings.push({
          type: 'Typosquatting',
          name: depName,
          file: 'package.json', // Placeholder, caller handles file
          severity: 'high',
          description: `Package '${depName}' looks very similar to popular package '${popular}'.`
        });
      }
    }
  }
  return findings;
}

export async function checkVulnerabilities(cwd: string): Promise<Finding[]> {
  try {
    // Run npm audit without installing dependencies
    // --audit-level=high limits noise, but for security tools we might want all.
    // Let's stick to moderate+
    const { stdout } = await execAsync('npm audit --json --audit-level=moderate', { cwd, maxBuffer: 10 * 1024 * 1024 });
    const auditResult = JSON.parse(stdout);
    
    // Parse audit result (structure depends on npm version, but usually has 'vulnerabilities' or 'advisories')
    // Modern npm audit --json output structure:
    // { vulnerabilities: { 'package-name': { severity: 'high', ... } }, metadata: ... }
    
    const vulns: Finding[] = [];
    if (auditResult.vulnerabilities) {
        // Flatten the object
        for (const [name, info] of Object.entries<any>(auditResult.vulnerabilities)) {
            if (info.severity === 'high' || info.severity === 'critical') {
                vulns.push({
                    type: 'Vulnerability',
                    name,
                    file: 'package-lock.json',
                    severity: info.severity,
                    description: `Known vulnerability via ${info.via && info.via.join ? info.via.join(', ') : 'transitive dependency'}`
                });
            }
        }
    }
    return vulns;

  } catch (error: any) {
    // npm audit exits with 1 if vulnerabilities are found, so we check stdout even on error
    if (error.stdout) {
        try {
            const auditResult = JSON.parse(error.stdout);
            const vulns: Finding[] = [];
            if (auditResult.vulnerabilities) {
                for (const [name, info] of Object.entries<any>(auditResult.vulnerabilities)) {
                     if (info.severity === 'high' || info.severity === 'critical') {
                        vulns.push({
                            type: 'Vulnerability',
                            name,
                            file: 'package-lock.json',
                            severity: info.severity,
                            description: `Known vulnerability (Severity: ${info.severity})`
                        });
                    }
                }
            }
            return vulns;
        } catch (e) {
            return [];
        }
    }
    // If it fails for other reasons (no package-lock), return empty but maybe warn in logs
    return [];
  }
}
