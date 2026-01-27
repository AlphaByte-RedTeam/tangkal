import levenshtein from 'fast-levenshtein';
import { getPopularPackages } from '../utils/popular-packages.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import type { Finding } from './static-analysis.js';

const execAsync = promisify(exec);

export async function checkTyposquatting(pkgJson: any): Promise<Finding[]> {
  const findings: Finding[] = [];
  const allDeps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies
  };

  const popularPackages = await getPopularPackages();

  for (const depName of Object.keys(allDeps)) {
    for (const popular of popularPackages) {
      if (depName === popular) continue; // Exact match is fine

      const distance = levenshtein.get(depName, popular);
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
    const { stdout } = await execAsync('npm audit --json --audit-level=moderate', { cwd, maxBuffer: 10 * 1024 * 1024 });
    const auditResult = JSON.parse(stdout);
    
    const vulns: Finding[] = [];
    if (auditResult.vulnerabilities) {
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
        } catch (e) { return []; }
    }
    return [];
  }
}
