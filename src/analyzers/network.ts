import axios from 'axios';
import pLimit from 'p-limit';
import type { Finding } from './static-analysis.js';
import type { Dependency } from '../utils/lockfile.js';

const limit = pLimit(10); // Increased concurrency for network checks

/**
 * Main entry point for network audit.
 * Checks vulnerabilities for all packages.
 * Checks reputation for a subset (or all if count is low) to avoid rate limiting.
 */
export async function auditDependencies(packages: Dependency[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // 1. Vulnerabilities (Batch API - Fast)
  try {
      const vulnFindings = await checkVulnerabilitiesBatch(packages);
      findings.push(...vulnFindings);
  } catch (e) {
      console.error('Vulnerability check failed:', e);
  }

  // 2. Reputation (Per-package API - Slow)
  // Only check reputation if < 200 packages to avoid long wait times
  if (packages.length < 200) {
      const reputationPromises = packages.map(p => checkReputation(p.name));
      const repResults = await Promise.all(reputationPromises);
      repResults.forEach(r => findings.push(...r));
  } else {
      // For large trees, maybe only check random sample? 
      // Or just skip to be safe.
  }

  return findings;
}

/**
 * Checks the npm registry for package reputation (downloads, age).
 */
export async function checkReputation(pkgName: string): Promise<Finding[]> {
  return limit(async () => {
    try {
      // 1. Get Metadata (Time, Maintainers)
      const regUrl = `https://registry.npmjs.org/${pkgName}`;
      const { data: meta } = await axios.get(regUrl, { timeout: 3000 });
      
      const findings: Finding[] = [];
      const now = new Date();
      const created = new Date(meta.time.created);
      
      const ageDays = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);

      if (ageDays < 14) {
        findings.push({
          type: 'Reputation',
          name: pkgName,
          file: 'package.json',
          severity: 'high',
          description: `Package is brand new (created ${Math.round(ageDays)} days ago).`
        });
      }

      // 2. Get Downloads (Popularity)
      try {
        const dlUrl = `https://api.npmjs.org/downloads/point/last-week/${pkgName}`;
        const { data: dl } = await axios.get(dlUrl, { timeout: 3000 });
        
        if (dl.downloads < 50) {
           findings.push({
            type: 'Reputation',
            name: pkgName,
            file: 'package.json',
            severity: 'medium',
            description: `Extremely low downloads (${dl.downloads}/week). Potential typosquat or abandoned.`
          });
        }
      } catch (e) {
         // Download stats might be private/unavailable
      }

      return findings;

    } catch (error: any) {
      if (error.response && error.response.status === 404) {
        const isScoped = pkgName.startsWith('@');
        return [{
          type: 'Reputation',
          name: pkgName,
          file: 'package.json',
          severity: isScoped ? 'low' : 'critical',
          description: isScoped 
            ? 'Scoped package not found in public registry (Likely Private).'
            : 'Unscoped package not found in registry (Possible Malware/Typosquat).'
        }];
      }
      return []; 
    }
  });
}

/**
 * Checks for known vulnerabilities using OSV API (Batch Mode).
 */
export async function checkVulnerabilitiesBatch(packages: Dependency[]): Promise<Finding[]> {
  if (packages.length === 0) return [];

  const chunkSize = 500;
  const chunks: Dependency[][] = [];
  
  for (let i = 0; i < packages.length; i += chunkSize) {
    chunks.push(packages.slice(i, i + chunkSize));
  }

  const allVulns: Finding[] = [];

  for (const chunk of chunks) {
    try {
      const payload = {
        queries: chunk.map(p => ({
          package: { name: p.name, ecosystem: 'npm' },
          version: p.version
        }))
      };

      const { data } = await axios.post('https://api.osv.dev/v1/querybatch', payload, { timeout: 10000 });
      
      const vulnIds = new Set<string>();
      data.results.forEach((res: any) => {
        if (res.vulns) {
          res.vulns.forEach((v: any) => vulnIds.add(v.id));
        }
      });

      const detailsMap = new Map<string, any>();
      const detailPromises = Array.from(vulnIds).map(id => 
        limit(async () => {
          try {
            const { data: detail } = await axios.get(`https://api.osv.dev/v1/vulns/${id}`, { timeout: 5000 });
            detailsMap.set(id, detail);
          } catch (e) {}
        })
      );

      await Promise.all(detailPromises);

      data.results.forEach((res: any, idx: number) => {
        if (res.vulns && res.vulns.length > 0) {
          const pkg = chunk[idx];
          if (!pkg) return;
          
          res.vulns.forEach((basicV: any) => {
             const v = detailsMap.get(basicV.id) || basicV;

             let fixedIn = 'Unknown';
             if (v.affected) {
                for (const affected of v.affected) {
                    if (affected.ranges) {
                        for (const range of affected.ranges) {
                            if (range.events) {
                                for (const event of range.events) {
                                    if (event.fixed) {
                                        if (fixedIn === 'Unknown' || event.fixed > fixedIn) {
                                            fixedIn = event.fixed;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
             }

             let severity: 'critical' | 'high' | 'medium' | 'low' = 'high';
             if (v.database_specific && v.database_specific.severity) {
                severity = v.database_specific.severity.toLowerCase();
             } else if (v.severity && v.severity.length > 0) {
                 severity = 'high'; 
             } else {
                const text = JSON.stringify(v).toLowerCase();
                if (text.includes('critical')) severity = 'critical';
                else if (text.includes('high')) severity = 'high';
                else if (text.includes('medium')) severity = 'medium';
                else severity = 'low';
             }

             const externalRefs: string[] = [];
             if (v.aliases) {
                 v.aliases.forEach((alias: string) => {
                     if (alias.startsWith('CVE-')) {
                         externalRefs.push(`Snyk: https://security.snyk.io/vuln?search=${alias}`);
                         externalRefs.push(`ExploitDB: https://www.exploit-db.com/search?cve=${alias.replace('CVE-', '')}`);
                     }
                 });
             }

             const osvUrl = `https://osv.dev/vulnerability/${v.id}`;
             const summary = v.summary || v.details?.split('\n')[0] || 'Vulnerability detected';
             
             allVulns.push({
                type: 'Vulnerability',
                name: pkg.name,
                version: pkg.version,
                severity: severity,
                file: 'package-lock.json',
                id: v.id,
                summary: summary,
                url: osvUrl,
                fixedIn: fixedIn,
                description: summary, 
                references: externalRefs
             });
          });
        }
      });

    } catch (e) {
      console.error(e);
    }
  }

  return allVulns;
}