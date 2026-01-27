import axios from 'axios';
import pLimit from 'p-limit';
import type { Finding } from './static-analysis.js';
import type { Dependency } from '../utils/lockfile.js';

const limit = pLimit(5); // Concurrency limit

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
      const modified = new Date(meta.time.modified);
      
      const ageDays = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);
      const modDays = (now.getTime() - modified.getTime()) / (1000 * 60 * 60 * 24);

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
      // We ignore this for scoped packages sometimes, but let's try.
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
        return [{
          type: 'Reputation',
          name: pkgName,
          file: 'package.json',
          severity: 'critical',
          description: 'Package not found in npm registry. Possible private dependency or malware injection.'
        }];
      }
      return []; // Ignore network errors (fail open) or flag as warning?
    }
  });
}

/**
 * Checks for known vulnerabilities using OSV API (Batch Mode).
 * Supports checking hundreds of dependencies in a single request.
 */
export async function checkVulnerabilitiesBatch(packages: Dependency[]): Promise<Finding[]> {
  // packages = [{ name: 'react', version: '18.2.0' }, ...]
  if (packages.length === 0) return [];

  // OSV Batch limit is roughly 1000, but let's chunk to 500 to be safe
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
      
      // Collect all unique Vulnerability IDs to fetch details
      const vulnIds = new Set<string>();
      data.results.forEach((res: any) => {
        if (res.vulns) {
          res.vulns.forEach((v: any) => vulnIds.add(v.id));
        }
      });

      // Fetch details for all IDs in parallel
      const detailsMap = new Map<string, any>();
      const detailPromises = Array.from(vulnIds).map(id => 
        limit(async () => {
          try {
            const { data: detail } = await axios.get(`https://api.osv.dev/v1/vulns/${id}`, { timeout: 5000 });
            detailsMap.set(id, detail);
          } catch (e) {
            // If fetch fails, we'll fall back to basic info
          }
        })
      );

      await Promise.all(detailPromises);

      // Map back to packages
      data.results.forEach((res: any, idx: number) => {
        if (res.vulns && res.vulns.length > 0) {
          const pkg = chunk[idx];
          if (!pkg) return;
          
          res.vulns.forEach((basicV: any) => {
             const v = detailsMap.get(basicV.id) || basicV;

             // Extract fix version if available
             let fixedIn = 'Unknown';
             if (v.affected) {
                for (const affected of v.affected) {
                    if (affected.ranges) {
                        for (const range of affected.ranges) {
                            if (range.events) {
                                for (const event of range.events) {
                                    if (event.fixed) {
                                        // Take the highest fixed version if multiple exist
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

             // Determine severity
             let severity: 'critical' | 'high' | 'medium' | 'low' = 'high';
             if (v.database_specific && v.database_specific.severity) {
                severity = v.database_specific.severity.toLowerCase();
             } else if (v.severity && v.severity.length > 0) {
                 severity = 'high'; // Default if structured severity is complex
             } else {
                const text = JSON.stringify(v).toLowerCase();
                if (text.includes('critical')) severity = 'critical';
                else if (text.includes('high')) severity = 'high';
                else if (text.includes('medium')) severity = 'medium';
                else severity = 'low';
             }

             // Aggregation: Find CVEs to link Snyk/ExploitDB
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
                description: summary, // Satisfy Finding interface
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
