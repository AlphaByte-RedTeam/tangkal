import { PATTERNS } from '../config.js';
import { isObfuscated, hasLongLines } from '../utils/entropy.js';

export interface Finding {
  type: string;
  name?: string;
  file: string;
  line?: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  content?: string;
  description: string;
  version?: string;
  id?: string;
  summary?: string;
  url?: string;
  fixedIn?: string;
  references?: string[];
}

export function analyzeContent(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  // 1. Regex Patterns
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      const lineIndex = content.substring(0, match.index).split('\n').length;
      const rawLine = lines[lineIndex - 1];
      const lineContent = rawLine ? rawLine.trim().substring(0, 100) : '';
      
      findings.push({
        type: 'Pattern',
        name: pattern.name,
        file,
        line: lineIndex,
        severity: pattern.severity,
        content: lineContent,
        description: pattern.description
      });
    }
  }

  // 2. Long Lines (Minified/Packed Code)
  const longLine = hasLongLines(content);
  if (longLine) {
    findings.push({
      type: 'Heuristic',
      name: 'Massive Line Length',
      file,
      line: longLine.lineIndex,
      severity: 'high',
      content: `Line length: ${longLine.length} chars`,
      description: 'Extremely long line detected. Often indicates minified malware or packed code.'
    });
  }

  // 3. High Entropy (Obfuscation)
  // We check the whole file or sampled chunks. Checking the whole file is safer for small files.
  // We skip JSON because it naturally has high structure/entropy sometimes.
  if (!file.endsWith('.json') && isObfuscated(content)) {
    findings.push({
      type: 'Heuristic',
      name: 'High Entropy',
      file,
      line: 0,
      severity: 'medium',
      content: 'File content appears random/encrypted',
      description: 'Shannon entropy is abnormally high. Potential obfuscated payload.'
    });
  }

  return findings;
}
