import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import { isObfuscated, hasLongLines } from '../utils/entropy.js';

// @ts-ignore
const traverse = _traverse.default || _traverse;
import fs from 'fs';
import readline from 'readline';

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

export async function analyzeStream(filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const fileStream = fs.createReadStream(filePath, { encoding: 'utf-8' });
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    let lineIndex = 0;
    let sampleContent = '';
    const SAMPLE_SIZE = 5000; 

    for await (const line of rl) {
        lineIndex++;
        if (line.length > 1000) {
            findings.push({
                type: 'Heuristic',
                name: 'Massive Line Length',
                file: filePath,
                line: lineIndex,
                severity: 'high',
                content: `Line length: ${line.length} chars`,
                description: 'Extremely long line detected (Streaming Scan).'
            });
            rl.close();
            break;
        }
        if (sampleContent.length < SAMPLE_SIZE) {
            sampleContent += line + '\n';
        }
    }
    
    if (sampleContent.length > 0 && isObfuscated(sampleContent)) {
         findings.push({
            type: 'Heuristic',
            name: 'High Entropy',
            file: filePath,
            line: 0,
            severity: 'medium',
            content: 'File content appears random/encrypted',
            description: 'Shannon entropy is abnormally high (Sampled).'
        });
    }
    return findings;
}

export function analyzeContent(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const isJson = file.endsWith('.json');
  
  if (isJson) return []; 

  if (content.length > 1024 * 1024) {
      const longLine = hasLongLines(content);
      if (longLine) {
        findings.push({
            type: 'Heuristic',
            name: 'Massive Line Length',
            file,
            line: longLine.lineIndex,
            severity: 'high',
            content: `Line length: ${longLine.length} chars`,
            description: 'Extremely long line detected (File too large for AST).'
        });
      }
      return findings;
  }

  // AST Analysis
  try {
      const ast = parse(content, {
          sourceType: 'unambiguous',
          plugins: ['typescript', 'jsx']
      });

      traverse(ast, {
          CallExpression(path: any) {
              const callee = path.node.callee;
              const line = path.node.loc?.start.line || 0;
              const rawLine = lines[line - 1];
              const codeSnippet = rawLine ? rawLine.trim() : 'N/A';

              // eval()
              if (callee.type === 'Identifier' && callee.name === 'eval') {
                  findings.push({
                      type: 'AST',
                      name: 'Dynamic Execution',
                      file,
                      line,
                      severity: 'high',
                      content: codeSnippet,
                      description: 'Use of eval() detected. Vulnerable to code injection.'
                  });
              }

               // child_process, fs, net, etc.
              if (callee.type === 'MemberExpression') {
                  const obj = callee.object;
                  const prop = callee.property;
                  
                  if (obj.type === 'Identifier' && prop.type === 'Identifier') {
                      if (obj.name === 'child_process') {
                           findings.push({
                              type: 'AST',
                              name: 'Shell Execution',
                              file,
                              line,
                              severity: 'medium',
                              content: codeSnippet,
                              description: `Executes system commands: ${obj.name}.${prop.name}(...)`
                          });
                      }
                      if (obj.name === 'fs' || obj.name === 'fs/promises') {
                           findings.push({
                              type: 'AST',
                              name: 'File System Access',
                              file,
                              line,
                              severity: 'medium',
                              content: codeSnippet,
                              description: `Accesses file system: ${obj.name}.${prop.name}(...)`
                          });
                      }
                       if (['net', 'http', 'https', 'dgram', 'tls'].includes(obj.name)) {
                           findings.push({
                              type: 'AST',
                              name: 'Network Access',
                              file,
                              line,
                              severity: 'medium',
                              content: codeSnippet,
                              description: `Establishes network connection: ${obj.name}.${prop.name}(...)`
                          });
                      }
                      
                      // Buffer.from(..., 'base64')
                      if (obj.name === 'Buffer' && prop.name === 'from') {
                          const args = path.node.arguments;
                          if (args.length > 1 && args[1].type === 'StringLiteral' && args[1].value === 'base64') {
                               findings.push({
                                  type: 'AST',
                                  name: 'Base64 Decoding',
                                  file,
                                  line,
                                  severity: 'medium',
                                  content: codeSnippet,
                                  description: 'Decodes Base64 content. Often used to hide payloads.'
                              });
                          }
                      }
                  }
              }
          },
          MemberExpression(path: any) {
               // process.env
               const line = path.node.loc?.start.line || 0;
               const rawLine = lines[line - 1];
               const codeSnippet = rawLine ? rawLine.trim() : 'N/A';

              if (path.node.object.type === 'Identifier' && path.node.object.name === 'process' &&
                  path.node.property.type === 'Identifier' && path.node.property.name === 'env') {
                  findings.push({
                      type: 'AST',
                      name: 'Environment Access',
                      file,
                      line,
                      severity: 'low',
                      content: codeSnippet,
                      description: 'Accesses environment variables (process.env).'
                  });
              }
          },
          StringLiteral(path: any) {
              const val = path.node.value;
              const line = path.node.loc?.start.line || 0;
              const rawLine = lines[line - 1];
              const codeSnippet = rawLine ? rawLine.trim() : val;
              
              if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(val)) {
                   if (val !== '127.0.0.1' && val !== '0.0.0.0') {
                        findings.push({
                          type: 'AST',
                          name: 'Suspicious IP',
                          file,
                          line,
                          severity: 'medium',
                          content: codeSnippet,
                          description: `Contains hardcoded IP address: ${val}`
                      });
                   }
              }
              if (val.startsWith('http://') || (val.startsWith('https://') && !val.includes('npmjs') && !val.includes('github'))) {
                   findings.push({
                          type: 'AST',
                          name: 'Suspicious URL',
                          file,
                          line,
                          severity: 'medium',
                          content: codeSnippet,
                          description: `Contains hardcoded URL: ${val}`
                  });
              }
          },
          NewExpression(path: any) {
              const callee = path.node.callee;
               const line = path.node.loc?.start.line || 0;
               const rawLine = lines[line - 1];
               const codeSnippet = rawLine ? rawLine.trim() : 'new Function(...)';
               
              if (callee.type === 'Identifier' && callee.name === 'Function') {
                   findings.push({
                      type: 'AST',
                      name: 'Dynamic Execution',
                      file,
                      line,
                      severity: 'high',
                      content: codeSnippet,
                      description: 'Creates function from string (new Function). Vulnerable to injection.'
                  });
              }
          }
      });
  } catch (e) {}

  // 2. Heuristics (Long Lines)
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

  // 3. Entropy Check (Obfuscation)
  if (!file.endsWith('.json') && isObfuscated(content)) {
    findings.push({
      type: 'Heuristic',
      name: 'High Entropy',
      file,
      line: 0,
      severity: 'medium',
      content: 'File content appears random/encrypted',
      description: 'Shannon entropy is abnormally high.'
    });
  }

  return findings;
}
