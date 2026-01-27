export interface Pattern {
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

export const PATTERNS: Pattern[] = [
  {
    name: 'Dynamic Execution',
    regex: /\b(eval|new\s+Function)\b/g,
    severity: 'high',
    description: 'Executes arbitrary code strings.'
  },
  {
    name: 'Base64 Decoding',
    regex: /\b(atob|Buffer\.from\(.*['"]base64['"]\))/g,
    severity: 'medium',
    description: 'Often used to hide payloads.'
  },
  {
    name: 'Suspicious Network',
    regex: /\b(axios|fetch|https?:\.get)\s*\(.*(atob|Buffer|token|api|model)\b/gi,
    severity: 'high',
    description: 'Network call with decoded/suspicious params.'
  },
  {
    name: 'Hex Obfuscation',
    regex: /\\x[0-9a-fA-F]{2}/g,
    severity: 'medium',
    description: 'Hex-encoded strings used for obfuscation.'
  },
  {
    name: 'Shell Execution',
    regex: /\b(child_process|exec|spawn|fork)\b/g,
    severity: 'medium',
    description: 'Executes system commands.'
  }
];

// A small list of very popular packages to check against for typosquatting
export const POPULAR_PACKAGES: string[] = [
  'react', 'react-dom', 'next', 'vue', 'express', 'lodash', 'commander',
  'chalk', 'axios', 'tslib', 'typescript', 'eslint', 'jest', 'moment',
  'date-fns', 'uuid', 'classnames', 'prop-types', 'webpack', 'babel-core',
  'body-parser', 'cookie-parser', 'dotenv', 'mongoose', 'nodemon'
];
