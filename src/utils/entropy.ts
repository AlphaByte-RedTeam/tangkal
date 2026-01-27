// @ts-ignore
import _entropy from 'shannon-entropy';
// @ts-ignore
const entropy = _entropy.default || _entropy;

export function calculateEntropy(text: string): number {
  if (typeof entropy !== 'function') return 0;
  return entropy(text);
}

export function isObfuscated(text: string, threshold = 4.5): boolean {
  // Common english text is around 3.5 - 4.5
  // Packed/encrypted code often exceeds 5.0
  return calculateEntropy(text) > threshold;
}

export function hasLongLines(text: string, threshold = 1000): { lineIndex: number; length: number } | null {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line && line.length > threshold) {
      return { lineIndex: i + 1, length: line.length };
    }
  }
  return null;
}
