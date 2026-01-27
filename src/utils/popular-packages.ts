import axios from 'axios';
import { POPULAR_PACKAGES as FALLBACK_PACKAGES } from '../config.js';

const LIST_URL = 'https://raw.githubusercontent.com/wooorm/npm-high-impact/main/data.json';
let cachedPackages: string[] | null = null;

export async function getPopularPackages(): Promise<string[]> {
  if (cachedPackages) return cachedPackages;

  try {
    const { data } = await axios.get(LIST_URL, { timeout: 5000 });
    if (Array.isArray(data)) {
      cachedPackages = [...new Set([...data, ...FALLBACK_PACKAGES])];
    } else {
      cachedPackages = FALLBACK_PACKAGES;
    }
  } catch (e) {
    cachedPackages = FALLBACK_PACKAGES;
  }

  return cachedPackages!;
}
