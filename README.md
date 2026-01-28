# Tangkal 🛡️

**Tangkal** (Indonesian for "ward off" or "repel") is a lightweight, preventive security scanner designed to inspect cloned repositories *before* you run `npm install`.

It is specifically built to detect malicious patterns often found in "Job Scam" repositories, such as:
- **Obfuscated Code:** Base64 (atob, Buffer), Hexadecimal strings.
- **Dynamic Execution:** `eval`, `new Function`.
- **Hidden Network Calls:** Fetching payloads from remote URLs (e.g., JSON keepers).
- **Dangerous Lifecycle Scripts:** `preinstall`, `postinstall` in `package.json`.
- **Typosquatting:** Detects packages with names deceptively similar to popular libraries (e.g., `react-doom` vs `react-dom`).
- **Vulnerability Scanning:** Aggregates data from **OSV**, **Snyk**, and **Exploit DB** to report known vulnerabilities.
- **Safe Installation:** Prompts to safely install dependencies using the detected package manager (npm, yarn, pnpm, bun, deno) only if the scan is clean.

## Installation

### From Source
```bash
git clone https://github.com/yourusername/tangkal.git
cd tangkal
npm install
npm link
```

## Usage

Run `tangkal` against any suspicious directory:

```bash
tangkal ./path-to-suspicious-repo
```

Or simply inside the directory:

```bash
cd suspicious-repo
tangkal .
```

## Output Example

Tangkal separates findings into two clear categories: **Malicious Code** and **Vulnerable Packages**.

```text
====================================
ALERT: Malicious Code Detected
====================================
File: src/utils.js
Line: 45
Suspicious pattern detected.
Code: new Function("return " + decodedPayload)()

====================================
ALERT: Vulnerable Package
====================================
[SOLUTION]: Upgrade lodash@4.17.15 to lodash@4.17.21 to fix.
[HIGH Severity] [https://osv.dev/vulnerability/GHSA-xxx] [Snyk: https://security.snyk.io/vuln?search=CVE-2021-23337]
lodash@4.17.15 Prototype Pollution
introduced by lodash@4.17.15
```

## How to Test

To safely test Tangkal's detection capabilities without risking your main environment, we recommend using our dedicated vulnerability test repository.

```bash
git clone https://github.com/AlphaByte-RedTeam/vuln-test
cd vuln-test
tangkal .
```

## Disclaimer

This tool uses heuristic pattern matching. It may produce false positives (e.g., in build scripts or test files) and cannot guarantee 100% safety. **Always review code manually if you are unsure.**
