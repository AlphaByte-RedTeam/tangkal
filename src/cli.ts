import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';
import inquirer from 'inquirer';
import { scanDirectory } from './scanner.js';
import type { Finding } from './analyzers/static-analysis.js';

const program = new Command();

program
  .name('tangkal')
  .description('Preventive security scanner for cloned repositories')
  .version('1.1.0')
  .argument('[directory]', 'directory to scan', '.')
  .option('--json', 'output results as JSON')
  .option('--no-audit', 'skip npm audit check')
  .option('--nuke', 'interactive mode to delete suspicious files')
  .action(async (directory, options) => {
    try {
        const results = await scanDirectory(directory, options);

        if (options.json) {
          console.log(JSON.stringify(results, null, 2));
          return;
        }

        if (results.length === 0) {
          console.log(chalk.green.bold('\nOK: No suspicious patterns found.'));
          return;
        }

        // Separate vulnerabilities from other results for special formatting
        const vulnerabilities = results.filter(f => f.type === 'Vulnerability');
        const otherResults = results.filter(f => f.type !== 'Vulnerability');

        if (otherResults.length > 0) {
            console.log(chalk.red.bold('\n===================================='));
            console.log(chalk.red.bold('ALERT: Malicious Code Detected'));
            console.log(chalk.red.bold('===================================='));
            
            otherResults.forEach(f => {
                console.log(chalk.red('--------------------------------------------------'));
                console.log(`${chalk.red.bold('TYPE:')} ${chalk.white.bold(f.name || f.type)}  ${chalk.gray(`(Severity: ${f.severity.toUpperCase()})`)}`);
                console.log(`${chalk.cyan('FILE:')} ${chalk.white(f.file)}:${chalk.yellow(f.line || 0)}`);
                console.log(`${chalk.cyan('DESC:')} ${chalk.yellow(f.description)}`);
                
                if (f.content) {
                     console.log(chalk.cyan('CODE:'));
                     console.log(chalk.bgBlack.white(`  ${f.content.trim()}  `));
                }
                console.log('');
            });
        }

        if (vulnerabilities.length > 0) {
            console.log(chalk.red.bold('\n===================================='));
            console.log(chalk.red.bold('ALERT: Vulnerable Package'));
            console.log(chalk.red.bold('===================================='));
            
            // Sort by severity (Critical first)
            const severityOrder: Record<string, number> = { 'critical': 0, 'high': 1, 'moderate': 2, 'medium': 2, 'low': 3 };
            vulnerabilities.sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99));

            vulnerabilities.forEach(v => {
                const fixedIn = v.fixedIn || 'latest';
                const severityColor = (v.severity === 'critical' || v.severity === 'high') ? chalk.red.bold : chalk.yellow;
                const pkgLabel = chalk.magenta(`${v.name}@${v.version}`);
                
                console.log(chalk.green(`[SOLUTION]: Upgrade ${v.name}@${v.version} to ${v.name}@${fixedIn} to fix.`));
                
                let links = `[${v.url}]`;
                if (v.references && v.references.length) {
                    const snyk = v.references.find(r => r.includes('snyk.io'));
                    if (snyk) links += ` [${snyk}]`;
                }

                console.log(`${chalk.white('[')}${severityColor(v.severity.toUpperCase())}${chalk.white(' Severity]')} ${chalk.blue(links)}`);
                console.log(`${pkgLabel} ${chalk.white(v.summary)}`);
                console.log(chalk.dim(`introduced by ${v.name}@${v.version}`));
                console.log('');
            });
        }

        // Nuke Mode
        if (options.nuke) {
          const filesToDelete = [...new Set(results.map(r => r.file))];
          
          const { selected } = await inquirer.prompt([
            {
              type: 'checkbox',
              name: 'selected',
              message: 'Select files to DELETE (Space to select, Enter to confirm):',
              choices: filesToDelete
            }
          ]);

          if (selected.length > 0) {
            const { confirm } = await inquirer.prompt([{ 
                type: 'confirm',
                name: 'confirm',
                message: `Are you sure you want to PERMANENTLY delete ${selected.length} files?`,
                default: false
            }]);

            if (confirm) {
                for (const file of selected) {
                    await fs.unlink(path.resolve(directory, file));
                    console.log(chalk.red(`Deleted: ${file}`));
                }
                console.log(chalk.green('Cleanup complete.'));
            }
          }
        } else {
            console.log(chalk.red.bold('FAIL: Potential threats found.'));
            console.log(chalk.yellow('Review manually or run with --nuke to delete files interactively.'));
        }
    } catch (error: any) {
        console.error(chalk.red.bold('\nFATAL ERROR:'), error.message || error);
        if (error.stack) console.error(chalk.gray(error.stack));
        process.exit(1);
    }
  });

export async function run() {
  await program.parseAsync();
}