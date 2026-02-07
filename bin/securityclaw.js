#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function log(msg) {
  process.stdout.write(`${msg}\n`);
}

function fail(msg, code = 1) {
  process.stderr.write(`ERROR: ${msg}\n`);
  process.exit(code);
}

function usage() {
  log(`SecurityClaw npm installer

Usage:
  securityclaw install [options]
  securityclaw scan [scanner args]
  securityclaw help

Install options:
  --openclaw-root <path>    Default: ~/.openclaw
  --skills-dir <path>       Default: <openclaw-root>/skills
  --notify-config <path>    Default: <openclaw-root>/securityclaw-notify.json
  --watch-interval <sec>    Default: 30
  --python-bin <binary>     Default: python3, fallback python
  --no-scheduler            Write scheduler files only (do not enable/start)
  --dry-run                 Print actions only
  --assume-yes              Auto-confirm prompts in Python installer
  --no-offer-install        Do not offer auto-install of missing Linux scheduler deps

Examples:
  npx github:mallen-lbx/SecurityClaw install
  npm i -g github:mallen-lbx/SecurityClaw && securityclaw install
  securityclaw scan --skills-dir ~/.openclaw/skills
`);
}

function parseInstallOptions(args) {
  const opts = {
    openclawRoot: process.env.OPENCLAW_HOME || path.join(os.homedir(), '.openclaw'),
    skillsDir: null,
    notifyConfig: null,
    watchInterval: 30,
    pythonBin: process.env.PYTHON_BIN || 'python3',
    noScheduler: false,
    dryRun: false,
    assumeYes: false,
    offerInstall: true,
    passthrough: []
  };

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    const next = () => {
      const v = args[i + 1];
      if (!v || v.startsWith('-')) {
        fail(`Missing value for ${a}`);
      }
      i += 1;
      return v;
    };

    if (a === '--openclaw-root') {
      opts.openclawRoot = path.resolve(next());
    } else if (a === '--skills-dir') {
      opts.skillsDir = path.resolve(next());
    } else if (a === '--notify-config') {
      opts.notifyConfig = path.resolve(next());
    } else if (a === '--watch-interval') {
      opts.watchInterval = Number.parseInt(next(), 10);
      if (!Number.isFinite(opts.watchInterval) || opts.watchInterval <= 0) {
        fail('Invalid --watch-interval value');
      }
    } else if (a === '--python-bin') {
      opts.pythonBin = next();
    } else if (a === '--no-scheduler') {
      opts.noScheduler = true;
    } else if (a === '--dry-run') {
      opts.dryRun = true;
    } else if (a === '--assume-yes') {
      opts.assumeYes = true;
    } else if (a === '--no-offer-install') {
      opts.offerInstall = false;
    } else {
      opts.passthrough.push(a);
    }
  }

  if (!opts.skillsDir) {
    opts.skillsDir = path.join(opts.openclawRoot, 'skills');
  }
  if (!opts.notifyConfig) {
    opts.notifyConfig = path.join(opts.openclawRoot, 'securityclaw-notify.json');
  }
  opts.reportDir = path.join(opts.openclawRoot, 'SecurityClaw_Scans');

  return opts;
}

function copyDirectory(src, dest, dryRun) {
  if (dryRun) {
    log(`[dry-run] copy ${src} -> ${dest}`);
    return;
  }
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  if (typeof fs.cpSync === 'function') {
    fs.cpSync(src, dest, { recursive: true });
    return;
  }
  // fallback for older Node (not expected with engines >=18)
  const entries = fs.readdirSync(src, { withFileTypes: true });
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of entries) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(s, d, false);
    } else if (entry.isFile()) {
      fs.copyFileSync(s, d);
    }
  }
}

function runPython(scriptPath, scriptArgs, preferredBin) {
  const bins = [];
  for (const b of [preferredBin, 'python3', 'python']) {
    if (b && !bins.includes(b)) {
      bins.push(b);
    }
  }

  for (const bin of bins) {
    const proc = spawnSync(bin, [scriptPath, ...scriptArgs], { stdio: 'inherit' });
    if (proc.error && proc.error.code === 'ENOENT') {
      continue;
    }
    if (proc.error) {
      fail(`Failed to run ${bin}: ${proc.error.message}`);
    }
    return proc.status || 0;
  }

  fail('No Python interpreter found. Install python3 and retry.');
  return 1;
}

function installFlow(args) {
  const opts = parseInstallOptions(args);

  const packageRoot = path.resolve(__dirname, '..');
  const sourceSkillDir = path.join(packageRoot, 'skills', 'securityclaw-skill');
  if (!fs.existsSync(sourceSkillDir)) {
    fail(`Bundled skill not found at ${sourceSkillDir}`);
  }

  const targetSkillDir = path.join(opts.skillsDir, 'securityclaw-skill');
  log(`Installing SecurityClaw skill to ${targetSkillDir}`);
  copyDirectory(sourceSkillDir, targetSkillDir, opts.dryRun);

  const installerPath = opts.dryRun
    ? path.join(sourceSkillDir, 'scripts', 'install_securityclaw.py')
    : path.join(targetSkillDir, 'scripts', 'install_securityclaw.py');
  const installerArgs = [
    '--skills-dir', opts.skillsDir,
    '--notify-config', opts.notifyConfig,
    '--report-dir', opts.reportDir,
    '--watch-interval', String(opts.watchInterval)
  ];

  if (opts.noScheduler) installerArgs.push('--no-install-scheduler');
  if (opts.dryRun) installerArgs.push('--dry-run');
  if (opts.assumeYes) installerArgs.push('--assume-yes');
  if (!opts.offerInstall) installerArgs.push('--no-offer-install');
  if (opts.passthrough.length) installerArgs.push(...opts.passthrough);

  log('Running scheduler installer...');
  const code = runPython(installerPath, installerArgs, opts.pythonBin);
  if (code !== 0) {
    process.exit(code);
  }

  log('SecurityClaw install complete.');
}

function scanFlow(args) {
  const packageRoot = path.resolve(__dirname, '..');
  const scannerPath = path.join(packageRoot, 'skills', 'securityclaw-skill', 'scripts', 'securityclaw_scan.py');
  if (!fs.existsSync(scannerPath)) {
    fail(`Scanner script not found at ${scannerPath}`);
  }

  const code = runPython(scannerPath, args, process.env.PYTHON_BIN || 'python3');
  process.exit(code);
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv.length && !argv[0].startsWith('-') ? argv.shift() : 'install';

  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    usage();
    return;
  }
  if (cmd === 'install') {
    installFlow(argv);
    return;
  }
  if (cmd === 'scan') {
    scanFlow(argv);
    return;
  }

  fail(`Unknown command: ${cmd}`);
}

main();
