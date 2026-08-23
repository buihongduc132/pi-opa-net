/**
 * RED tests for the home-wide find/grep gate (BHD-195 / BHD-165 Stage 1).
 *
 * Do NOT implement the rule here. Catalog + policy/safety.rego have no
 * `program == "find"` deny today — every DENY case must fail until Stage 2.
 *
 * Rule IDs (unlock keys, LD-L1 per-rule, no god-key LD-L2):
 *   block-home-wide-find
 *   block-home-wide-grep
 *
 * Unlock GREEN contract: same deny cmds with the matching key → ALLOW +
 * source:'opa-unlocked'. RED asserts catalog registration + mintability; do
 * not implement the key material.
 *
 * Fail-open (`default allow := true`) must not be weakened.
 *
 * Fixture table: tests/fixtures/home-wide-find-grep.json (live PIDs/cmds).
 */
import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { mintUnlockKey } from '../../src/cli/unlock-key.ts';
import { RULES } from '../../src/rules/index.ts';

const OPA_BIN = process.env.OPA_BIN ?? '/home/bhd/.local/share/mise/installs/opa/1.18.2/opa';
const OPA_AVAILABLE = existsSync(OPA_BIN);
const SKIP_REASON = !OPA_AVAILABLE ? 'OPA binary not found' : '';

const FIND_RULE = 'block-home-wide-find';
const GREP_RULE = 'block-home-wide-grep';

const ROOT = resolve(import.meta.dir, '../../');
const BIN = resolve(ROOT, 'bin/pi-opa-net.js');
const FIXTURE_PATH = resolve(ROOT, 'tests/fixtures/home-wide-find-grep.json');
const REGO_PATH = resolve(ROOT, 'policy/safety.rego');

const HOME = process.env.HOME ?? homedir() ?? '/home/bhd';
const REPO = ROOT;

interface FixtureCase {
  id: string;
  pid: number | null;
  command: string;
  expect: 'deny' | 'allow';
  rule_id: string | null;
  notes: string;
}

interface FixtureTable {
  source: string;
  rule_ids: { find: string; grep: string };
  cases: FixtureCase[];
}

const FIXTURE: FixtureTable = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));

/** RED gate: fails until Stage 2 registers the rule in the catalog. */
function expectRuleRegistered(ruleId: string): void {
  const ids = RULES.map((r) => r.ruleId);
  expect(ids, `catalog must register ${ruleId}`).toContain(ruleId);
}

interface EvalResult {
  exitCode: number;
  json: {
    decision?: string;
    action?: string;
    source?: string;
    reasons?: Array<{ rule_id?: string; family?: string }>;
    input?: { program?: string; raw?: string; args?: string[] };
    [k: string]: unknown;
  };
}

function runEval(
  command: string,
  extraEnv: Record<string, string> = {},
  timeoutMs = 15000,
): Promise<EvalResult> {
  return new Promise((accept, reject) => {
    const child = spawn('bun', [BIN, 'eval', command, '--json'], {
      env: { ...process.env, OPA_BIN, ...extraEnv },
      cwd: REPO,
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`timeout after ${timeoutMs}ms: ${command}`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      try {
        const json = stdout.trim() ? JSON.parse(stdout.trim()) : {};
        accept({ exitCode: code ?? 0, json });
      } catch {
        reject(new Error(`non-JSON stdout: ${stdout.slice(0, 200)}\nstderr: ${stderr}`));
      }
    });
  });
}

function reasonIds(json: EvalResult['json']): string[] {
  return (json.reasons ?? []).map((r) => r.rule_id ?? '');
}

describe('home-wide find/grep gate — catalog (RED until Stage 2)', () => {
  it(`registers ${FIND_RULE}`, () => {
    expectRuleRegistered(FIND_RULE);
  });

  it(`registers ${GREP_RULE}`, () => {
    expectRuleRegistered(GREP_RULE);
  });

  it('fixture table names the same rule_ids the tests assert', () => {
    expect(FIXTURE.rule_ids.find).toBe(FIND_RULE);
    expect(FIXTURE.rule_ids.grep).toBe(GREP_RULE);
    expect(FIXTURE.cases.length).toBeGreaterThan(0);
  });
});

describe('home-wide find/grep gate — fail-open must not be weakened', () => {
  it('policy/safety.rego keeps default allow := true', () => {
    const rego = readFileSync(REGO_PATH, 'utf8');
    expect(rego).toMatch(/default allow := true/);
  });
});

describe.if(!SKIP_REASON)('home-wide find/grep gate — DENY without unlock', () => {
  // Verbatim live deny-class commands from BHD-165. Worst case first.

  it('find /home/bhd -name goal.json -mmin -15 → DENY (live D-find)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { exitCode, json } = await runEval('find /home/bhd -name goal.json -mmin -15');
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find $HOME → DENY (raw $HOME; shell-quote expands arg to empty)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find $HOME');
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find "$HOME" → DENY (quoted $HOME raw token)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find "$HOME"');
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find /home/bhd unbounded → DENY', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find /home/bhd');
    expect(json.decision).toBe('deny');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find /tmp /home/bhd -maxdepth 4 -name completion.json -newermt 2026-08-23 → DENY (PID 3224795)', async () => {
    expectRuleRegistered(FIND_RULE);
    const cmd = 'find /tmp /home/bhd -maxdepth 4 -name completion.json -newermt 2026-08-23';
    const { json, exitCode } = await runEval(cmd);
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('grep -rl BHD-156 ~/.hermes --include=*.db → DENY (live recursive hermes db)', async () => {
    expectRuleRegistered(GREP_RULE);
    const { json, exitCode } = await runEval('grep -rl BHD-156 ~/.hermes --include=*.db');
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(GREP_RULE);
  });

  it('bash -c inner find → DENY (inner program, not only bash)', async () => {
    expectRuleRegistered(FIND_RULE);
    const cmd = "bash -c 'echo hi; find /home/bhd -name goal.json -mmin -15'";
    const { json, exitCode } = await runEval(cmd);
    expect(json.decision).toBe('deny');
    expect(json.action).toBe('block');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
    // Inner find must be classified. GREEN may unwrap bash -c before eval;
    // matching only program=bash with no find rule is a miss.
    expect(json.input?.raw).toContain('find');
  });

  // Adversarial extras — same deny class, different spellings.

  it('find ~ → DENY', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json } = await runEval('find ~');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find /home/bhd/ trailing slash → DENY', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json } = await runEval('find /home/bhd/');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('/usr/bin/find /home/bhd → DENY (absolute program path)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json } = await runEval('/usr/bin/find /home/bhd');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it(`find ${HOME} (expanded home) → DENY`, async () => {
    expectRuleRegistered(FIND_RULE);
    const { json } = await runEval(`find ${HOME}`);
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('find /home/bhd/Documents/Projects -name .wt-context.json → DENY (unbounded Projects)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json } = await runEval('find /home/bhd/Documents/Projects -name .wt-context.json');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('export FOO=bar; find /home/bhd → DENY (compound env prefix)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('export FOO=bar; find /home/bhd');
    expect(json.decision).toBe('deny');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });

  it('grep -R foo ~/.hermes → DENY (recursive -R alias)', async () => {
    expectRuleRegistered(GREP_RULE);
    const { json } = await runEval('grep -R foo ~/.hermes');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(GREP_RULE);
  });

  it('grep --recursive foo ~/.hermes → DENY', async () => {
    expectRuleRegistered(GREP_RULE);
    const { json } = await runEval('grep --recursive foo ~/.hermes');
    expect(json.decision).toBe('deny');
    expect(reasonIds(json)).toContain(GREP_RULE);
  });

  it('PIOPANET_UNLOCK_ALL is not a god-key (LD-L2)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find /home/bhd', {
      PIOPANET_UNLOCK_ALL: '1',
    });
    expect(json.decision).toBe('deny');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
  });
});

describe.if(!SKIP_REASON)('home-wide find/grep gate — ALLOW scoped walks', () => {
  // Precondition expectRuleRegistered makes these RED today (rule absent).
  // Once Stage 2 lands, they pin the false-positive contract.

  it('find . → ALLOW', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find .');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
    expect(reasonIds(json)).not.toContain(FIND_RULE);
  });

  it(`find ${REPO} → ALLOW (repo path, even when under $HOME)`, async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval(`find ${REPO}`);
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
    expect(reasonIds(json)).not.toContain(FIND_RULE);
  });

  it('find ~/.pi/goals → ALLOW (known goal dir)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find ~/.pi/goals');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('find ~/.verifier-loop/goals → ALLOW (known goal dir)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find ~/.verifier-loop/goals');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('find <repo>/.worktrees -maxdepth 2 -name .wt-context.json → ALLOW', async () => {
    expectRuleRegistered(FIND_RULE);
    const cmd = `find ${REPO}/.worktrees -maxdepth 2 -name .wt-context.json`;
    const { json, exitCode } = await runEval(cmd);
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
    expect(reasonIds(json)).not.toContain(FIND_RULE);
  });

  it('find beet-orches -name process-incoming-object.js → ALLOW (repo-relative)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find beet-orches -name process-incoming-object.js');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('rg -l BHD-156 . → ALLOW (rg in a worktree is not this gate)', async () => {
    expectRuleRegistered(FIND_RULE);
    expectRuleRegistered(GREP_RULE);
    const { json, exitCode } = await runEval('rg -l BHD-156 .');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('find /tmp -name completion.json → ALLOW (tmp-only, no home root)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find /tmp -name completion.json');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('grep foo ./README.md → ALLOW (non-recursive, non-home)', async () => {
    expectRuleRegistered(GREP_RULE);
    const { json, exitCode } = await runEval('grep foo ./README.md');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('find /home/bhd/.pi/goals → ALLOW (expanded known goal dir)', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find /home/bhd/.pi/goals');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('bare find (cwd default) → ALLOW', async () => {
    expectRuleRegistered(FIND_RULE);
    const { json, exitCode } = await runEval('find');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });

  it('grep -r foo . → ALLOW (recursive but cwd-scoped)', async () => {
    expectRuleRegistered(GREP_RULE);
    const { json, exitCode } = await runEval('grep -r foo .');
    expect(json.decision).toBe('allow');
    expect(exitCode).toBe(0);
  });
});

describe.if(!SKIP_REASON)('home-wide find/grep gate — unlock contract (RED until Stage 2)', () => {
  let tempDir: string;
  let saltPath: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'piopanet-homewalk-'));
    saltPath = join(tempDir, 'salt');
    writeFileSync(saltPath, Buffer.from('e2e-test-salt-32-bytes-exactly!!!'), { mode: 0o600 });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it(`mintUnlockKey(${FIND_RULE}) is catalog-known (unlock key name)`, () => {
    // GREEN: catalog entry makes this mint. RED: throws unknown rule_id.
    expect(() => mintUnlockKey({ ruleId: FIND_RULE, saltPath })).not.toThrow();
  });

  it(`mintUnlockKey(${GREP_RULE}) is catalog-known (unlock key name)`, () => {
    expect(() => mintUnlockKey({ ruleId: GREP_RULE, saltPath })).not.toThrow();
  });

  it('find /home/bhd with per-rule find key → ALLOW + source opa-unlocked', async () => {
    expectRuleRegistered(FIND_RULE);
    const key = mintUnlockKey({ ruleId: FIND_RULE, saltPath });
    const { json, exitCode } = await runEval('find /home/bhd', {
      PIOPANET_UNLOCK_KEYS: key,
      PIOPANET_UNLOCK_SALT: saltPath,
    });
    expect(exitCode).toBe(0);
    expect(json.decision).toBe('allow');
    expect(json.source).toBe('opa-unlocked');
  });

  it('grep -rl ~/.hermes with per-rule grep key → ALLOW + source opa-unlocked', async () => {
    expectRuleRegistered(GREP_RULE);
    const key = mintUnlockKey({ ruleId: GREP_RULE, saltPath });
    const { json, exitCode } = await runEval('grep -rl BHD-156 ~/.hermes --include=*.db', {
      PIOPANET_UNLOCK_KEYS: key,
      PIOPANET_UNLOCK_SALT: saltPath,
    });
    expect(exitCode).toBe(0);
    expect(json.decision).toBe('allow');
    expect(json.source).toBe('opa-unlocked');
  });

  it('stash unlock key does not bypass home-wide find (LD-L1)', async () => {
    expectRuleRegistered(FIND_RULE);
    const stashKey = mintUnlockKey({ ruleId: 'block-git-stash-mutations', saltPath });
    const { json, exitCode } = await runEval('find /home/bhd', {
      PIOPANET_UNLOCK_KEYS: stashKey,
      PIOPANET_UNLOCK_SALT: saltPath,
    });
    expect(json.decision).toBe('deny');
    expect(exitCode).toBe(2);
    expect(reasonIds(json)).toContain(FIND_RULE);
    expect(json.source).not.toBe('opa-unlocked');
  });
});

describe.if(!SKIP_REASON)('home-wide find/grep gate — fixture table', () => {
  for (const c of FIXTURE.cases) {
    const label = c.pid ? `PID ${c.pid}` : c.id;
    it(`${label}: ${c.command} → ${c.expect.toUpperCase()}`, async () => {
      if (c.expect === 'deny') {
        expect(c.rule_id, `fixture ${c.id} deny case needs rule_id`).toBeTruthy();
        expectRuleRegistered(c.rule_id as string);
      } else {
        expectRuleRegistered(FIND_RULE);
      }
      const { json, exitCode } = await runEval(c.command);
      if (c.expect === 'deny') {
        expect(json.decision).toBe('deny');
        expect(exitCode).toBe(2);
        expect(reasonIds(json)).toContain(c.rule_id as string);
      } else {
        expect(json.decision).toBe('allow');
        expect(exitCode).toBe(0);
      }
    });
  }
});

if (SKIP_REASON) {
  describe.skip(`home-wide find/grep gate e2e: ${SKIP_REASON}`, () => {});
}
