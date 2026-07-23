import { afterEach, describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isClaudeCliInstalled, hasClaudeSubscriptionAuth, detectClaudeCli,
  resolveClaudeCliExecutable, _test,
} from '../../src/core/claude-cli-detect.js';
import { CLAUDE_SUBSCRIPTION_PROBE_FILE } from '../../src/constants.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * These are environment-dependent boolean probes, so we assert on TYPE and
 * INTERNAL CONSISTENCY rather than a fixed value (CI may or may not have the
 * CLI / a subscription). The security-critical property — that we NEVER read a
 * token value — is guaranteed by construction (no `-w` on the keychain probe,
 * no file content read); see the module. Here we assert the API contract.
 */
describe('claude-cli-detect — boolean probes', () => {
  it('isClaudeCliInstalled returns a boolean and never throws', () => {
    expect(typeof isClaudeCliInstalled()).toBe('boolean');
  });

  it('resolves the standard user install directory when PATH omits it', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'walnut-claude-detect-'));
    tempDirs.push(home);
    const executable = path.join(home, '.local', 'bin', 'claude');
    fs.mkdirSync(path.dirname(executable), { recursive: true });
    fs.writeFileSync(executable, '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    expect(resolveClaudeCliExecutable({
      HOME: home,
      PATH: path.join(home, 'empty-bin'),
    })).toBe(executable);
  });

  it('hasClaudeSubscriptionAuth returns a boolean and never throws', () => {
    expect(typeof hasClaudeSubscriptionAuth()).toBe('boolean');
  });

  it('detectClaudeCli is internally consistent', () => {
    const caps = detectClaudeCli();
    expect(typeof caps.installed).toBe('boolean');
    expect(typeof caps.subscriptionAuth).toBe('boolean');
    expect(typeof caps.subscriptionReady).toBe('boolean');
    // subscriptionReady ⟺ installed AND subscriptionAuth
    expect(caps.subscriptionReady).toBe(caps.installed && caps.subscriptionAuth);
    // subscriptionAuth can only be true when installed (we short-circuit on install).
    if (caps.subscriptionAuth) expect(caps.installed).toBe(true);
  });
});

/**
 * The keychain-probe cache is what stops the macOS "Walnut wants to access your
 * keychain" popup from firing on every /api/config fetch. Its policy — positive
 * result sticky forever, negative result re-probed after 7 days — is verified
 * directly here (WALNUT_HOME is a per-process temp dir under the test guard, so
 * these writes never touch real user data).
 */
describe('claude-cli-detect — subscription probe cache', () => {
  afterEach(() => {
    fs.rmSync(CLAUDE_SUBSCRIPTION_PROBE_FILE, { force: true });
  });

  it('round-trips a written cache and never throws on a missing file', () => {
    fs.rmSync(CLAUDE_SUBSCRIPTION_PROBE_FILE, { force: true });
    expect(_test.readProbeCache()).toBeNull();

    _test.writeProbeCache(true);
    const cache = _test.readProbeCache();
    expect(cache).not.toBeNull();
    expect(cache!.found).toBe(true);
    expect(cache!.version).toBe(1);
    expect(typeof cache!.probedAt).toBe('string');
  });

  it('a positive result is sticky — always valid, so the keychain is never re-probed', () => {
    // Even an ancient positive result stays authoritative (a logout is rare and
    // the CLI surfaces auth failures anyway).
    const ancient = new Date(Date.now() - _test.NEGATIVE_PROBE_TTL_MS * 10).toISOString();
    expect(_test.probeCacheValid({ version: 1, found: true, probedAt: ancient })).toBe(true);
  });

  it('a fresh negative result is valid (skips the popup) but expires after 7 days', () => {
    const fresh = new Date(Date.now() - 60_000).toISOString();
    expect(_test.probeCacheValid({ version: 1, found: false, probedAt: fresh })).toBe(true);

    const stale = new Date(Date.now() - (_test.NEGATIVE_PROBE_TTL_MS + 60_000)).toISOString();
    expect(_test.probeCacheValid({ version: 1, found: false, probedAt: stale })).toBe(false);
  });

  it('treats an unparseable timestamp on a negative cache as expired (re-probe)', () => {
    expect(_test.probeCacheValid({ version: 1, found: false, probedAt: 'not-a-date' })).toBe(false);
  });
});
