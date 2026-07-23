/**
 * Boolean-only detection of the Claude Code CLI and its subscription auth state.
 *
 * SECURITY RED LINE: this module NEVER reads the value of any OAuth/subscription
 * token. It only answers yes/no questions:
 *   - Is the `claude` binary available on PATH or in a standard user bin dir?
 *   - Does a subscription credential EXIST (keychain item on macOS, or the
 *     `.credentials.json` file elsewhere)?
 * We mirror the credential-resolver's `probeAwsFiles` pattern (best-effort
 * existence checks, never content reads). On macOS we ask the keychain only for
 * an EXIT CODE (`security find-generic-password -s <svc>` with no `-w`), so the
 * secret value is never emitted, printed, or returned.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CLAUDE_CREDENTIALS_FILE, CLAUDE_SUBSCRIPTION_PROBE_FILE } from '../constants.js';

/** Keychain service name Claude Code stores its OAuth (subscription) token under.
 *  Verified against the fork: `Claude Code${OAUTH_FILE_SUFFIX}${'-credentials'}`
 *  where the default (production) OAUTH_FILE_SUFFIX is ''. */
const KEYCHAIN_OAUTH_SERVICE = 'Claude Code-credentials';

/**
 * Persisted cache for the macOS keychain subscription probe.
 *
 * Reading a keychain item created by *another* app (Claude Code CLI) makes macOS
 * pop the "walnut wants to use confidential information in your keychain" dialog
 * every time the `security` process runs. `hasClaudeSubscriptionAuth()` is on the
 * hot `/api/config` path, so an uncached probe prompts on every settings fetch /
 * app open. We cache the result to disk so the `security` call — the ONLY popup
 * trigger — runs rarely:
 *   - found    → sticky forever (never re-probe; a real logout is rare and the
 *                CLI would surface auth failures anyway).
 *   - not found → re-probe at most once every 7 days.
 * The file-based fallback below never prompts, so it is always allowed to run.
 */
const NEGATIVE_PROBE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface SubscriptionProbeCache {
  version: 1;
  /** Result of the last keychain probe. */
  found: boolean;
  /** ISO timestamp of when the probe ran. */
  probedAt: string;
}

function readProbeCache(): SubscriptionProbeCache | null {
  try {
    const raw = fs.readFileSync(CLAUDE_SUBSCRIPTION_PROBE_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed?.version !== 1 || typeof parsed.found !== 'boolean' || typeof parsed.probedAt !== 'string') {
      return null;
    }
    return parsed as SubscriptionProbeCache;
  } catch {
    return null;
  }
}

function writeProbeCache(found: boolean): void {
  try {
    fs.mkdirSync(path.dirname(CLAUDE_SUBSCRIPTION_PROBE_FILE), { recursive: true });
    const payload: SubscriptionProbeCache = {
      version: 1,
      found,
      probedAt: new Date().toISOString(),
    };
    fs.writeFileSync(CLAUDE_SUBSCRIPTION_PROBE_FILE, JSON.stringify(payload), 'utf-8');
  } catch {
    // Best-effort: a write failure just means we probe again next time.
  }
}

/** True when the cached probe result is still authoritative (skip the keychain). */
function probeCacheValid(cache: SubscriptionProbeCache): boolean {
  // A positive result is sticky — never re-probe (avoids all future popups).
  if (cache.found) return true;
  // A negative result expires so a newly-added credential is eventually noticed.
  const age = Date.now() - Date.parse(cache.probedAt);
  return Number.isFinite(age) && age >= 0 && age < NEGATIVE_PROBE_TTL_MS;
}

/**
 * Run the raw macOS keychain existence probe. THIS is the call that can trigger
 * the keychain-access popup — every other check in this module is popup-free.
 * -s selects the service; NO -w means the password value is NOT emitted. We read
 * only the exit code (throws on not-found). stdio is fully ignored.
 */
function keychainCredentialExists(): boolean {
  try {
    execFileSync('security', ['find-generic-password', '-s', KEYCHAIN_OAUTH_SERVICE], {
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

/** Resolve the CLI exactly as Walnut's daemon does: inherited PATH first, then
 * standard per-user install directories that service processes often omit. */
export function resolveClaudeCliExecutable(
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  const home = env.HOME || os.homedir();
  const pathDirs = (env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const fallbackDirs = [
    path.join(home, '.toolbox', 'bin'),
    path.join(home, '.local', 'bin'),
    path.join(home, '.npm-global', 'bin'),
    path.join(home, '.bun', 'bin'),
    '/usr/local/bin',
    '/opt/homebrew/bin',
    '/usr/bin',
    '/bin',
  ];

  for (const dir of [...new Set([...pathDirs, ...fallbackDirs])]) {
    const candidate = path.join(dir, 'claude');
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

/** True when the `claude` binary is available to Walnut. */
export function isClaudeCliInstalled(): boolean {
  return resolveClaudeCliExecutable() !== null;
}

/**
 * True when a Claude Code subscription (OAuth) credential EXISTS.
 *
 * We do NOT read the token — only its existence:
 *   - macOS: `security find-generic-password -s "Claude Code-credentials"`.
 *     We pass NO `-w` flag, so the value is never printed; we read only the
 *     exit code (0 = present). stdio is fully ignored.
 *   - other platforms / fallback: existence of `~/.claude/.credentials.json`.
 *
 * Best-effort: any error → false. Never throws.
 */
export function hasClaudeSubscriptionAuth(forceProbe = false): boolean {
  // Popup-free fast paths first, so we never touch the keychain unnecessarily:
  //   1. The JSON store existing is a definitive "yes" (some setups keep it even
  //      on macOS — CLAUDE_CONFIG_DIR overrides, headless installs).
  if (fileCredentialExists()) return true;
  //   2. On non-macOS there is no keychain — the file probe above is the whole story.
  if (process.platform !== 'darwin') return false;

  // macOS keychain: consult the persisted cache before running the popup-triggering
  // `security` probe. Sticky when found, 7-day TTL when missing (see cache comment).
  // forceProbe bypasses the cache for an explicit user-initiated refresh (e.g. after
  // logging into Claude Code) — one intentional popup instead of a 7-day wait.
  if (!forceProbe) {
    const cache = readProbeCache();
    if (cache && probeCacheValid(cache)) return cache.found;
  }

  const found = keychainCredentialExists();
  writeProbeCache(found);
  return found;
}

/** Best-effort existence check of the JSON credential store. No content read. */
function fileCredentialExists(): boolean {
  try {
    return fs.existsSync(CLAUDE_CREDENTIALS_FILE);
  } catch {
    return false;
  }
}

/**
 * Snapshot of what the local Claude Code install can offer the butler as a
 * zero-config provider. `subscriptionReady` gates the text-only `claude-cli`
 * provider (Phase 2).
 */
export interface ClaudeCliCapabilities {
  /** `claude` binary is available on PATH or in a standard user install directory. */
  installed: boolean;
  /** A subscription OAuth credential exists (existence only, value never read). */
  subscriptionAuth: boolean;
  /** Both installed AND a subscription credential exists. */
  subscriptionReady: boolean;
}

export function detectClaudeCli(forceProbe = false): ClaudeCliCapabilities {
  const installed = isClaudeCliInstalled();
  const subscriptionAuth = installed && hasClaudeSubscriptionAuth(forceProbe);
  return {
    installed,
    subscriptionAuth,
    subscriptionReady: installed && subscriptionAuth,
  };
}

// Re-export the keychain home for tests that need to know which store we probe
// (kept internal otherwise). Tests never read a value either.
export const _CLAUDE_CREDENTIALS_HOME = os.homedir();

// Test-only exports of the cache internals: the sticky-positive / 7-day-negative
// policy is the whole point of this change, so we verify it directly (the public
// hasClaudeSubscriptionAuth() short-circuits on the real ~/.claude cred file and
// the host platform, which makes end-to-end cache assertions environment-coupled).
export const _test = {
  readProbeCache,
  writeProbeCache,
  probeCacheValid,
  NEGATIVE_PROBE_TTL_MS,
};
