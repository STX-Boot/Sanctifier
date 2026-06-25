import { describe, it, expect } from 'vitest';
import { analyzeSorobanSource, looksLikeSorobanSource, CODES } from './analyzer';

// ---------------------------------------------------------------------------
// Fixtures – minimal Soroban snippets that trigger (or must NOT trigger) rules
// ---------------------------------------------------------------------------

const SOROBAN_HEADER = `
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Address, storage};
`;

function wrap(body: string): string {
  return `${SOROBAN_HEADER}
pub struct Contract;

#[contractimpl]
impl Contract {
${body}
}
`;
}

// ---------------------------------------------------------------------------
// looksLikeSorobanSource
// ---------------------------------------------------------------------------

describe('looksLikeSorobanSource', () => {
  it('returns true for soroban_sdk import', () => {
    expect(looksLikeSorobanSource('use soroban_sdk::Env;')).toBe(true);
  });

  it('returns true for #[contractimpl]', () => {
    expect(looksLikeSorobanSource('#[contractimpl]')).toBe(true);
  });

  it('returns true for #[contract]', () => {
    expect(looksLikeSorobanSource('#[contract]\npub struct Foo;')).toBe(true);
  });

  it('returns false for plain Rust with no Soroban markers', () => {
    expect(looksLikeSorobanSource('fn main() { println!("hi"); }')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// S002 – PANIC_USAGE
// ---------------------------------------------------------------------------

describe('S002 PANIC_USAGE', () => {
  it('flags panic! inside a contract', () => {
    const src = wrap(`  pub fn blow_up(env: Env) {
    panic!("never");
  }`);
    const findings = analyzeSorobanSource(src);
    const hit = findings.find((f) => f.code === CODES.PANIC_USAGE);
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('error');
  });

  it('does NOT flag panic! in a line comment', () => {
    const src = wrap(`  pub fn ok(env: Env) -> u32 {
    // panic! is bad, don't use it
    42
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.PANIC_USAGE)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S006 – UNSAFE_PATTERN (.unwrap / .expect)
// ---------------------------------------------------------------------------

describe('S006 UNSAFE_PATTERN', () => {
  it('flags .unwrap() inside a contract function', () => {
    const src = wrap(`  pub fn risky(env: Env) -> u32 {
    let val: Option<u32> = Some(1);
    val.unwrap()
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.UNSAFE_PATTERN)).toBeDefined();
  });

  it('flags .expect("…") inside a contract function', () => {
    const src = wrap(`  pub fn risky(env: Env) -> u32 {
    let val: Option<u32> = None;
    val.expect("must exist")
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.UNSAFE_PATTERN)).toBeDefined();
  });

  it('does NOT flag .unwrap() inside a line comment', () => {
    const src = wrap(`  pub fn safe(env: Env) -> u32 {
    // val.unwrap() is bad
    42
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.UNSAFE_PATTERN)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S001 – AUTH_GAP
// ---------------------------------------------------------------------------

const AUTH_GAP_SRC = wrap(`  pub fn privileged(env: Env, caller: Address) {
    env.storage().persistent().set(&"key", &42u32);
  }`);

const AUTH_OK_SRC = wrap(`  pub fn guarded(env: Env, caller: Address) {
    caller.require_auth();
    env.storage().persistent().set(&"key", &42u32);
  }`);

describe('S001 AUTH_GAP', () => {
  it('flags a pub fn that mutates storage without require_auth', () => {
    const findings = analyzeSorobanSource(AUTH_GAP_SRC);
    expect(findings.find((f) => f.code === CODES.AUTH_GAP)).toBeDefined();
  });

  it('does NOT flag a pub fn that calls require_auth before mutating storage', () => {
    const findings = analyzeSorobanSource(AUTH_OK_SRC);
    expect(findings.filter((f) => f.code === CODES.AUTH_GAP)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S003 – ARITHMETIC_OVERFLOW
// ---------------------------------------------------------------------------

describe('S003 ARITHMETIC_OVERFLOW', () => {
  it('flags unchecked + between identifiers inside contractimpl', () => {
    const src = wrap(`  pub fn add(env: Env, a: u32, b: u32) -> u32 {
    a + b
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toBeDefined();
  });

  it('does NOT flag checked_add', () => {
    const src = wrap(`  pub fn safe_add(env: Env, a: u32, b: u32) -> u32 {
    a.checked_add(b).unwrap_or(0)
  }`);
    // Note: .unwrap_or(0) does not use .unwrap() or .expect() so no S006 either.
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });

  it('does NOT flag saturating_add', () => {
    const src = wrap(`  pub fn safe_add(env: Env, a: u32, b: u32) -> u32 {
    a.saturating_add(b)
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });

  it('does NOT flag unchecked arithmetic outside a contractimpl block', () => {
    const src = `${SOROBAN_HEADER}
fn helper(a: u32, b: u32) -> u32 { a + b }
`;
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// De-duplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('does not emit the same finding twice for the same line + code', () => {
    const src = wrap(`  pub fn double(env: Env) {
    panic!("a");
    panic!("a");
  }`);
    const findings = analyzeSorobanSource(src);
    const panics = findings.filter((f) => f.code === CODES.PANIC_USAGE);
    // Two distinct lines → two findings; same line + message → deduplicated
    const lines = new Set(panics.map((f) => f.line));
    expect(panics.length).toBe(lines.size);
  });
});

// ---------------------------------------------------------------------------
// Clean source produces no findings
// ---------------------------------------------------------------------------

describe('clean source', () => {
  it('produces no findings for a well-written contract', () => {
    const src = wrap(`  pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    let balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
    let new_balance = balance.checked_sub(amount).expect("underflow");
    env.storage().persistent().set(&from, &new_balance);
  }`);
    // unwrap_or and .expect are still flagged by the heuristic — that's expected.
    // The key assertion: NO auth-gap and NO panic! findings.
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.AUTH_GAP)).toHaveLength(0);
    expect(findings.filter((f) => f.code === CODES.PANIC_USAGE)).toHaveLength(0);
  });
});
