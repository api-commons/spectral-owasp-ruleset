#!/usr/bin/env node
// Test harness for @api-common/spectral-owasp-ruleset.
//
// Runs the local Spectral CLI against the two fixtures and asserts that:
//   1. the INSECURE fixture produces findings across the expected OWASP rules
//   2. the CLEAN fixture is (near-)silent
//
// No test framework — just spawn Spectral, parse its JSON, assert, exit non-zero
// on failure so `npm test` and CI gate on it.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const ruleset = resolve(root, 'owasp-api-top10.yaml');

function lint(fixture) {
  const file = resolve(root, 'fixtures', fixture);
  // Resolve the Spectral CLI from local node_modules so we don't depend on PATH.
  const bin = resolve(root, 'node_modules', '.bin', 'spectral');
  // Write JSON results to a file: with -f json, the CLI still prints a human
  // "No results ... found!" note to stdout, which would corrupt a parse.
  const outFile = resolve(tmpdir(), `owasp-spectral-${fixture}-${process.pid}.json`);
  const res = spawnSync(
    bin,
    ['lint', file, '-r', ruleset, '-f', 'json', '-o', outFile],
    { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 * 32 }
  );
  let json;
  try {
    json = JSON.parse(readFileSync(outFile, 'utf8').trim() || '[]');
  } catch (e) {
    console.error('Failed to parse Spectral JSON output.');
    console.error('stdout:', res.stdout);
    console.error('stderr:', res.stderr);
    process.exit(2);
  } finally {
    try { rmSync(outFile, { force: true }); } catch {}
  }
  return json;
}

// Every OWASP item that ships a static rule must fire on the insecure fixture.
const expectedRules = [
  'owasp-api1-bola-operation-security-defined',
  'owasp-api2-auth-apikey-not-in-url',
  'owasp-api2-auth-no-http-basic',
  'owasp-api2-auth-oauth2-https-urls',
  'owasp-api3-bopla-response-schema-defined',
  'owasp-api3-bopla-request-schema-defined',
  'owasp-api4-resource-array-maxitems',
  'owasp-api4-resource-string-maxlength',
  'owasp-api4-resource-integer-bounds',
  'owasp-api5-bfla-global-security-defined',
  'owasp-api6-sensitive-flows-rate-limit-response',
  'owasp-api7-ssrf-url-property-format',
  'owasp-api8-misconfig-https-servers',
  'owasp-api8-misconfig-no-trace-method',
  'owasp-api9-inventory-info-version',
  'owasp-api9-inventory-contact-defined',
  'owasp-api9-inventory-operation-description',
  'owasp-api9-inventory-operationid-defined',
  'owasp-api9-inventory-servers-not-example',
  'owasp-api10-consumption-externaldocs-https',
];

let failures = 0;

console.log('== Linting INSECURE fixture ==');
const insecure = lint('insecure.yaml');
const firedRules = new Set(insecure.map((r) => r.code));
console.log(`Insecure fixture: ${insecure.length} findings across ${firedRules.size} rules.`);

for (const rule of expectedRules) {
  if (!firedRules.has(rule)) {
    console.error(`  MISSING: expected rule "${rule}" did not fire on insecure fixture.`);
    failures++;
  }
}
if (failures === 0) {
  console.log(`  OK: all ${expectedRules.length} expected OWASP rules fired.`);
}

// Report which OWASP families fired.
const families = new Set(
  [...firedRules].map((c) => (c.match(/^owasp-(api\d+)/) || [])[1]).filter(Boolean)
);
console.log(`  OWASP families with findings: ${[...families].sort().join(', ')}`);

console.log('\n== Linting CLEAN fixture ==');
const clean = lint('clean.yaml');
console.log(`Clean fixture: ${clean.length} findings.`);
if (clean.length > 0) {
  console.error('  Clean fixture is not silent. Findings:');
  for (const f of clean) {
    console.error(`    ${f.code} @ ${(f.path || []).join('.')} — ${f.message}`);
  }
  failures++;
} else {
  console.log('  OK: clean fixture is silent.');
}

console.log('');
if (failures > 0) {
  console.error(`FAILED with ${failures} problem(s).`);
  process.exit(1);
}
console.log('PASSED: OWASP ruleset fires on insecure spec and is silent on clean spec.');
