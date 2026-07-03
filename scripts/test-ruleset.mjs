#!/usr/bin/env node
// Test harness for @api-common/spectral-owasp-ruleset.
//
// Lints BOTH the OpenAPI 3.x and the Swagger 2.0 fixture pairs and asserts:
//   1. each INSECURE fixture fires the expected OWASP rules / all 10 families
//   2. each CLEAN fixture is (near-)silent
//   3. NO rule throws (errors out) while linting either document
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

let failures = 0;

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
  // A rule that throws during execution is surfaced by Spectral on stderr.
  // Treat any such runtime error as a hard failure — a rule must never throw on
  // a valid document of a format it is allowed to run against.
  const stderr = res.stderr || '';
  if (/threw|exception|Error running|Cannot read|is not a function/i.test(stderr)) {
    console.error(`  RULE ERROR while linting ${fixture}:`);
    console.error(stderr.trim());
    failures++;
  }
  let json;
  try {
    json = JSON.parse(readFileSync(outFile, 'utf8').trim() || '[]');
  } catch (e) {
    console.error(`Failed to parse Spectral JSON output for ${fixture}.`);
    console.error('stdout:', res.stdout);
    console.error('stderr:', res.stderr);
    process.exit(2);
  } finally {
    try { rmSync(outFile, { force: true }); } catch {}
  }
  return json;
}

function familiesOf(codes) {
  return new Set(
    [...codes].map((c) => (c.match(/^owasp-(api\d+)/) || [])[1]).filter(Boolean)
  );
}

// Run the insecure/clean assertions for one format.
function checkFormat({ label, insecureFixture, cleanFixture, expectedRules }) {
  console.log(`\n############ ${label} ############`);

  console.log(`== Linting INSECURE fixture (${insecureFixture}) ==`);
  const insecure = lint(insecureFixture);
  const firedRules = new Set(insecure.map((r) => r.code));
  console.log(`Insecure fixture: ${insecure.length} findings across ${firedRules.size} rules.`);

  for (const rule of expectedRules) {
    if (!firedRules.has(rule)) {
      console.error(`  MISSING: expected rule "${rule}" did not fire on ${insecureFixture}.`);
      failures++;
    }
  }

  const families = familiesOf(firedRules);
  const allTen = ['api1', 'api2', 'api3', 'api4', 'api5', 'api6', 'api7', 'api8', 'api9', 'api10'];
  const missingFamilies = allTen.filter((f) => !families.has(f));
  if (missingFamilies.length) {
    console.error(`  MISSING OWASP families on ${insecureFixture}: ${missingFamilies.join(', ')}`);
    failures++;
  }
  console.log(`  OWASP families with findings: ${[...families].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).join(', ')}`);

  console.log(`\n== Linting CLEAN fixture (${cleanFixture}) ==`);
  const clean = lint(cleanFixture);
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
}

// ---- OpenAPI 3.x ----------------------------------------------------------
const expectedRulesOas3 = [
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

// ---- Swagger 2.0 ----------------------------------------------------------
// Keep rules (no `formats`) fire on 2.0 as-is; the `-oas2` twins stand in for
// the 3.x-structure rules (security schemes, servers->host/schemes, content->
// body-param/response schema).
const expectedRulesOas2 = [
  'owasp-api1-bola-operation-security-defined',
  'owasp-api2-auth-apikey-not-in-url-oas2',
  'owasp-api2-auth-no-http-basic-oas2',
  'owasp-api2-auth-oauth2-https-urls-oas2',
  'owasp-api3-bopla-response-schema-defined-oas2',
  'owasp-api3-bopla-request-schema-defined-oas2',
  'owasp-api4-resource-array-maxitems',
  'owasp-api4-resource-string-maxlength',
  'owasp-api4-resource-integer-bounds',
  'owasp-api5-bfla-global-security-defined',
  'owasp-api6-sensitive-flows-rate-limit-response',
  'owasp-api7-ssrf-url-property-format',
  'owasp-api8-misconfig-https-servers-oas2',
  'owasp-api9-inventory-info-version',
  'owasp-api9-inventory-contact-defined',
  'owasp-api9-inventory-operation-description',
  'owasp-api9-inventory-operationid-defined',
  'owasp-api9-inventory-host-not-example-oas2',
  'owasp-api10-consumption-externaldocs-https',
];

checkFormat({
  label: 'OpenAPI 3.x',
  insecureFixture: 'insecure.yaml',
  cleanFixture: 'clean.yaml',
  expectedRules: expectedRulesOas3,
});

checkFormat({
  label: 'Swagger 2.0',
  insecureFixture: 'insecure-oas2.yaml',
  cleanFixture: 'clean-oas2.yaml',
  expectedRules: expectedRulesOas2,
});

console.log('');
if (failures > 0) {
  console.error(`FAILED with ${failures} problem(s).`);
  process.exit(1);
}
console.log('PASSED: OWASP ruleset fires on both 3.x and 2.0 insecure specs, is silent on both clean specs, and no rule throws.');
