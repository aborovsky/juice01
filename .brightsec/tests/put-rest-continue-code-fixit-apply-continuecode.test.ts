import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('PUT /rest/continue-code-fixIt/apply/:continueCode', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'http_method_fuzzing', 'sqli', 'xss'],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.BODY]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/rest/continue-code-fixIt/apply/testCode`,
      body: {
        continueCode: 'testCode'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
