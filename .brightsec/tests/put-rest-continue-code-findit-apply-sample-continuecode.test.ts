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

test('PUT /rest/continue-code-findIt/apply/sample-continueCode', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'sqli', 'ssrf', 'osi', 'file_upload', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/rest/continue-code-findIt/apply/sample-continueCode`,
      body: {
        continueCode: '<encoded-continue-code>'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
