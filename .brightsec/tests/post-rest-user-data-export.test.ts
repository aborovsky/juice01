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

test('POST /rest/user/data-export', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'bopla', 'business_constraint_bypass', 'sqli', 'nosql', 'secret_tokens', 'open_database'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/user/data-export`,
      body: {
        userData: '{\n  "username": "johndoe",\n  "email": "j*hnd**@example.com",\n  "orders": [],\n  "reviews": [],\n  "memories": []\n}',
        confirmation: 'Your data export will open in a new Browser window.'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
