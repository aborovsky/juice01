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

test('PUT /rest/basket/1/coupon/sample-coupon', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'sqli', 'xss', 'http_method_fuzzing', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.PATH]
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/rest/basket/1/coupon/sample-coupon`,
      body: {
        coupon: 'sample-coupon'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
