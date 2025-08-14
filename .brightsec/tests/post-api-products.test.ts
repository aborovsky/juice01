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

test('POST /api/products', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xss', 'bopla', 'sqli', 'csrf', 'file_upload'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {}
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Products`,
      body: {
        name: 'Apple Juice',
        description: 'Freshly squeezed apple juice',
        price: 3.99,
        deluxePrice: 5.99,
        image: 'apple-juice.png'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
