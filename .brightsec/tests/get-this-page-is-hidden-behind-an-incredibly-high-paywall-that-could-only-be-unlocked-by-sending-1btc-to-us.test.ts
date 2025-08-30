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

test('GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'unvalidated_redirect',
        'full_path_disclosure',
        'csrf',
        'xss',
        'lfi',
        'rfi',
        'osi',
        'sqli',
        'ssrf',
        'xxe',
        'jwt',
        'improper_asset_management',
        'secret_tokens',
        'open_database',
        'open_cloud_storage',
        'amazon_s3_takeover',
        'bopla',
        'broken_saml_auth',
        'business_constraint_bypass',
        'css_injection',
        'date_manipulation',
        'email_injection',
        'file_upload',
        'graphql_introspection',
        'html_injection',
        'http_method_fuzzing',
        'id_enumeration',
        'iframe_injection',
        'insecure_tls_configuration',
        'ldapi',
        'nosql',
        'proto_pollution',
        'server_side_js_injection',
        'ssti',
        'stored_xss',
        'version_control_systems',
        'wordpress',
        'xpathi'
      ],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.HEADER],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us`,
      headers: { 'X-Recruiting': '<recruiting-info-from-config>' }
    });
});