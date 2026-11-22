// Cross-language fixture check. Public deterministic TEST key, never production.
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const root = new URL('../internal/bootpolicy/testdata/', import.meta.url);
const read = (name) => JSON.parse(readFileSync(new URL(name, root), 'utf8'));
const trust = read('trust.json');
const POLICY = 'sahinit-boot-policy-v1\n';
const FLOOR = 'sahinit-boot-floor-v1\n';
const seed = (byte) => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(trust.keys['test-key'], 'base64')]),
  format: 'der', type: 'spki',
});
const privateKey = seed(0x42);
const otherKey = createPublicKey(seed(0x43));
const message = (domain, payload) => Buffer.concat([Buffer.from(domain), payload]);
const checks = (name, domain, others, shape) => {
  const envelope = read(name);
  assert.equal(envelope.key_id, 'test-key');
  const payload = Buffer.from(envelope.payload, 'base64');
  const sig = Buffer.from(envelope.signature, 'base64');
  assert(verify(null, message(domain, payload), publicKey, sig), name);
  assert.equal(sign(null, message(domain, payload), privateKey).toString('base64'), envelope.signature, name);
  for (const d of others) assert(!verify(null, message(d, payload), publicKey, sig), `${name} under ${JSON.stringify(d)}`);
  assert(!verify(null, message(domain, payload), otherKey, sig), `${name} wrong key`);
  const tampered = Buffer.from(payload);
  tampered[tampered.length - 2] ^= 1;
  assert(!verify(null, message(domain, tampered), publicKey, sig), `${name} tampered`);
  assert.deepEqual(JSON.parse(payload), read(shape), name);
  return JSON.parse(payload);
};
const v1 = checks('policy.json', POLICY, [FLOOR, 'sash-grant-v1\n'], 'payload.json');
assert.equal(v1.version, 'sahinit-boot-policy/1');
assert(!('lifetime' in v1));
const never = checks('policy-never.json', POLICY, [FLOOR, 'sash-grant-v1\n'], 'payload-never.json');
assert.equal(never.version, 'sahinit-boot-policy/2');
assert.equal(never.lifetime, 'never');
assert.equal(never.expires_at, 0);
assert.equal(never.offline_until, 0);
assert.equal(never.refresh_after_seconds, 0);
assert.equal(never.not_before, never.issued_at);
const floor = checks('floor.json', FLOOR, [POLICY, 'sash-grant-v1\n'], 'floor-payload.json');
assert.deepEqual(Object.keys(floor), ['version', 'tenant_id', 'host_id', 'enrollment_id', 'min_sequence', 'issued_at']);
assert.equal(floor.version, 'sahinit-boot-floor/1');
for (const k of ['tenant_id', 'host_id', 'enrollment_id']) assert.equal(floor[k], trust[k]);
// Negative vectors: valid bytes signed under the other domain. Go refuses both.
checks('floor-wrong-domain.json', POLICY, [FLOOR], 'floor-payload.json');
checks('policy-wrong-domain.json', FLOOR, [POLICY], 'payload-never.json');
console.log('PASS Go/Node Ed25519 boot-policy v1, v2 never and floor fixtures, domain separation, negative vectors');
