// Cross-language fixture check. Public deterministic TEST key, never production.
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const root = new URL('../internal/bootpolicy/testdata/', import.meta.url);
const envelope = JSON.parse(readFileSync(new URL('policy.json', root), 'utf8'));
const trust = JSON.parse(readFileSync(new URL('trust.json', root), 'utf8'));
const payload = Buffer.from(envelope.payload, 'base64');
const message = Buffer.concat([Buffer.from('sahinit-boot-policy-v1\n'), payload]);
const publicKey = createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(trust.keys[envelope.key_id], 'base64')]),
  format: 'der', type: 'spki',
});
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x42)]),
  format: 'der', type: 'pkcs8',
});
assert(verify(null, message, publicKey, Buffer.from(envelope.signature, 'base64')));
assert.equal(sign(null, message, privateKey).toString('base64'), envelope.signature);
assert.deepEqual(JSON.parse(payload), JSON.parse(readFileSync(new URL('payload.json', root), 'utf8')));
assert(!verify(null, Buffer.concat([Buffer.from('sash-grant-v1\n'), payload]), publicKey, Buffer.from(envelope.signature, 'base64')));
console.log('PASS Go/Node Ed25519 boot-policy fixture and domain separation');
